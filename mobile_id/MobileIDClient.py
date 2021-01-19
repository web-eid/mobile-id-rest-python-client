"""
A thin wrapper around the Mobile-ID authentication REST API.
See documentation at https://github.com/SK-EID/MID
"""

from base64 import b64decode, b64encode
from dataclasses import dataclass
from enum import Enum, auto
import hashlib
import secrets
import time

from typing import Callable

import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA


class Language(Enum):
    ET = "EST", "Autentimine"
    RU = "RUS", "Аутентификация"
    EN = "ENG", "Authentication"


@dataclass
class AuthenticationStartResponse:
    session_id: str
    phone_number: str
    nonce_hash: str
    verification_code: int


@dataclass
class AuthenticationResult:
    cert: bytes  # certificate in DER format
    signature: bytes
    signature_algorithm: str


class MobileIDClient:
    LIVE_URL = "https://mid.sk.ee/mid-api/"
    TEST_URL = "https://tsp.demo.sk.ee/mid-api/"

    TEST_UUID = "00000000-0000-0000-0000-000000000000"
    TEST_NAME = "DEMO"

    POLL_INTERVALS = [10, 10, 7, 7, 7, 7, 7, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 15, 20]
    API_REQUEST_TIMEOUT_MILLISECS = 10000

    def __init__(self, live: bool = False, uuid: str = None, name: str = None):
        if live and (not uuid or not name):
            raise RuntimeError(
                "'name' and 'uuid' arguments have to be provided in live mode"
            )
        self.live = live
        self.url = self.LIVE_URL if live else self.TEST_URL
        self.uuid = uuid if live else self.TEST_UUID
        self.name = name if live else self.TEST_NAME
        nonce = secrets.token_bytes(64)
        self.nonce_hash = hashlib.sha256(nonce).digest()

    def start_authentication(
        self,
        phone_number: str,
        national_id_number: str,
        language: Language = Language.ET,
        phone_calling_code: str = None,
        display_text: str = None,
    ) -> AuthenticationStartResponse:
        """
        Sends start authentication request to the Mobile-ID REST API and returns the response.
        See https://github.com/SK-EID/MID#323-request-parameters
        """
        if not phone_calling_code:
            phone_calling_code = "+372"
        full_phone_number = f"{phone_calling_code}{phone_number}".strip()

        payload = {
            "relyingPartyUUID": self.uuid,
            "relyingPartyName": self.name,
            "phoneNumber": full_phone_number,
            "nationalIdentityNumber": national_id_number.strip(),
            "language": language.value[0],
            "hash": b64encode(self.nonce_hash).decode("ascii"),
            "hashType": "SHA256",
            "displayText": display_text,
        }

        try:
            response_dict = _mobile_id_api_request(
                requests.post, self.url, "authentication", payload
            )
            if "sessionID" not in response_dict:
                raise AuthenticationError(
                    "sessionID not in response_dict, "
                    f"likely request failure: {response_dict}",
                    ErrorCodes.MOBILEID_API_RESPONSE_ERROR,
                )
            return AuthenticationStartResponse(
                session_id=response_dict["sessionID"],
                phone_number=full_phone_number,
                nonce_hash=self.nonce_hash,
                verification_code=_calculate_verification_code(self.nonce_hash),
            )
        # In case raise_for_status() raises, the response body will usually contain a Mobile-ID API response error message,
        # example: {"code":400,"message":"Bad Request"}
        except requests.RequestException as e:
            content = None
            if e.response is not None:
                content = e.response.content
                if e.response.status_code == 404:
                    raise AuthenticationError(
                        "HTTP status 404, user does not have a Mobile-ID account, "
                        f"URL: {e.response.url}, content: {content}",
                        ErrorCodes.MOBILEID_API_USER_DOES_NOT_HAVE_MOBILEID_ACCOUNT,
                    )
                elif e.response.status_code == 403:
                    raise AuthenticationError(
                        "HTTP status 403, no permission to issue the request, "
                        f"URL: {e.response.url}, content: {content}",
                        ErrorCodes.MOBILEID_API_NO_PERMISSION_TO_ISSUE_REQUEST,
                    )
            raise AuthenticationError(
                f"Mobile-ID API response error: {e}, content: {content}",
                ErrorCodes.MOBILEID_API_RESPONSE_ERROR,
            )

    def finalize_authentication(self, session_id: str, nonce_hash: bytes):
        """
        Polls Mobile-ID REST API until authentication is completed, expires or fails.
        See https://github.com/SK-EID/MID#333-request-parameters
        """
        url_path = f"authentication/session/{session_id}?timeoutMs={self.API_REQUEST_TIMEOUT_MILLISECS}"
        # Two minutes total polling intervals time, starts from end
        poll_intervals = self.POLL_INTERVALS.copy()
        while poll_intervals:
            try:
                # Sleep before the first call so that the user can enter the PIN
                time.sleep(poll_intervals.pop())
                response_dict = _mobile_id_api_request(requests.get, self.url, url_path)
                _verify_state_in_authentication_response(response_dict)

                # Check if the transaction is still running, i.e. not completed yet
                if response_dict["state"] == "RUNNING":
                    continue

                _verify_finalize_authentication_response(response_dict)

                result = AuthenticationResult(
                    cert=b64decode(response_dict["cert"]),
                    signature=b64decode(response_dict["signature"]["value"]),
                    signature_algorithm=response_dict["signature"]["algorithm"],
                )

                # TODO: incomplete, validate certificate with OCSP
                # TODO: _validate_signature(nonce_hash, result) - investigate why signature validation fails
                # TODO: more validation, see Mobile-ID Java client code

                return result

            except requests.RequestException as e:
                content = None
                if e.response is not None:
                    content = e.response.content
                    if e.response.status_code == 404:
                        raise AuthenticationError(
                            "HTTP status 404, nonexistent or expired session, "
                            f"URL: {e.response.url}, content: {content}",
                            ErrorCodes.MOBILEID_API_NONEXISTENT_SESSION,
                        )
                raise AuthenticationError(
                    f"Smart-ID API response error: {e}, content: {content}",
                    ErrorCodes.MOBILEID_API_RESPONSE_ERROR,
                )

        raise AuthenticationError(
            "Transaction still not complete after exhausting retry intervals",
            ErrorCodes.MOBILEID_TIMEOUT_ERROR,
        )


class ErrorCodes(Enum):
    MOBILEID_API_NONEXISTENT_SESSION = auto()
    MOBILEID_API_NO_PERMISSION_TO_ISSUE_REQUEST = auto()
    MOBILEID_API_RESPONSE_ERROR = auto()
    MOBILEID_API_RESPONSE_JSON_DECODING_ERROR = auto()
    MOBILEID_API_USER_DOES_NOT_HAVE_MOBILEID_ACCOUNT = auto()
    MOBILEID_AUTH_RESPONSE_DELIVERY_ERROR = auto()
    MOBILEID_AUTH_RESPONSE_NOT_MID_CLIENT_ERROR = auto()
    MOBILEID_AUTH_RESPONSE_PHONE_ABSENT_ERROR = auto()
    MOBILEID_AUTH_RESPONSE_SIGNATURE_HASH_MISMATCH_ERROR = auto()
    MOBILEID_AUTH_RESPONSE_SIM_ERROR = auto()
    MOBILEID_AUTH_RESPONSE_TIMEOUT_ERROR = auto()
    MOBILEID_AUTH_RESPONSE_USER_CANCELLED_ERROR = auto()
    MOBILEID_INVALID_SIGNATURE_ERROR = auto()
    MOBILEID_TIMEOUT_ERROR = auto()


class AuthenticationError(Exception):
    def __init__(self, message, status):
        self.status = status
        super().__init__(message)


def _mobile_id_api_request(
    requests_method: Callable, url: str, url_path: str, payload: dict = None
) -> dict:
    url = url + url_path
    response = (
        requests_method(url) if not payload else requests_method(url, json=payload)
    )
    response.raise_for_status()
    try:
        return response.json()
    except ValueError as e:
        raise AuthenticationError(
            e, ErrorCodes.MOBILEID_API_RESPONSE_JSON_DECODING_ERROR
        )


def _verify_state_in_authentication_response(response_dict):
    if "state" not in response_dict:
        raise AuthenticationError(
            f"'state' missing: {response_dict}", ErrorCodes.MOBILEID_API_RESPONSE_ERROR
        )


def _verify_finalize_authentication_response(response_dict):
    if response_dict["state"] != "COMPLETE":
        raise AuthenticationError(
            f"'state' not COMPLETE: {response_dict}",
            ErrorCodes.MOBILEID_API_RESPONSE_ERROR,
        )
    if "result" not in response_dict:
        raise AuthenticationError(
            f"'result' missing from response: {response_dict}",
            ErrorCodes.MOBILEID_API_RESPONSE_ERROR,
        )

    if response_dict["result"] != "OK":
        end_result = response_dict["result"]
        if end_result in (
            "TIMEOUT",
            "NOT_MID_CLIENT",
            "USER_CANCELLED",
            "SIGNATURE_HASH_MISMATCH",
            "PHONE_ABSENT",
            "DELIVERY_ERROR",
            "SIM_ERROR",
        ):
            raise AuthenticationError(
                f"End result error: {end_result}",
                getattr(ErrorCodes, f"MOBILEID_AUTH_RESPONSE_{end_result}_ERROR"),
            )
        else:
            raise AuthenticationError(
                f"Uknown result code: {end_result} in {response_dict}",
                ErrorCodes.MOBILEID_API_RESPONSE_ERROR,
            )


def _calculate_verification_code(hash: bytes) -> int:
    """
    Verification code is a 4-digit number used in mobile authentication and mobile signing linked with the hash value to be signed.
    See https://github.com/SK-EID/MID#241-verification-code-calculation-algorithm
    """
    return ((0xFC & hash[0]) << 5) | (hash[-1] & 0x7F)


def _validate_signature(nonce_hash: bytes, result: AuthenticationResult):
    cert = x509.load_der_x509_certificate(result.cert)
    pubkey = cert.public_key()
    try:
        # TODO: handle RSA and ECDSA separately
        pubkey.verify(result.signature, nonce_hash, ECDSA(SHA256()))
    except InvalidSignature:
        raise AuthenticationError(
            "Signature validation failed", ErrorCodes.MOBILEID_INVALID_SIGNATURE_ERROR
        )
