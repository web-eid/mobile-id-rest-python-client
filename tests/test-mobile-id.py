import unittest
from pathlib import Path
import sys

from cryptography import x509
from cryptography.x509.oid import NameOID

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from mobile_id import (
    AuthenticationError,
    ErrorCodes,
    MobileIDClient,
)

from mobile_id.MobileIDClient import _calculate_verification_code


class TestMobileID(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.client = MobileIDClient()

    def test_successful_authentication(self):
        auth_start_response = self.client.start_authentication(
            phone_number="00000766", national_id_number="60001019906"
        )
        self._assert_auth_start_response_ok(auth_start_response)

        result = self.client.finalize_authentication(
            auth_start_response.session_id, auth_start_response.nonce_hash
        )

        cert = x509.load_der_x509_certificate(result.cert)
        issuer = cert.issuer
        subject = cert.subject

        self.assertEqual(_get_cert_attr(issuer, NameOID.COUNTRY_NAME), "EE")
        self.assertEqual(
            _get_cert_attr(issuer, NameOID.COMMON_NAME), "TEST of ESTEID-SK 2015"
        )
        self.assertEqual(
            _get_cert_attr(subject, NameOID.COMMON_NAME),
            "O’CONNEŽ-ŠUSLIK TESTNUMBER,MARY ÄNN,60001019906",
        )
        self.assertEqual(_get_cert_attr(subject, NameOID.SERIAL_NUMBER), "60001019906")

        self.assertEqual(result.signature_algorithm, "SHA256WithECEncryption")

    def test_user_refused(self):
        self._assert_expected_error(
            "01100266",
            "60001019950",
            ErrorCodes.MOBILEID_AUTH_RESPONSE_USER_CANCELLED_ERROR,
        )

    def test_timeout(self):
        self._assert_expected_error(
            "13100266",
            "60001019983",
            ErrorCodes.MOBILEID_AUTH_RESPONSE_PHONE_ABSENT_ERROR,
        )

    def test_verification_code_calculation(self):
        verification_code = _calculate_verification_code(
            bytes.fromhex("2f665f6a6999e0ef0752e00ec9f453adf59d8cb6")
        )
        self.assertEqual(verification_code, 1462)

    def _assert_expected_error(self, phone_number, id_code, error_code):
        auth_start_response = self.client.start_authentication(
            phone_number=phone_number, national_id_number=id_code
        )
        self._assert_auth_start_response_ok(auth_start_response)

        with self.assertRaises(AuthenticationError) as exception_context:
            self.client.finalize_authentication(
                auth_start_response.session_id, auth_start_response.nonce_hash
            )
        exception = exception_context.exception

        self.assertEqual(exception.status, error_code, f"Exception: {exception}")

    def _assert_auth_start_response_ok(self, auth_start_response):
        self.assertRegex(
            auth_start_response.session_id,
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        )
        self.assertLess(auth_start_response.verification_code, 8193)
        self.assertEqual(len(auth_start_response.nonce_hash), 32)

    # TODO: more failure cases
    # - invalid parameters (country, ID-code etc)
    # - invalid settings (invalid URL, relying party details)


def _get_cert_attr(cert, oid):
    return cert.get_attributes_for_oid(oid)[0].value


if __name__ == "__main__":
    unittest.main()
