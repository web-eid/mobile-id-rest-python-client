# mobile-id-rest-python-client

Estonian Mobile-ID Python client is a Python library that can be used for
easy integration with Mobile-ID REST service (https://github.com/SK-EID/MID).

**THIS IS AN UNOFFICIAL AND INCOMPLETE IMPLEMENTATION**.
Currently only authentication is implemented and both certificate validation
with OCSP and signature validation are unimplemented. Pull requests most
welcome.

## Testing and usage

Install the package with _pip_ as follows:

    pip install git+https://github.com/web-eid/mobile-id-rest-python-client

See usage examples in `tests/test-mobile-id.py`.

Run the tests with

    python -m venv venv
    . venv/bin/activate # . venv/Scripts/activate in Windows
    pip install .
    python tests/test-mobile-id.py

## Development guidelines

Format code with _[black](https://github.com/psf/black)_ before committing.
