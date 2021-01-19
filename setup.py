import os
from setuptools import find_packages, setup

VERSION = "0.0.1"

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

description = "Estonian Mobile-ID Python client is an Python library that can be used for easy integration with Mobile-ID REST service"
long_description = description
if os.path.exists("README.txt"):
    long_description = open("README.txt").read()

setup(
    name="mobile-id-rest-python-client",
    version=VERSION,
    packages=find_packages(),
    include_package_data=True,
    license="MIT License",
    description=description,
    long_description=long_description,
    url="https://github.com/web-eid/mobile-id-rest-python-client",
    download_url=f"https://github.com/web-eid/mobile-id-rest-python-client/archive/{VERSION}.zip",
    author="Mart Sõmermaa",
    author_email="mrts.pydev@gmail.com",
    keywords=[
        "Mobile-ID",
        "REST",
    ],
    install_requires=["cryptography", "requests"],
    classifiers=[
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Topic :: Internet :: WWW/HTTP",
    ],
)
