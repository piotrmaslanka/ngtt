import logging
import typing as tp

import pkg_resources
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from pyasn1.codec.der.decoder import decode
from pyasn1.error import PyAsn1Error
from satella.coding import reraise_as
from satella.files import read_in_file

logger = logging.getLogger(__name__)

DEVICE_ID = x509.ObjectIdentifier('1.3.6.1.4.1.55338.0.0')
ENVIRONMENT = x509.ObjectIdentifier('1.3.6.1.4.1.55338.0.1')
# noinspection PyProtectedMember
x509.oid._OID_NAMES[DEVICE_ID] = 'DeviceID'
# noinspection PyProtectedMember
x509.oid._OID_NAMES[ENVIRONMENT] = 'Environment'


def get_cert(cert_name: str):
    ca_file = pkg_resources.resource_filename(__name__, '../certs/%s.crt' % (cert_name,), )
    return read_in_file(ca_file)


def get_root_cert() -> bytes:
    """
    Return the bytes sequence for SMOK's master CA certificate
    """
    return get_cert('root')


def get_dev_ca_cert() -> bytes:
    """
    Return the bytes sequence for SMOK's device signing CA
    """
    return get_cert('dev')


def get_device_info(cert_data: bytes) -> tp.Tuple[str, int]:
    try:
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    except ValueError:
        raise ValueError('Error unserializing certificate')

    try:
        device_asn1 = cert.extensions.get_extension_for_oid(DEVICE_ID).value.value
    except x509.extensions.ExtensionNotFound as e:
        return ValueError('DEVICE_ID not found in cert: %s' % (e,))

    try:
        device_id = str(decode(device_asn1)[0])
    except (PyAsn1Error, IndexError) as e:
        return ValueError('error during decoding DEVICE_ID: %s' % (e,))

    try:
        environment_asn1 = cert.extensions.get_extension_for_oid(ENVIRONMENT).value.value
    except x509.extensions.ExtensionNotFound as e:
        raise ValueError(str(e))

    try:
        environment = int(decode(environment_asn1)[0])
    except (PyAsn1Error, IndexError, TypeError) as e:
        raise ValueError('error during decoding environment: %s' % (e,))
    except ValueError as e:
        raise ValueError('unrecognized environment: %s' % (e,))

    with reraise_as(ValueError, ValueError):
        return device_id, environment
