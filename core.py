from base64 import b64encode

import pycades


def certificate_info(cert):
    pkey = cert.PrivateKey
    algo = cert.PublicKey().Algorithm

    cert_info = {
        'privateKey': {
            'providerName': pkey.ProviderName,
            'uniqueContainerName': pkey.UniqueContainerName,
            'containerName': pkey.ContainerName,
        },
        'algorithm': {
            'name': algo.FriendlyName,
            'val': algo.Value,
        },
        'valid': {
            'from': cert.ValidFromDate,
            'to': cert.ValidToDate,
        },
        'issuer': parse_detail(cert.IssuerName),
        'subject': parse_detail(cert.SubjectName),
        'thumbprint': cert.Thumbprint,
        'serialNumber': cert.SerialNumber,
        'hasPrivateKey': cert.HasPrivateKey()
    }

    return cert_info


def parse_detail(row):
    if row:
        detail = dict(
            key_val.split('=')
            for key_val in row.split(',')
        )
        detail['row'] = row
        return detail


def certificates_store():
    store = pycades.Store()
    store.Open(
        pycades.CADESCOM_CONTAINER_STORE,
        pycades.CAPICOM_MY_STORE,
        pycades.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED
    )
    return store.Certificates


def get_signer(cert, pin):
    signer = pycades.Signer()
    signer.Certificate = cert
    signer.CheckCertificate = True
    signer.KeyPin = pin
    return signer


def get_signature(file, signer):
    signed_data = pycades.SignedData()
    signed_data.Content = b64encode(file).decode()
    return signed_data.SignCades(signer, pycades.CADESCOM_CADES_BES)


def get_unsigned(signature):
    unsigned_data = pycades.SignedData()
    unsigned_data.VerifyCades(signature, pycades.CADESCOM_CADES_BES)
    return unsigned_data.Content
