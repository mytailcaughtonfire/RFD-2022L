'''
SSL/TLS context for RFD's HTTPS web server. For v554 (2022L), uses RBLXHUB's
certificates from webserver/apache/certificats/ when available. The RBLXHUB CA
is installed to the Windows root store via certutil (like main.go setup_certificate).
'''
import functools
import os
import platform
import subprocess

# Local application imports
import logger
import util.resource
import trustme
import tempfile

RBLXHUB_CA_PEM = b'''-----BEGIN CERTIFICATE-----
MIIE/jCCAuagAwIBAgIUPNZtRmpJ7t1phrx6HcmMF9HifIIwDQYJKoZIhvcNAQEL
BQAwFzEVMBMGA1UEAwwMKi5yYm9sb2NrLnRrMB4XDTI2MDMyNjEzMDc1M1oXDTM2
MDMyMzEzMDc1M1owFzEVMBMGA1UEAwwMKi5yYm9sb2NrLnRrMIICIjANBgkqhkiG
9w0BAQEFAAOCAg8AMIICCgKCAgEA0HnJk9fL+OkIzSMBdQzHCR0ZReA2QxlRlH6n
rZfL5jZCcv9wHQzHDjGh9Mh/WPYjDxvmpoMeLZtosLuAsbDJiF7Us80G0n/AaURt
/8+5Gd105LlMX+6sqybH6VGpv7W9smyIWLADjAhLx5d/QZH2Ye1vPyKybMNVUR79
BLdnsyrmvI0mZXFZgVRK6gst1mb4JaDbNpNUYsEy2zXOCJnLc1+ijQwo6wjPu4dJ
Kvcwd8BYS3V6CK+lLvn7GM5NH8VdiyGCvT+w4DtbHqmHfYoOpUBMXifFgn1kpROo
1rI3Go1hjQKVVYTDMY4CDuDvRzHE8i47n237Fu9Z1qTxQIn+fO6rWvh6zvNb6Em3
A/3oORv16fuHaTzLhRayWW4BSth+F1ZB4hIXlc+RJuxWt00X+FDkLW1bqFbBqZ/d
oKJcyjH7HFyX1iq8XuEFTlvq/bR5MFvgxgNKvYHxqEv7LHgy27D9AMpcu318uDXx
i2k8JOzyarsPhuHHXUnf6E/bOHO/Kin7inmWK31o6ybnEqOMHRAl87H5rkkjlyGI
G6imP3H8imM2BFJNz9CymulxnQPDcXqDVwgc0D5vUJMuA6hsjaBYkMU75xMoeHCq
KoDhJ/0fiWoktnB5oGX/MIy1myyw9qkgL+d4bkp8RH6UIdSnN6/lm5rxgg1izjL1
ytgdSHcCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUtC4ERtip
QbXWMsg0zPdSXeEzYOwwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4IC
AQCnoqWXkXxVaeau5nAgzZrvq6vAB4haTS/sIFpF1czKbGeWfRW86IT9S7Kp7eOt
IjLZDk1U0sovi3h1CnyYwrHB9Z2sPWo8Ze/SbKewuitJeeAklCQkcZ2pbgGvBYFb
A5B+be0F0FxMzy+KT8HP+ZAio8L3qITwtYEkJeZgucDSgp5ddowepGJ2Y40Ixjlb
FoUYquMSU+7qRIIm08sVNmM/yJNN9AMngcFD9BxwPzK/EpnI7T8y0YUZa2p4Cdmb
9LkLJQZjA0xStydeF8fkO8C4jB70RTgs4MoaN6tyU2W2rKsEems2l1ICJ505N+lr
Y+/0KyDePKoiOoUjatQXIS0hEdyZ57q3ZknGR5xicChd+OcLU4DFhuVCHajW3aa7
mtXmB9nMgJvKrBaRGLGac2Yqt21QWbkKbFTQ4ieSXfW/0osbA/xde4vfeN7qz321
zgEBdY2UU5AOG3/bpcEjGIr9lLJCdh+1d2Sh8o08l/m1cchmP4hI9g+pRq3OVYGg
e3p2+9LOvGHDLN0m+dqfQesOsv/TwWbXLLgGNYrN8IDfy4SLk3SK2g0iqzdzaTkk
tO/K4D00b9ZSo8Z/tcNywwfxp9qhCy4v/VV4A+Va9sWI3gcqeceLtlBjkdligLYG
/JH6y6w+icx7oJ9La3NPFwIWrEYKeGH1qicejZzTQQvNFw==
-----END CERTIFICATE-----
'''

RBLXHUB_SERVER_CERT_PEM = b'''-----BEGIN CERTIFICATE-----
MIIEJDCCAgygAwIBAgIUUxy1eOX/zdJu5JxGF9kLryxA42AwDQYJKoZIhvcNAQEL
BQAwFzEVMBMGA1UEAwwMKi5yYm9sb2NrLnRrMB4XDTI2MDMyNjEzMDc1M1oXDTM2
MDMyMzEzMDc1M1owFzEVMBMGA1UEAwwMKi5yYm9sb2NrLnRrMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5M6gPAUkXWZlLGhM8FvRSAD1EBFCCi49vmIG
JIsYk7a3h1iJ+ZrsJoOLu0cXGIRd7/199w5n+40bkjdl/Bn17aIOIlFaOCG9v+sl
POGtApBzcO3Sd7swLobJ09HeYIak/o+QqTj23cnBxpt2Kc8ANmhXg4S86OYPKINX
F+AvH+GNWOjLR7S7BqKS4a864bTjKOHVU50LajBYPX7Lqgx8jVoJXyW3EvMlPPqV
X1/V1nMGPBVKqsbLmc8KKI9wOILnmqbGlpkpEfJFOrIU5GNXl+yYNWaI3JxADD4d
DlvJ8kSu4JMbV6P+7Cj2xO0NNyUdu3X0QNJXCVn4IMy5tBnQjwIDAQABo2gwZjA0
BgNVHREELTArggwqLnJib2xvY2sudGuCCnJib2xvY2sudGuCCWxvY2FsaG9zdIcE
fwAAATAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEF
BQcDATANBgkqhkiG9w0BAQsFAAOCAgEAByOVi5kzEn8t4h18mtJNNzd+anjftAli
oAboe/gAs6F0WDEWMG1QLRQ3fPlFjHrJcfplue0pKmbhVURYLTGyqL5/8irMi4SD
SrQhYlvgcCvDx+H7uGiG/40LGFxFkTA0n3AGXPJ7lH+NY7ihumZ5cpNeT7ZaxGeW
z3QKJZI85BrBBVdr0jfAfJm3iD8/MKvdl0fm8PhwpXxQuw06JWWnnZR9qJlr1ujA
//SSrRJrahDmjLffObrCLG6rlFZPry1JgvoTVlofVlnn25A/jWLDRDQ4RrLxZ3B9
ObvPmJQXBcwCwZNQVncIcDNH+Tmuak/3Kyj9G5jFuSkUv9Gh2+eobyyDjd0bQBd3
jMtFzM/yFrwai9VLAvZ3xHgZFBImf3UJysc2spreJ4uayyuU1rcYyI0YkSBRoPeR
EmsQByc/lKq9KOXyq8csEDfOJuAnD3MHuVNnlj7SanhmLzbcQKTbIj5yfgwyXd70
OsdZadRdULX5cD/ImMAQnU5+m6Qyb1yMiyPhE3H1VpeZIV696CurVUcbozpC33L/
aDmc72+GtvI5yvJMmAE9SDLyzMN9AHowbyDhZXjNBNUagmx6Tgs3YhA1RRwI24ep
v3FWAgioUa3DpOlHSpxTu88ETU7y4lIoORVNy1ffixJiiaIZRA757ULQSolNxogg
jMbKHu+uXiQ=
-----END CERTIFICATE-----
'''

RBLXHUB_SERVER_KEY_PEM = b'''-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDkzqA8BSRdZmUs
aEzwW9FIAPUQEUIKLj2+YgYkixiTtreHWIn5muwmg4u7RxcYhF3v/X33Dmf7jRuS
N2X8GfXtog4iUVo4Ib2/6yU84a0CkHNw7dJ3uzAuhsnT0d5ghqT+j5CpOPbdycHG
m3YpzwA2aFeDhLzo5g8og1cX4C8f4Y1Y6MtHtLsGopLhrzrhtOMo4dVTnQtqMFg9
fsuqDHyNWglfJbcS8yU8+pVfX9XWcwY8FUqqxsuZzwooj3A4gueapsaWmSkR8kU6
shTkY1eX7Jg1ZojcnEAMPh0OW8nyRK7gkxtXo/7sKPbE7Q03JR27dfRA0lcJWfgg
zLm0GdCPAgMBAAECggEARBYwnGuzTI/h33sSGhxYhKK0Shm4myrzeKnWxh0WLS6c
Iox4UmyFhVhzxkD7YHJTOc0nJNOGodZ1s+cEVCathg9JQXEP9dAklO22YQ2O3Ep7
78j1bmeniNDXUk8La5Hlm1LBa3nmDE2zehRc70gH+ijGkf538J41OIsM6a/ulf+K
cQvS0SA6mQ6KF7tzR+ghUUyUqtq4vmL34bT4r3RTLx1kwDvryvMcEMj5MT1y2Hlp
ljV3Bnc54dkFPgp7LH3tIZsCk2+TSw24pFtyQYFP0nB/KPX9h3EpEI6KhwZWj69x
QdCi8BeB074lKYtGlfmpjIWaGk0VPM9xkHgeSP6xcQKBgQD1EpL+/6UHGoqezkP8
d94Yu6fWZ31mSv/RLaOS/FVIaKBaXXoKm9SARODZmHQVwwoiahScUPSR6nS5Rs5t
BVB9SF70qol8Np+2vA0K622Y8HuwA/YfVT85r2e1H45v3gDi4C/s9+4u2FQ6XUbA
+FTkvSywPbouIwvBtXUdK6VlBQKBgQDvAmMViwwOo2HQ+Jf3grWC3dR/1eUNTuwv
he8yASm2yhBL4Ju8weeacVpRZOhIn1ax/uix+YummPkIF7V/V06/fp8IUF/sWzDn
QesuS49PwvodO5WOB2TKD8MEOhYh8sqSM1jn86uZ5k6y57Wg2DyhZuRkBEKeOpjm
RJHVEaTTgwKBgQCF8nz9euTMGSmi2sI1/54YjpiRi0by3hMsVXGOKPTD+suKGIVX
vwxKf1sWE0l/i3bCkJBrT6QdDLR3f8fbtofjseaUe5Fhnsl0qxvF2B+y893muoOP
ZJyF/uUEDhdf9UsutbH8Jxa76+k9bTX6ysA7tVnzigl0phsK6Q71vqFLsQKBgQDM
e9hV6B6qr3HSnb02j2fHzQ4vSMqs9ibwCcC5oXEU6A/FOydC+QqzgeNp29E3wMsl
gheHnR6zrBDzsYUgq4u+HhDlxg4rY2GVmToi45Z7AS+HryCm4QCEN7P7e87PwK87
Ih8gY8Me6oHOYptsP1SwKh2gzFxKj4udBnFWP8ArDQKBgCu3oOOxmkAIVa+j4BQ0
yGmElCPhS18LKVUKKjwSRhlG3eXy2LcFPLiLvthq5WZadICfofvvvJ1jEoEm2POF
SOmEam1N0LrzyQWnanInR2k6SviuFIffuhssRKqXeL4O02aRPKLl9quTXX3uoHMz
S0XTVE2aN9c+uTBqQpl/F7D3
-----END PRIVATE KEY-----
'''


def _embedded_certs_available() -> bool:
    '''True when both stubs have been filled in with real cert/key data.'''
    return (
        b'BEGIN CERTIFICATE' in RBLXHUB_SERVER_CERT_PEM and
        b'BEGIN' in RBLXHUB_SERVER_KEY_PEM
    )


@functools.cache
def use_rblxhub_certs() -> bool:
    '''True if the embedded RBLXHUB server cert + key stubs have been filled in.'''
    return _embedded_certs_available()


def get_server_cert_paths() -> tuple[str, str] | None:
    '''
    Writes the embedded PEM blobs to a temp dir and returns (cert_path, key_path)
    so the ssl module can load them by path. Returns None if stubs are not filled
    in (falls back to generated certs).
    '''
    if not _embedded_certs_available():
        return None
    import tempfile as _tempfile
    tmp = _tempfile.mkdtemp(prefix='rfd-certs-')
    cert_path = os.path.join(tmp, 'server.crt')
    key_path  = os.path.join(tmp, 'server.key')
    with open(cert_path, 'wb') as f:
        f.write(RBLXHUB_SERVER_CERT_PEM)
    with open(key_path, 'wb') as f:
        f.write(RBLXHUB_SERVER_KEY_PEM)
    return (cert_path, key_path)

def get_ca_pem_bytes() -> bytes:
    '''Returns the CA in PEM format. For v554 with RBLXHUB certs, returns RBLXHUB CA.'''
    if use_rblxhub_certs():
        return RBLXHUB_CA_PEM
    return _get_or_create_persistent_ca()[0]


def _get_ca_storage_dir() -> str:
    base = util.resource.get_rfd_top_dir()
    return os.path.join(base, '.rfd')


def _get_ca_paths() -> tuple[str, str]:
    d = _get_ca_storage_dir()
    return (os.path.join(d, 'ca.pem'), os.path.join(d, 'ca_key.pem'))


@functools.cache
def _get_or_create_persistent_ca() -> tuple[bytes, bytes]:
    cert_path, key_path = _get_ca_paths()
    if os.path.isfile(cert_path) and os.path.isfile(key_path):
        with open(cert_path, 'rb') as f:
            cert_pem = f.read()
        with open(key_path, 'rb') as f:
            key_pem = f.read()
        return (cert_pem, key_pem)

    ca = trustme.CA(key_type=trustme.KeyType.RSA)
    cert_pem = ca.cert_pem.bytes()
    key_pem = ca.private_key_pem.bytes()
    os.makedirs(_get_ca_storage_dir(), exist_ok=True)
    with open(cert_path, 'wb') as f:
        f.write(cert_pem)
    with open(key_path, 'wb') as f:
        f.write(key_pem)
    return (cert_pem, key_pem)


class _PemBlob:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def write_to_path(self, path: str, *, append: bool = False) -> None:
        mode = 'ab' if append else 'wb'
        with open(path, mode) as f:
            f.write(self._data)


@functools.cache
def get_shared_ca() -> trustme.CA:
    '''Returns a CA that can issue certs. Used when not using RBLXHUB certs.'''
    cert_path, key_path = _get_ca_paths()
    if os.path.isfile(cert_path) and os.path.isfile(key_path):
        import datetime
        import ipaddress
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        with open(key_path, 'rb') as f:
            ca_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        with open(cert_path, 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(
                f.read(), default_backend()
            )

        def issue_cert(*hostnames: str):
            san_list = []
            for name in hostnames:
                try:
                    san_list.append(x509.IPAddress(ipaddress.ip_address(name)))
                except ValueError:
                    san_list.append(x509.DNSName(name))
            key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )
            builder = (
                x509.CertificateBuilder()
                .subject_name(x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0]),
                ]))
                .issuer_name(ca_cert.subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.utcnow())
                .not_valid_after(
                    datetime.datetime.utcnow() + datetime.timedelta(days=365)
                )
                .add_extension(
                    x509.SubjectAlternativeName(san_list), critical=False,
                )
            )
            cert = builder.sign(ca_key, hashes.SHA256(), default_backend())
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            key_pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
            chain = [cert_pem, _get_or_create_persistent_ca()[0]]

            class Result:
                cert_chain_pems = [_PemBlob(b) for b in chain]
                private_key_pem = _PemBlob(key_pem)
            return Result()

        class PersistentCA:
            pass
        PersistentCA.cert_pem = property(
            lambda _: _PemBlob(_get_or_create_persistent_ca()[0])
        )
        PersistentCA.private_key_pem = property(
            lambda _: _PemBlob(_get_or_create_persistent_ca()[1])
        )
        PersistentCA.issue_cert = staticmethod(issue_cert)
        return PersistentCA()  # type: ignore[return-value]

    ca = trustme.CA(key_type=trustme.KeyType.RSA)
    os.makedirs(_get_ca_storage_dir(), exist_ok=True)
    with open(cert_path, 'wb') as f:
        f.write(ca.cert_pem.bytes())
    with open(key_path, 'wb') as f:
        f.write(ca.private_key_pem.bytes())
    return ca


RBLXHUB_REQUIRED_HOSTS = [
    '127.0.0.1 rbolock.tk',
    '127.0.0.1 www.rbolock.tk',
    '127.0.0.1 api.rbolock.tk',
    '127.0.0.1 assetgame.rbolock.tk',
    '127.0.0.1 assetdelivery.rbolock.tk',
    '127.0.0.1 clientsettingscdn.rbolock.tk',
]


def _ensure_rbolock_hosts(log_filter) -> None:
    '''
    Ensures www.rbolock.tk etc. resolve to 127.0.0.1 in the hosts file.
    On Windows: shows a friendly messagebox before requesting UAC.
    On Linux:   stub — add entries manually for now.
    '''
    system = platform.system()

    if system == 'Linux':
        log_filter.log(
            text=(
                'Linux: add the following to /etc/hosts manually (requires sudo):\n  ' +
                '\n  '.join(RBLXHUB_REQUIRED_HOSTS)
            ),
            context=logger.log_context.PYTHON_SETUP,
        )
        return

    if system != 'Windows':
        return

    hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
    try:
        with open(hosts_path, 'r', encoding='utf-8', errors='replace') as f:
            existing = f.read()
    except OSError:
        log_filter.log(
            text='Cannot read hosts file. Add manually: ' + ', '.join(RBLXHUB_REQUIRED_HOSTS),
            context=logger.log_context.PYTHON_SETUP,
            is_error=True,
        )
        return

    def _host_present(entry: str) -> bool:
        domain = entry.split(maxsplit=1)[1] if ' ' in entry else ''
        for raw in existing.splitlines():
            line = raw.strip()
            if line and not line.startswith('#'):
                if domain in line and '127.0.0.1' in line:
                    return True
        return False

    missing = [line for line in RBLXHUB_REQUIRED_HOSTS if not _host_present(line)]
    if not missing:
        return

    # Show a friendly messagebox so the user knows what is about to happen
    # and why, before the UAC prompt appears.
    try:
        import ctypes
        MB_OK              = 0x00000000
        MB_ICONINFORMATION = 0x00000040
        missing_display = '\n'.join(f'  {e}' for e in missing)
        ctypes.windll.user32.MessageBoxW(
            0,
            (
                'RFD needs admin to add a few entries to your Windows hosts file so that '
                'the Roblox client can find the local server.\n\n'
                'You\'ll see a admin prompt next, and you\'ll need to click "Yes" for this to work.\n'
                'This is a one-time step and the only time admin is needed, and is a very harmless procedure.\n'
                'You can find the hosts file in C:\\Windows\\System32\\drivers\\etc\\hosts. and open it in Notepad.\n\n'
                'The following lines will be added:\n'
                f'{missing_display}\n\n'
            ),
            'RFD-2022L - Setup',
            MB_OK | MB_ICONINFORMATION,
        )
    except Exception:
        pass  # If ctypes fails for any reason, skip the box and proceed to UAC

    log_filter.log(
        text='Adding rbolock.tk entries to hosts file (UAC prompt incoming)...',
        context=logger.log_context.PYTHON_SETUP,
    )

    entries = ' && '.join(f'echo {line} >>{hosts_path}' for line in missing)
    ps_cmd = (
        f'Start-Process -Verb RunAs -FilePath "cmd.exe" '
        f'-ArgumentList \'/c {entries}\'' 
    )
    try:
        proc = subprocess.Popen(['powershell', '-NoProfile', '-Command', ps_cmd])
        proc.wait()  # Wait for the elevated cmd to finish before continuing
    except FileNotFoundError:
        log_filter.log(
            text='Add to hosts file manually (as Admin):\n  ' + '\n  '.join(missing),
            context=logger.log_context.PYTHON_SETUP,
            is_error=True,
        )

def _is_ca_already_installed() -> bool:
    '''
    Checks if the RFD CA is already present in the Windows Trusted Root store
    by running certutil -store root and looking for the cert's subject/thumbprint.
    Avoids re-installing (and re-prompting) on every startup.
    '''
    try:
        # Extract the subject CN from the CA PEM so we can search for it.
        ca_pem = get_ca_pem_bytes()
        from cryptography import x509 as _x509
        from cryptography.hazmat.backends import default_backend as _backend
        cert = _x509.load_pem_x509_certificate(ca_pem, _backend())
        cn_attrs = cert.subject.get_attributes_for_oid(
            _x509.oid.NameOID.COMMON_NAME
        )
        if not cn_attrs:
            return False
        subject_cn = cn_attrs[0].value  # e.g. "*.rbolock.tk"

        result = subprocess.run(
            ['certutil', '-store', 'root'],
            capture_output=True, text=True, timeout=10,
        )
        return subject_cn in result.stdout
    except Exception:
        return False


def install_ca_to_windows_root(log_filter) -> None:
    '''
    Installs the RFD CA into the Windows Trusted Root store via certutil.
    - Skipped entirely if already installed (no UAC, no prompt).
    - Skipped with a stub log on Linux.
    - Shows a friendly messagebox on Windows before the UAC prompt.
    '''
    system = platform.system()

    if system == 'Linux':
        log_filter.log(
            text='Linux: CA installation not yet automated. Install manually if needed.',
            context=logger.log_context.PYTHON_SETUP,
        )
        return

    if system != 'Windows':
        return

    if _is_ca_already_installed():
        log_filter.log(
            text='CA already installed, skipping.',
            context=logger.log_context.PYTHON_SETUP,
        )
        return

    ca_pem = get_ca_pem_bytes()
    tmp_path = os.path.join(tempfile.gettempdir(), 'rfd-ca.pem')
    with open(tmp_path, 'wb') as f:
        f.write(ca_pem)

    # Show a friendly messagebox before the UAC prompt.
    try:
        import ctypes
        MB_OK              = 0x00000000
        MB_ICONINFORMATION = 0x00000040
        ctypes.windll.user32.MessageBoxW(
            0,
            (
                'RFD needs admin to install a certificate so that the Roblox client '
                'can trust the local server (bypassing Trust Check failed).\n\n'
                'This is a self-signed certificate used only for local connections.\n'
                'You\'ll see a admin prompt next, and you\'ll need to click "Yes" for this to work.\n'
                'This is a one-time step and the only time admin is needed.'
            ),
            'RFD-2022L - Setup',
            MB_OK | MB_ICONINFORMATION,
        )
    except Exception:
        pass

    log_filter.log(
        text='Installing CA into Windows root store (UAC prompt incoming)...',
        context=logger.log_context.PYTHON_SETUP,
    )

    ps_cmd = (
        f'Start-Process -Verb RunAs -FilePath "cmd.exe" '
        f'-ArgumentList \'/c certutil -addstore root "{tmp_path}"\'' 
    )
    try:
        proc = subprocess.Popen(['powershell', '-NoProfile', '-Command', ps_cmd])
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        pass  # UAC timed out or was dismissed — continue anyway
    except FileNotFoundError:
        log_filter.log(
            text='powershell not found. Install CA manually: certutil -addstore root "%s"' % tmp_path,
            context=logger.log_context.PYTHON_SETUP,
            is_error=True,
        )