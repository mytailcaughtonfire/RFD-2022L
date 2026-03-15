'''
SSL/TLS context for RFD's HTTPS web server. For v535 (2022M), uses RBLXHUB's
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


# RBLXHUB CA from main.go - installed to Windows root store for v535 trust
RBLXHUB_CA_PEM = b'''-----BEGIN CERTIFICATE-----
MIIFDzCCAvegAwIBAgIUWC9sZdzGHiz0aRS/XC25bxtdv88wDQYJKoZIhvcNAQEL
BQAwFzEVMBMGA1UEAwwMKi5yYm9sb2NrLnRrMB4XDTI1MDYxNjIwMzUyN1oXDTM1
MDYxNDIwMzUyN1owFzEVMBMGA1UEAwwMKi5yYm9sb2NrLnRrMIICIjANBgkqhkiG
9w0BAQEFAAOCAg8AMIICCgKCAgEAwRvoMVMKwe2wsPWa+fJPxqivdenwUZ9gVgXP
WwZOaHVwuzojnyauZuAKZX3Q4uBCCCyIxzDI01D1Xh1PrFZPyYKKuByeffxcHn9m
3+yzB/npx59anZWbyfwe7W4EtSh1cYdMQRiplovtATyzRq9NIPXAMjyfAZvTl31r
Pb+y5BJXj03YvyqEf7QdMJs49MNfDlKeMn8N4xFiqx6Hcno6MS03o+GKDl7g2cy6
4APuFd+tMKpAoW0kU0nbLETacpOVMBQMFZ6IeICbYdfdggcVFiuUfsVbbwxPtDqL
J5/H6IVkYNimyLkXQnw7/ZpfomO03ZXUBs5+LUkSYXUTaqviOQZcpizJGkHaFi8k
xT4M8zmgZbrYPieXw4JXTL+IR0aanpUbzQWIeF5NDguuKn4Me4FTl4r8fPTr/54Z
vex1ftHpi8rLmoLEiapZMN3LEYpuLbaQC5yLheTU0m0W++PMFApgy/3EnGvaQFnU
L4bKOnD1S2Ozq1SLH6tymJY4dGtJUyvlt645o8shPbaghenlquwutNQuTXShlxpK
e53LvMDead5TEbiQZ/qC1G/GtEzojVouRtv2USwQQluwpuLUNU9FxzZnU+wGp0Hb
qJK2vWnd8y3sGNjHioQfqJhOLf/CufTAo3PWk00bDExfjdDiIY2L825Twg/qZIHF
87BWkp0CAwEAAaNTMFEwHQYDVR0OBBYEFBljm/8HM3fkg7DpIj0ZKYPbdLIwMB8G
A1UdIwQYMBaAFBljm/8HM3fkg7DpIj0ZKYPbdLIwMA8GA1UdEwEB/wQFMAMBAf8w
DQYJKoZIhvcNAQELBQADggIBAGxjKkDWkd2yJzkJq127s34mOJQrsvkXigPIgkEJ
QYfUpCMm7EQzzh5+/82JmFTmeV1D4210+krFv83ic9VKBDAqKMV2w89iAGK6MGKx
0GkUlYVD7YVFnldrHFAuDLKor1lmg1V1VqQYQWvCYmMDuCNZHueBnakunL0oUDSm
iGxX5NvCiNBzMNGQCSfJq0/2io292LhgKsM8h+33QHiB8Lel9nw401WRWJtNQ5sb
3USowh1fpjeymCYtQqJ7XDPjhpjFRknnYdfN8ag6wNPNkdHK+7PKl2erxOQv4hm5
QK0rChzCkyjlbfBNBtl++Ppv3eRrqmLrmwhxKYpp/Nq6/hapPwgr/gT39l5HY4BJ
1WEvuyVdKtYYdTVx/MqUkcsVuG2twGz7dSHobVTqg7ZqZNudD8QktQiL8Hp8ze4d
Ym3Ky2/D9vukA1SrP8JwoT4/QdaM5G6HIoHwbptz0/cI/xlJY7o2q1Z99Cx0XFXf
U7BOfoMcHdkodO5b9Cs1hA3Z/z9y9MdGexKIzR824js1Rfj+Gh/J4hOGwmQOHbVE
conv8F5NGxhawVmkmhL5015dvpd7NJc65c6RIkFTa4WSVZcO/RemG9p8WCk3e9WG
eY5OsqEVk4mExztbpyX8Y80VeIKfJD8nOUqE5GFUb+SkW/I3rOT4m7/2EMJLWHK4
Z78Z
-----END CERTIFICATE-----
'''


# ---------------------------------------------------------------------------
# Embedded RBLXHUB server certificate and private key.
# ---------------------------------------------------------------------------

RBLXHUB_SERVER_CERT_PEM = b'''
-----BEGIN CERTIFICATE-----
MIIDYjCCAkqgAwIBAgIUALRdujcI5PfeWESa8ojMg64uKOAwDQYJKoZIhvcNAQEF
BQAwFzEVMBMGA1UEAwwMKi5yYm9sb2NrLnRrMB4XDTI0MDcxNjE3NTEwM1oXDTI1
MDcxNjE3NTEwM1owFzEVMBMGA1UEAwwMKi5yYm9sb2NrLnRrMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2OZAQ1mdyGlgyiKQjruskIP3TRIop3L/s2DE
GxTA3EydY9nGiLYTXwQ8h4nq5brNPbhJZRxSlBY7+Yo6eyU0EoGK7DMXA+Vyadto
V0bHGpLOiJJ3nQmg+WNUBmvXMYKwJbY5YUCu59S+Se8IR5xidwVNG9Ky9Oigkh53
8laX4CXxExFENPmlP3SZqqIxVWbT1NE9aEed+Kfdsl+CBsSRCicJlbhPEWCWRE+f
A20wOKoCHFw5S+W1AKmu31Bi3vrm7Ejg9/zVc6xpEtf1wDMz7i7ofd1izbbHnaxx
W+XlZntzg/FWOWNK9XsoztjRDCtdVetnK1VSX4i01d57e70BSQIDAQABo4GlMIGi
MB0GA1UdDgQWBBSqQK78EpD/5UgykS9ZtPgJUcWNhTAfBgNVHSMEGDAWgBSqQK78
EpD/5UgykS9ZtPgJUcWNhTAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIFoDAXBgNV
HREEEDAOggwqLnJib2xvY2sudGswLAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2Vu
ZXJhdGVkIENlcnRpZmljYXRlMA0GCSqGSIb3DQEBBQUAA4IBAQB+wT3aOjQVssuw
ZJeN1UqixATH2cqf2/DAoS2Ez0k6g08w8o5ucasSsG1zwsk5PtHFUPUTTUj2y6aF
bDDw+73xEmX5mWu4Oo2bwwwfENDnFmLCWrwr8cQDJcRGIF7KnQzPYEtxE8gYTS3F
oeqCSXwUehOMODIzljCNmYXVQvpheW7zUB+IjRXyrcpz7SHXrq6OLfpuJew9QEET
kwA9RGqM4RHnTGeCrZUScS347Vu+Hd/i1fCsDz0RmOvh4ny6e2wg3nkWYnlCvvev
y5XklEGmr0OCJuZeD6EAUVL5gNNB47FCuA93ybzvRW/yOmODPjY3E2gLu/IEo4L8
JguAJrKz
-----END CERTIFICATE-----
'''

RBLXHUB_SERVER_KEY_PEM = b'''
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDY5kBDWZ3IaWDK
IpCOu6yQg/dNEiincv+zYMQbFMDcTJ1j2caIthNfBDyHierlus09uEllHFKUFjv5
ijp7JTQSgYrsMxcD5XJp22hXRscaks6IknedCaD5Y1QGa9cxgrAltjlhQK7n1L5J
7whHnGJ3BU0b0rL06KCSHnfyVpfgJfETEUQ0+aU/dJmqojFVZtPU0T1oR534p92y
X4IGxJEKJwmVuE8RYJZET58DbTA4qgIcXDlL5bUAqa7fUGLe+ubsSOD3/NVzrGkS
1/XAMzPuLuh93WLNtsedrHFb5eVme3OD8VY5Y0r1eyjO2NEMK11V62crVVJfiLTV
3nt7vQFJAgMBAAECggEAIl+K+6FuId6hWidUJWqUlGp1fJ9OFgthfnntWiVV0xPJ
NZPDpNLGCx7OwOQYd8O81vUnnIB6jcFgS9GeJvnkYLJq47fNA+8OzLvas0oiL5Ho
bThZAGgQPLWDEWlxtwTxCWjxevoXPeI3LdxVwZOE/zu11pzzg2CCYeW2OI+Ejh7q
PeZnbukd/1picPznqLW6KAOHh5+OW4Yp6Y43nwePporMbyzeRxGyffuNqjL10ncF
LrsT2dZqO+y21xlEX4MbTtCXsewb/rB/e3WW3TzRZo8WPKNprvRxOhBxQDc71wQ3
+GcT6WEHsjsjQE1SVxoIL3txoLn3kkWin1LGqnObyQKBgQD//vZYfDcMlV+GgMKk
ozMS/JpgmKz8kaPYBUT+3k0f74yuTqM8yEdmrP7os/Vk1tUhDQwBvB6DGocSHVns
4CwnUV51Ldh8Y+bzzJF5RmxlC6BW+66RUs3zkI/l43900189XODB/YXPfA7KhvtJ
7Bn5xAv/s72sZP1FACukNdET6wKBgQDY5yFYiZG4cw6r2i0HW1sSMPT2qd1ttl8J
35SkQUh+gpvcVpQsRESUBGihREMYZgBE8SMYh/uL9NoHMd1VGE6a4XZc8EDkmiLf
NxC+kBEVS/ExPO3WNB2e/rmSs2WZrqp1b077QOtoKwUzwEi7twGuRFZhTQJ3yAjg
QgTrwB9WmwKBgQDbq0Be67AdRyxicakUt8pC96nNTBXc4Wi0HMl43u9VgSy6AlbG
+KF0dOyEaLAhaMwYgWaVMoUIQUI4hCE/R5n73zHr4XxMOTncaOVIKOsoxhI/sda5
c1GxOJKSVWZwrFSkhkeDj3Y8dhsHJU8KvuQHVHhrYiRXg41loWDRlzCjIwKBgG4i
Zhcruzc6DOAL50NOCt8gxrGcrNdxe65qvXHtyB6cuQFXYONdQqkZ1/rSy3LPECHx
gw2ItpxpFnACzMzRi9Au3UfxojGxZjWLI1BvnI0Aw5ZpxqY2TjgWRSoNN3CidOEu
RJ9lZmK9PWX6o7PVB+BxyJ6dWLxzcLZWL2N5aTAzAoGBAN6AiVTxny4RX9J3wyMu
lmavd9uSBbJBwgnSqkTPPZuydyxtNh/x6PPmsv18KFMailM+um3yMldkUVAoXHY1
6hmfQy1SizmNeGfgtYqnA3jDBr2KBb4ykvozAhx8FMimuPmAjcYa0zj9DZOSjngj
7kbCojLzRznnBom/lGQrV4YC
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
    '''Returns the CA in PEM format. For v535 with RBLXHUB certs, returns RBLXHUB CA.'''
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
    Ensures www.rbolock.tk, assetdelivery.rbolock.tk etc. resolve to 127.0.0.1.
    Required when using RBLXHUB certs - Studio fetches assets from
    https://assetdelivery.rbolock.tk:port/v1/asset?id=...
    '''
    if platform.system() != 'Windows':
        return
    hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
    try:
        with open(hosts_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
    except OSError:
        log_filter.log(
            text='Cannot read hosts file. Add manually: 127.0.0.1 assetdelivery.rbolock.tk',
            context=logger.log_context.PYTHON_SETUP,
            is_error=True,
        )
        return

    def _host_present(entry: str) -> bool:
        domain = entry.split(maxsplit=1)[1] if ' ' in entry else ''
        for raw in content.splitlines():
            line = raw.strip()
            if line and not line.startswith('#'):
                if domain in line and '127.0.0.1' in line:
                    return True
        return False

    missing = [line for line in RBLXHUB_REQUIRED_HOSTS if not _host_present(line)]
    if not missing:
        return

    log_filter.log(
        text=(
            'RBLXHUB certs need hosts entries. UAC prompt: Approve to add '
            'assetdelivery.rbolock.tk etc. to hosts file.'
        ),
        context=logger.log_context.PYTHON_SETUP,
    )
    # Like RBLXHUB setup_hosts: spawn elevated cmd to append to hosts
    entries = ' && '.join(f'echo {line} >>{hosts_path}' for line in missing)
    ps_cmd = (
        f'Start-Process -Verb RunAs -FilePath "cmd.exe" '
        f'-ArgumentList \'/c {entries} && pause\''
    )
    try:
        subprocess.Popen(['powershell', '-NoProfile', '-Command', ps_cmd])
    except FileNotFoundError:
        log_filter.log(
            text='Add to hosts file manually (as Admin):\n  ' + '\n  '.join(missing),
            context=logger.log_context.PYTHON_SETUP,
            is_error=True,
        )


def install_ca_to_windows_root(log_filter) -> None:
    '''
    Installs the CA into Windows Trusted Root via certutil.
    For v535 with RBLXHUB certs, uses RBLXHUB CA. Uses start-process -verb runas.
    '''
    if platform.system() != 'Windows':
        return

    ca_pem = get_ca_pem_bytes()
    tmp_path = os.path.join(tempfile.gettempdir(), 'rfd-ca.pem')
    with open(tmp_path, 'wb') as f:
        f.write(ca_pem)

    ps_cmd = (
        f'Start-Process -Verb RunAs -FilePath "cmd.exe" '
        f'-ArgumentList \'/c certutil -addstore root "{tmp_path}" && pause\''
    )
    try:
        subprocess.Popen(['powershell', '-NoProfile', '-Command', ps_cmd])
        log_filter.log(
            text='UAC prompt: Approve to install CA into Windows root store.',
            context=logger.log_context.PYTHON_SETUP,
        )
    except FileNotFoundError:
        log_filter.log(
            text='powershell not found. Install CA manually: certutil -addstore root "%s"' % tmp_path,
            context=logger.log_context.PYTHON_SETUP,
            is_error=True,
        )