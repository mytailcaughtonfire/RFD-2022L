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


# RBLXHUB CA from main.go - installed to Windows root store for v554 trust
RBLXHUB_CA_PEM = b''''''


# ---------------------------------------------------------------------------
# Embedded RBLXHUB server certificate and private key.
# ---------------------------------------------------------------------------

RBLXHUB_SERVER_CERT_PEM = b''''''

RBLXHUB_SERVER_KEY_PEM = b''''''


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