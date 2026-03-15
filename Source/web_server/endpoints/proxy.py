'''
Reverse-proxy for rbolock.tk → remote server.

The Roblox client always connects to rbolock.tk (via the hosts file entry
127.0.0.1 rbolock.tk). This proxy listens on 127.0.0.1 on the same port as
the web server and forwards all HTTPS/TCP traffic to whatever host:port the
player routine has set as the current target.

This means the hosts file can permanently stay as 127.0.0.1 rbolock.tk —
the user never needs to edit it again regardless of which server they join.

UDP (RCC game server) is NOT proxied — the Roblox client connects to that
directly via the MachineAddress/ServerPort in the join script.
'''

import socket
import ssl
import threading


class RoblockProxy:
    def __init__(self, listen_port: int, cert_path: str, key_path: str) -> None:
        self.listen_port  = listen_port
        self.cert_path    = cert_path
        self.key_path     = key_path
        self._target_host = '127.0.0.1'
        self._target_port = listen_port
        self._lock        = threading.Lock()
        self._started     = False

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def set_target(self, host: str, port: int) -> None:
        '''Update the forwarding target at runtime — no restart needed.'''
        with self._lock:
            self._target_host = host
            self._target_port = port

    def get_target(self) -> tuple[str, int]:
        with self._lock:
            return self._target_host, self._target_port

    def start(self) -> None:
        '''Start the proxy in a background daemon thread. Safe to call once.'''
        if self._started:
            return
        self._started = True

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert_path, self.key_path)

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_sock.bind(('127.0.0.1', self.listen_port))
        raw_sock.listen(32)
        ssl_sock = ctx.wrap_socket(raw_sock, server_side=True)

        threading.Thread(
            target=self._accept_loop,
            args=(ssl_sock,),
            daemon=True,
            name='rbolock-proxy',
        ).start()

    # -------------------------------------------------------------------------
    # Internal
    # -------------------------------------------------------------------------

    def _pipe(self, src: ssl.SSLSocket, dst: ssl.SSLSocket, done: threading.Event) -> None:
        try:
            while True:
                chunk = src.recv(4096)
                if not chunk:
                    break
                dst.sendall(chunk)
        except Exception:
            pass
        finally:
            done.set()

    def _handle(self, client_conn: ssl.SSLSocket) -> None:
        target_host, target_port = self.get_target()
        try:
            raw_fwd = socket.create_connection((target_host, target_port), timeout=10)
            fwd_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            fwd_ctx.check_hostname = False
            fwd_ctx.verify_mode    = ssl.CERT_NONE
            fwd_conn = fwd_ctx.wrap_socket(raw_fwd, server_hostname=target_host)
        except Exception as e:
            try:
                client_conn.sendall(
                    b'HTTP/1.1 502 Bad Gateway\r\n'
                    b'Content-Length: 0\r\n\r\n'
                )
            except Exception:
                pass
            client_conn.close()
            return

        done = threading.Event()
        threading.Thread(
            target=self._pipe,
            args=(fwd_conn, client_conn, done),
            daemon=True,
        ).start()
        self._pipe(client_conn, fwd_conn, done)
        done.wait(timeout=10)
        for conn in (client_conn, fwd_conn):
            try:
                conn.close()
            except Exception:
                pass

    def _accept_loop(self, ssl_sock: ssl.SSLSocket) -> None:
        while True:
            try:
                conn, _addr = ssl_sock.accept()
                threading.Thread(
                    target=self._handle,
                    args=(conn,),
                    daemon=True,
                ).start()
            except Exception:
                pass