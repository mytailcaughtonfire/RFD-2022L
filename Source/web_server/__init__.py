import web_server._logic as web_server_logic

# Make sure all API endpoints are working without taking anything therefrom.
from .endpoints import _


def make_server(
    port: int,
    is_ssl: bool = True,
    *args,
    **kwargs,
) -> web_server_logic.web_server:
    if is_ssl:
        cls = web_server_logic.web_server_ssl
    else:
        cls = web_server_logic.web_server

    server = cls(port, *args, **kwargs)

    # Start the rbolock.tk reverse proxy when using RBLXHUB certs.
    # The proxy listens on 127.0.0.1:<port> and forwards to a target
    # that the player routine updates via /rfd/set-proxy-target.
    # This keeps the hosts file permanently as 127.0.0.1 rbolock.tk
    # regardless of which remote server the player is joining.
    if is_ssl:
        import util.ssl_context as _ssl_ctx
        if _ssl_ctx.use_rblxhub_certs():
            from web_server.proxy import RoblockProxy
            cert_path, key_path = _ssl_ctx.get_server_cert_paths()
            proxy = RoblockProxy(port, cert_path, key_path)
            proxy.set_target('127.0.0.1', port)
            proxy.start()
            server.proxy = proxy

    return server