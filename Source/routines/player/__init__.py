# Standard library imports
import functools
import os
import urllib.parse
import uuid
import dataclasses
import ipaddress
import time

# Typing imports
from typing import ClassVar, override

# Local application imports
from .. import _logic as logic
import util.resource
import util.versions
import util.const


@dataclasses.dataclass(kw_only=True, unsafe_hash=True)
class obj_type(logic.bin_entry):
    BIN_SUBTYPE: ClassVar = util.resource.bin_subtype.PLAYER
    DIRS_TO_ADD: ClassVar = ['logs', 'LocalStorage']

    web_host: str = 'localhost'
    web_port: int = util.const.RFD_DEFAULT_PORT
    rcc_host: str | None
    rcc_port: int | None
    app_host: str = dataclasses.field(init=False)

    user_code: str | None
    display_name: str | None
    use_rbolock_base: bool = False
    launch_delay: float = 0

    @override
    def __post_init__(self) -> None:
        super().__post_init__()
        (
            self.web_host, self.rcc_host,
        ) = self.maybe_differenciate_web_and_rcc_stuff(
            self.web_host, self.rcc_host,
        )
        (
            self.web_port, self.rcc_port,
        ) = self.maybe_differenciate_web_and_rcc_stuff(
            self.web_port, self.rcc_port,
        )
        (
            self.rcc_host, self.rcc_port,
        ) = self.maybe_separate_host_and_port(
            self.rcc_host, self.rcc_port,
        )

        if self.rcc_host == 'localhost':
            self.rcc_host = '127.0.0.1'

        self.app_host = self.web_host
        if self.web_host == 'localhost':
            self.web_host = self.app_host = '127.0.0.1'

        elif self.app_host.startswith('['):
            # Converts
            # - "[2607:fb91:1b74:d4d8:3dfb:5a51:55c3:d516]" into
            # - "[2607:fb91:1b74:d4d8:3dfb:5a51:85.195.213.22]"
            # This is because Rōblox's CoreScripts do not like working with `BaseUrl` settings which don't have dots.
            prefix_len = 30
            ipv6_obj = ipaddress.IPv6Address(self.web_host[1:-1])
            ipv4_mapped = ipaddress.IPv4Address(int(ipv6_obj) & 0xFFFFFFFF)
            exploded_str = ipv6_obj.exploded
            self.app_host = f"[{exploded_str[:prefix_len]}{ipv4_mapped!s}]"

    def finalise_user_code(self) -> None:
        '''
        This method is separate from `__post_init__` because
        it needs to be executed after `launch_delay` seconds.
        The `__post_init__` method gets executed before that delay.
        '''
        if self.user_code is not None:
            return
        res = self.send_request('/rfd/default-user-code')
        self.user_code = str(res.read(), encoding='utf-8')

    def get_server_url(self) -> str:
        '''
        URL used by the routine itself to talk to the web server (send_request).
        Always uses the raw IP/host — never the rbolock alias — so it works
        whether or not the rbolock hosts file entries are present on this machine.
        '''
        return f'https://{self.web_host}:{self.web_port}'

    @override
    def send_request(self, path: str, timeout: float = 7):
        '''
        Always connects via the raw IP, not the rbolock alias.
        The rbolock alias is only for the Roblox client's SSL verification.
        '''
        import urllib.request as _req
        import urllib.error as _err
        try:
            return _req.urlopen(
                f'{self.get_server_url()}{path}',
                context=self.get_none_ssl(),
                timeout=timeout,
            )
        except _err.URLError:
            raise Exception(
                'No server is currently running on %s (%s).' %
                (self.get_server_url(), path),
            )

    @override
    def get_base_url(self) -> str:
        '''
        URL embedded in the client launch args (-a, -j).
        Uses the rbolock alias when certs require it so the client's
        SSL verification passes against the rbolock certificate.
        '''
        if self.use_rbolock_base:
            return f'https://www.rbolock.tk:{self.web_port}'
        return f'https://{self.web_host}:{self.web_port}'

    @override
    def get_app_base_url(self) -> str:
        if self.use_rbolock_base:
            return f'https://www.rbolock.tk:{self.web_port}'
        return f'https://{self.app_host}:{self.web_port}'

    @override
    @functools.cache
    def retr_version(self) -> util.versions.rōblox:
        res = self.send_request('/rfd/roblox-version')
        return util.versions.rōblox.from_name(
            str(res.read(), encoding='utf-8'),
        )

    @staticmethod
    def _is_local_host(host: str) -> bool:
        return host in ('127.0.0.1', 'localhost', '::1')

    def _start_proxy(self) -> None:
        '''
        Starts the rbolock.tk reverse proxy on 127.0.0.1:<web_port>.
        Only runs when:
          - using RBLXHUB certs, AND
          - connecting to a remote host (not localhost/127.0.0.1)
        The proxy forwards HTTPS traffic to web_host:web_port so the hosts
        file can permanently stay as 127.0.0.1 rbolock.tk.
        '''
        import util.ssl_context as _ssl_ctx
        if not _ssl_ctx.use_rblxhub_certs():
            print('[proxy] Not started: not using RBLXHUB certs.', flush=True)
            return
        if self._is_local_host(self.web_host):
            print('[proxy] Not started: connecting to localhost.', flush=True)
            return

        # Inform the user before starting.
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(
                0,
                (
                    f'RFD will start a local HTTPS proxy on port {self.web_port}.\n\n'
                    f'This forwards your Roblox client\'s traffic to {self.web_host}:{self.web_port} '
                    f'without needing to change your hosts file each time.\n\n'
                    f'Your hosts file stays permanently as 127.0.0.1 rbolock.tk.'
                ),
                'RFD — Proxy starting',
                0x00000040,  # MB_ICONINFORMATION
            )
        except Exception:
            pass

        from web_server.proxy import RoblockProxy
        cert_path, key_path = _ssl_ctx.get_server_cert_paths()
        self._proxy = RoblockProxy(self.web_port, cert_path, key_path)
        self._proxy.set_target(self.web_host, self.web_port)
        self._proxy.start()
        print(f'[proxy] Started on 127.0.0.1:{self.web_port} → {self.web_host}:{self.web_port}', flush=True)

    @override
    def bootstrap(self) -> None:
        super().bootstrap()
        time.sleep(self.launch_delay)
        self._start_proxy()
        self.finalise_user_code()
        self.make_client_popen()

    def make_client_popen(self) -> None:
        base_url = self.get_base_url()
        version = self.retr_version()

        if version == util.versions.rōblox.v535: # note, join_url isn't passed
            # 2022M uses a direct JSON joinScript endpoint instead of the two-step
            # PlaceLauncher → join.ashx flow used by older versions.
            join_url = f'{base_url}/game/PlaceLaunch22.ashx?' + urllib.parse.urlencode({
                'MachineAddress': self.rcc_host,
                'ServerPort': self.rcc_port,
                'UserCode': self.user_code,
            })
        else:
            join_url = f'{base_url}/game/PlaceLauncher.ashx?' + urllib.parse.urlencode(
                {k: v for k, v in {
                    'MachineAddress': self.rcc_host,
                    'ServerPort': self.rcc_port,
                    'UserCode': self.user_code,

                    # Temporary backwards compatibility below 0.65.1.
                    # Might get rid of in six or seven months.
                    'rcc-host-addr': self.rcc_host,
                    'rcc-port': self.rcc_port,
                    'user-code': self.user_code,
                }.items() if v}
            )

        # v535: generate a unique token, register join params with the web server,
        # then pass the token as -t so /v1/authentication-ticket/redeem can
        # associate this client's IP with its join config for /v1/join-game.
        join_token = '1'
        if version == util.versions.rōblox.v535:
            join_token = str(uuid.uuid4())
            self.send_request(
                '/rfd/player-join-config?' +
                urllib.parse.urlencode({
                    'token':        join_token,
                    'user_code':    self.user_code or '',
                    'display_name': self.display_name or '',
                    'rcc_host':     self.rcc_host or '127.0.0.1',
                    'rcc_port':     self.rcc_port or util.const.RFD_DEFAULT_PORT,
                }),
            )
            # Update the rbolock.tk reverse proxy target if it's running.
            # Only sent when connecting to a remote host.
            if not self._is_local_host(self.web_host):
                self.send_request(
                    '/rfd/set-proxy-target?' +
                    urllib.parse.urlencode({
                        'host': self.web_host,
                        'port': self.web_port,
                    }),
                )

        exe_path = self.get_versioned_path('RobloxPlayerBeta.exe')
        if not os.path.isfile(exe_path):
            alt_path = self.get_versioned_path('Roblox.exe')
            if os.path.isfile(alt_path):
                exe_path = alt_path
        self.init_popen(
            exe_path,
            (
                '-a', f'{base_url}/login/negotiate.ashx',
                '-j', join_url, # this doesn't get passed to the webserver in v535 unlike v463. why??
                # v535: the UUID token lets the redeem handler look up this
                # client's join config by IP in self.server.join_configs.
                # Other versions: plain '1' (ticket unused by RFD).
                '-t', join_token,
            ))

    @override
    def restart(self) -> None:
        self.stop()
        self.bootstrap()
        self.make_client_popen()