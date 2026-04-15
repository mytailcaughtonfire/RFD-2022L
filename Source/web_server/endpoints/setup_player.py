# Standard library imports
import functools
import json
import os
import re

# Local application imports
import assets.returns as returns
import util.const
import util.resource
import util.versions as versions
from web_server._logic import web_server_handler, server_path, web_server_ssl


@server_path('/rfd/default-user-code')
def _(self: web_server_handler) -> bool:
    result = self.game_config.server_core.retrieve_default_user_code(
        time.time(),
    )
    #result = self.game_config.server_core.retrieve_default_user_code()
    self.send_data(bytes(result, encoding='utf-8'))
    return True


@server_path('/rfd/player-join-config')
def _(self: web_server_handler) -> bool:
    '''
    Called by the player routine before launching a v535 client.
    Stores join params keyed by a UUID token so they can be retrieved
    by /v1/authentication-ticket/redeem (which maps client IP to token)
    and ultimately by /v1/join-game (which maps client IP to join params).

    To add a new param: add it to the urlencode({...}) in
    routines/player/__init__.py and read it here.
    '''
    token = self.query.get('token', '')
    if not token:
        self.send_data(b'error: missing token', status=400)
        return True

    if not hasattr(self.server, 'join_configs'):
        self.server.join_configs = {}

    # -------------------------------------------------------------------------
    # Add new join params here -- they will be available in /v1/join-game via
    # self.server.join_configs.get(token, {}).get('your_key')
    # -------------------------------------------------------------------------
    self.server.join_configs[token] = {
        'user_code':    self.query.get('user_code') or '',
        'display_name': self.query.get('display_name') or '',
        'rcc_host':     self.query.get('rcc_host') or '127.0.0.1',
        'rcc_port':     int(self.query.get('rcc_port') or util.const.RFD_DEFAULT_PORT),
    }
    self.send_data(b'ok')
    return True


@server_path('/rfd/is-player-allowed')
def _(self: web_server_handler) -> bool:
    database = self.server.storage.players

    id_num = int(self.query['userId'])
    user_code = database.get_player_field_from_index(
        database.player_field.IDEN_NUM,
        id_num,
        database.player_field.USERCODE,
    )

    if user_code is None:
        self.send_data(b'false')
        return True

    # This function was also called during join-data creation.
    # It's called a second time here (potentially) for additional protection.
    if self.game_config.server_core.check_user_allowed.cached_call(
        7, user_code,
        id_num, user_code,
    ):
        self.send_data(b'true')
        return True

    self.send_data(b'false')
    return True


@server_path('/rfd/roblox-version')
def _(self: web_server_handler) -> bool:
    '''
    Used by clients to automatically detect which version to run.
    '''
    version = self.game_config.game_setup.roblox_version
    self.send_data(bytes(version.name, encoding='utf-8'))
    return True


@server_path('/Data/Upload.ashx')
def _(self: web_server_handler) -> bool:
    '''
    Handles asset uploads from Studio (e.g. MaterialVariant TexturePack XML).
    Generates a random 12-digit asset ID, stores the raw body in the asset
    cache under that ID, and returns the ID as a plain integer string --
    matching the real Roblox Data/Upload.ashx response format.
    '''
    import random as _random
    import os as _os
    try:
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length else b''
    except Exception:
        body = b''

    # Generate a random 12-digit ID that won't collide with real Roblox IDs.
    # Retry on the rare chance the cache already has this ID.
    asset_cache = self.game_config.asset_cache
    while True:
        asset_id = _random.randint(100_000_000_000, 999_999_999_999)
        if not _os.path.exists(asset_cache.get_asset_path(asset_id)):
            break

    asset_cache.add_asset(asset_id, body)

    # Real Roblox returns the asset version ID as a plain integer string.
    self.send_data(str(asset_id).encode())
    print('new texturepack id ' + str(asset_id))
    return True


@server_path('/rfd/set-proxy-target')
def _(self: web_server_handler) -> bool:
    '''
    Called by the player routine before launching the Roblox client.
    Updates the rbolock.tk reverse proxy target so the client's HTTPS
    traffic is forwarded to the correct remote server IP.
    Has no effect when the proxy is not running (non-rblxhub-cert mode).
    '''
    host = self.query.get('host', '127.0.0.1')
    port = int(self.query.get('port', str(util.const.RFD_DEFAULT_PORT)))
    proxy = getattr(self.server, 'proxy', None)
    if proxy is not None:
        proxy.set_target(host, port)
    self.send_data(b'ok')
    return True


@server_path('/game/validate-machine')
def _(self: web_server_handler) -> bool:
    self.send_json({"success": True})
    return True


@server_path('/Setting/QuietGet/StudioAppSettings/')
@server_path('/Setting/QuietGet/ClientAppSettings/')
def _(self: web_server_handler) -> bool:
    self.send_json({})
    return True


@server_path('/avatar-thumbnail/json')
def _(self: web_server_handler) -> bool:
    '''
    To simplify the server program, let not there be avatar thumbnail storage.
    '''
    self.send_json({})
    return True


@server_path('/avatar-thumbnail/image')
def _(self: web_server_handler) -> bool:
    '''
    To simplify the server program, let there not be avatar thumbnail images.
    '''
    return True


@server_path('/asset-thumbnail/json')
def _(self: web_server_handler) -> bool:
    '''
    TODO: properly deflect thumbnail generation.
    '''
    self.send_json({
        'Url': f'{self.hostname}/Thumbs/GameIcon.ashx',
        'Final': True,
        'SubstitutionType': 0,
    })
    return True


@server_path('/Thumbs/GameIcon.ashx')
def _(self: web_server_handler) -> bool:
    asset_cache = self.game_config.asset_cache
    thumbnail_data = asset_cache.get_asset(util.const.THUMBNAIL_ID_CONST)
    if isinstance(thumbnail_data, returns.ret_data):
        self.send_data(thumbnail_data.data)
    return True


@server_path('/v1/settings/application')
def _(self: web_server_handler) -> bool:
    self.send_json({'applicationSettings': {}})
    return True


@server_path('/users/account-info', versions={versions.rōblox.v535})
def _(self: web_server_handler) -> bool:
    '''
    RBLXHUB-style account bootstrap endpoint.
    Used by the 2022M studio client when fetching critical settings.
    '''
    self.send_json({
        "UserId": 21,
        "Username": "test",
        "DisplayName": "test",
        "HasPasswordSet": True,
        "Email": {
            "Value": "t***@real.com",
            "IsVerified": True,
        },
        "AgeBracket": 0,
        "Roles": [],
        "MembershipType": 0,
        "RobuxBalance": 99999999,
        "NotificationCount": 0,
        "EmailNotificationEnabled": False,
        "PasswordNotificationEnabled": False,
        "CountryCode": "US",
    })
    return True


@server_path('/v1/authentication-ticket/redeem', versions={versions.rōblox.v535})
def _(self: web_server_handler) -> bool:
    '''
    2022M authentication-ticket redeem stub.
    The client POSTs {"authenticationTicket": "<token>"} where the token is
    the UUID generated by the player routine and registered via /rfd/player-join-config.
    We map the client's IP to that token so /v1/join-game can look up join params.
    '''
    try:
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length else b''
        token = json.loads(body).get('authenticationTicket', '')
    except Exception:
        token = ''

    if token and hasattr(self.server, 'join_configs') and token in self.server.join_configs:
        if not hasattr(self.server, 'ip_to_token'):
            self.server.ip_to_token = {}
        client_ip = self.client_address[0]
        self.server.ip_to_token[client_ip] = token

    self.send_json({
        "userId": 21,
        "authenticationTicket": "local-ticket",
        "sessionId": "local-session",
        "isValid": True,
    })
    return True


_PC_DESKTOP_CLIENT_SETTINGS_PATH = os.path.join(
    os.path.dirname(__file__), 'pc_desktop_client_settings.json',
)


@functools.cache
def _get_pc_desktop_client_settings() -> dict:
    with open(_PC_DESKTOP_CLIENT_SETTINGS_PATH, encoding='utf-8') as f:
        return json.load(f)

_PCSTUDIOAPP_PATH = os.path.join(os.path.dirname(__file__), 'PCStudioApp.json')

@server_path('/v2/settings/application/PCDesktopClient', versions={versions.rōblox.v535})
def _(self: web_server_handler) -> bool:
    '''
    Studio FFlag settings blob (~275KB). Served from PCStudioApp.json
    sitting next to this file, so it can be edited without touching Python.
    '''
    try:
        with open(_PCSTUDIOAPP_PATH, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        self.send_json({'applicationSettings': {}})
        return True
    self.send_response(200)
    self.send_header('Content-Type', 'application/json')
    self.send_header('Content-Length', str(len(data)))
    self.end_headers()
    self.wfile.write(data)
    return True

@server_path('/v1/player-policies-client')
def _(self: web_server_handler) -> bool:
    self.send_json({
        'isSubjectToChinaPolicies': False,
        'arePaidRandomItemsRestricted': False,
        'isPaidItemTradingAllowed': True,
        'areAdsAllowed': True,
    })
    return True


@server_path(r'/users/(\d+)/canmanage/([\d]+)', regex=True)
def _(self: web_server_handler, match: re.Match[str]) -> bool:
    database = self.server.storage.players

    id_num = int(match.group(1))
    user_code = database.get_player_field_from_index(
        database.player_field.IDEN_NUM,
        id_num,
        database.player_field.USERCODE,
    )

    if user_code is None:
        result = False
    else:
        result = self.game_config.server_core.check_user_has_admin.cached_call(
            7, user_code,
            id_num, user_code,
        )

    self.send_json({"Success": True, "CanManage": result})
    return True


@server_path(r'/v1/user/(\d+)/is-admin-developer-console-enabled', regex=True)
def _(self: web_server_handler, match: re.Match[str]) -> bool:
    database = self.server.storage.players

    id_num = int(match.group(1))
    user_code = database.get_player_field_from_index(
        database.player_field.IDEN_NUM,
        id_num,
        database.player_field.USERCODE,
    )

    if user_code is None:
        result = False
    else:
        result = self.game_config.server_core.check_user_has_admin.cached_call(
            7, user_code,
            id_num, user_code,
        )

    self.send_json({"isAdminDeveloperConsoleEnabled": result})
    return True