# Standard library imports
import json
import time

# Typing imports
from typing import Any

# Local application imports
import util.const
import game_config
import util.versions as versions
from web_server._logic import web_server_handler, server_path


def gen_player(config: game_config.obj_type, usercode: str) -> tuple[int, str, bool] | None:
    '''
    Returns a tuple with the following:
    `int`: corresponds with the iden number of a user whose `index` field matches `value`.
    `str`: corresponds with the username of a user whose `index` field matches `value`.
    `bool`: returns `True` if the player is being created for the first time.
    '''
    database = config.storage.players
    existing = database.check(usercode)
    if existing is not None:
        return (*existing, False)

    # Keeps generating an iden number until it finds one that is not yet in the database.
    while True:
        iden_num = config.server_core.retrieve_user_id(usercode)
        if not config.server_core.check_user_allowed.cached_call(
            7, usercode,
            iden_num, usercode,
        ):
            return None

        username = config.server_core.retrieve_username(iden_num, usercode)

        result = database.add_player(
            usercode, iden_num, username,
        )

        if result is not None:
            return (*result, True)


def init_player(config: game_config.obj_type, usercode: str) -> tuple[int, str] | None:
    '''
    Returns a tuple with the following:
    `int`: corresponds with that user's `id_num`.
    `str`: corresponds with that user's `username`.
    '''
    player_data = gen_player(config, usercode)
    if player_data is None:
        return None
    (iden_num, username, first_time) = player_data

    if first_time:
        funds = config.server_core.retrieve_default_funds(iden_num, usercode)
        config.storage.funds.first_init(iden_num, funds)

    return (iden_num, username)


def perform_and_send_join(self: web_server_handler, additional_return_data: dict[str, Any], prefix: bytes) -> None:
    '''
    The query arguments in `Roblox-Session-Id` were previously serialised.
    For example, when `join.ashx` was called the first time a player joined.

    Some methods (such as retrieving a user fund balance, or rejoining in 2021E) need data from `Roblox-Session-Id`.
    '''
    config = self.game_config
    server_core = config.server_core

    query_args: dict[str, str] = json.loads(
        self.headers.get('Roblox-Session-Id', '{}'),
    ) | self.query

    # Fallbacks here should point to the local RCC server rather than the
    # HTTPS web hostname, otherwise the client will try to connect to an
    # invalid address like "https://api.rbolock.tk:2005".
    rcc_host_addr = str(query_args.get('MachineAddress', '127.0.0.1'))
    rcc_port = int(query_args.get('ServerPort', util.const.RFD_DEFAULT_PORT))
    user_code = query_args.get('UserCode')
    if not user_code:
        user_code = self.game_config.server_core.retrieve_default_user_code(
            time.time(),
        )

    result = init_player(self.game_config, user_code)
    if result is None:
        self.send_json({"error": "403: disallowed user"}, 403)
        return

    (id_num, username) = result

    join_data = {
        'ServerConnections': [
            {
                'Address': rcc_host_addr,
                'Port': rcc_port,
            }
        ],
        'UserCode':
            user_code,
        'UserId':
            id_num,
        'MachineAddress':
            rcc_host_addr,
        'ServerPort':
            rcc_port,
        'BaseUrl':
            self.hostname,
        'PlaceId':
            util.const.PLACE_IDEN_CONST,
        'UserName':
            username,
        'DisplayName':
            username,
        'AccountAge':
            server_core.retrieve_account_age(id_num, user_code),
        'ChatStyle':
            server_core.chat_style.value,
        'characterAppearanceId':
            id_num,
        'CharacterAppearanceId':
            id_num,
        'CharacterAppearance':
            f'{self.hostname}/v1.1/avatar-fetch?userId={id_num}',
    }

    # NOTE: the `SessionId` is saved as an HTTPS header `Roblox-Session-Id` for later requests.
    # I'm placing the information which was passed into `join.ashx` here for simplicity.
    join_data |= {
        'SessionId': json.dumps(join_data | {'RFDJoinQuery': query_args})
    }
    self.send_json(join_data | additional_return_data, prefix=prefix)


@server_path('/game/join.ashx', versions={versions.rōblox.v347})
def _(self: web_server_handler) -> bool:
    perform_and_send_join(self, {
        'ClientPort': 0,
        'PingUrl': '',
        'PingInterval': 0,
        'SeleniumTestMode': False,
        'SuperSafeChat': False,
        'MeasurementUrl': '',
        'WaitingForCharacterGuid': '',
        'VendorId': 0,
        'ScreenShotInfo': '',
        'VideoInfo': '',
        'CreatorId': 0,
        'CreatorTypeEnum': 'User',
        'MembershipType': 'None',
        'CookieStoreFirstTimePlayKey': 'rbx_evt_ftp',
        'CookieStoreFiveMinutePlayKey': 'rbx_evt_fmp',
        'CookieStoreEnabled': False,
        'IsRobloxPlace': True,
        'GenerateTeleportJoin': False,
        'IsUnknownOrUnder13': False,
        'DataCenterId': 0,
        'FollowUserId': 0,
        'UniverseId': 0,
    }, prefix=b'--rbxsig%0%\r\n')
    return True


@server_path('/game/join.ashx', versions={versions.rōblox.v463})
def _(self: web_server_handler) -> bool:
    perform_and_send_join(self, {
        'ClientPort': 0,
        'PingUrl': '',
        'PingInterval': 0,
        'DirectServerReturn': True,
        'SeleniumTestMode': False,
        'RobloxLocale': 'en_us',
        'GameLocale': 'en_us#RobloxTranslateAbTest2',
        'SuperSafeChat': True,
        'ClientTicket': '2022-03-26T05:13:05.7649319Z;dj09X5iTmYtOPwh0hbEC8yvSO1t99oB3Yh5qD/sinDFszq3hPPaL6hH16TvtCen6cABIycyDv3tghW7k8W+xuqW0/xWvs0XJeiIWstmChYnORzM1yCAVnAh3puyxgaiIbg41WJSMALRSh1hoRiVFOXw4BKjSKk7DrTTcL9nOG1V5YwVnmAJKY7/m0yZ81xE99QL8UVdKz2ycK8l8JFvfkMvgpqLNBv0APRNykGDauEhAx283vARJFF0D9UuSV69q6htLJ1CN2kXL0Saxtt/kRdoP3p3Nhj2VgycZnGEo2NaG25vwc/KzOYEFUV0QdQPC8Vs2iFuq8oK+fXRc3v6dnQ==;BO8oP7rzmnIky5ethym6yRECd6H14ojfHP3nHxSzfTs=;XsuKZL4TBjh8STukr1AgkmDSo5LGgQKQbvymZYi/80TYPM5/MXNr5HKoF3MOT3Nfm0MrubracyAtg5O3slIKBg==;6',
        'GameId': util.const.PLACE_IDEN_CONST,
        'CreatorId': 0,
        'CreatorTypeEnum': 'User',
        'MembershipType': 'None',
        'CookieStoreFirstTimePlayKey': 'rbx_evt_ftp',
        'CookieStoreFiveMinutePlayKey': 'rbx_evt_fmp',
        'CookieStoreEnabled': True,
        'IsUnknownOrUnder13': False,
        'GameChatType': 'AllUsers',
        'AnalyticsSessionId': 'c89589f1-d1de-46e3-80e0-2703d1159409',
        'DataCenterId': 302,
        'UniverseId': 994732206,
        'FollowUserId': 0,
        'CountryCode': 'US',
        'RandomSeed1': '7HOfysTid4XsV/3mBPPPhKHIykE4GXSBBBzd93rplbDQ3bNSgPFcR9auB780LjNYg+4mbNQPOqTmJ2o3hUefmw==',
        'ClientPublicKeyData': json.dumps({
            'creationTime': '19:56 11/23/2021',
            'applications': {
                'RakNetEarlyPublicKey': {
                    'versions': [{
                        'id': 2,
                        'value': 'HwatfCnkndvyKCMPSa0VAl2M2c0GQv9+0z0kENhcj2w=',
                        'allowed': True,
                    }],
                    'send': 2,
                    'revert': 2,
                }
            }
        }),
    }, prefix=b'--rbxsig2%0%\r\n')
    return True


@server_path('/game/PlaceLaunch22.ashx', versions={versions.rōblox.v535})
def _(self: web_server_handler) -> bool:
    '''
    2022M (v535) join endpoint.  Returns a JSON joinScript directly so the
    client can connect to Server.exe without an intermediate PlaceLauncher
    redirect.  TokenValue and PepperId are bypass values that disable the
    client's authentication checks.
    '''
    query_args: dict[str, str] = json.loads(
        self.headers.get('Roblox-Session-Id', '{}'),
    ) | self.query

    rcc_host = str(query_args.get('MachineAddress', '127.0.0.1'))
    rcc_port = int(query_args.get('ServerPort', util.const.RFD_DEFAULT_PORT))
    user_code = query_args.get('UserCode')
    if not user_code:
        user_code = self.game_config.server_core.retrieve_default_user_code(
            time.time(),
        )

    result = init_player(self.game_config, user_code)
    if result is None:
        self.send_json({'error': '403: disallowed user'}, 403)
        return True

    (id_num, username) = result
    server_core = self.game_config.server_core

    # v535 client may fetch place from assetdelivery; use it for PlaceFetchUrl
    # when host is www so the request hits our server (hosts: assetdelivery.rbolock.tk).
    place_fetch_host = self.hostname
    if 'www.rbolock.tk' in self.hostname:
        place_fetch_host = self.hostname.replace('www.rbolock.tk', 'assetdelivery.rbolock.tk')

    join_script = {
        'ClientTicket': '',
        'NewClientTicket': '',
        'MachineAddress': rcc_host,
        'ServerPort': rcc_port,
        'CharacterAppearance': f'{self.hostname}/v1.1/avatar-fetch?userId={id_num}',
        'CharacterAppearanceId': id_num,
        'characterAppearanceId': id_num,
        'UserId': id_num,
        'UserName': username,
        'DisplayName': username,
        'MembershipType': 0,
        'AccountAge': server_core.retrieve_account_age(id_num, user_code),
        'PingUrl': '',
        'PingInterval': 0,
        'ChatStyle': server_core.chat_style.value,
        'GameChatType': 'AllUsers',
        # Bypass values — skip the client's network security key / signature checks.
        'TokenValue': 'WbTnhqvC68TN2/lveKnrgA==',
        'PepperId': 1701041219,
        'RccVersion': '0.603.3.6030569',
        'PlaceId': util.const.PLACE_IDEN_CONST,
        'UniverseId': util.const.PLACE_IDEN_CONST,
        'GameId': str(util.const.PLACE_IDEN_CONST),
        'BaseUrl': self.hostname,
        'PlaceFetchUrl': f'{place_fetch_host}/asset/?id={util.const.PLACE_IDEN_CONST}',
        'CreatorId': 0,
        'CreatorType': 'User',
        'FollowUserId': 0,
        'IsTeleport': False,
        'SeleniumTestMode': False,
        'IsUnknownOrUnder13': False,
        'IsUserPlayingWithTeleportedChildren': False,
        'CountryCode': 'US',
        'IsoCountryCode': 'US',
        'DataCenterId': '',
        'UniverseAgeInDays': 0,
        'MatchmakingDecisionId': '',
        'MeasureConnectionPerformance': False,
        'SendAdditionalTelemetryData': False,
        'DirectServerReturn': False,
        'ServerConnections': [
            {
                'Address': rcc_host,
                'Port': rcc_port,
            }
        ],
    }
    self.send_json(join_script)
    return True


@server_path('/v1/join-game', versions={versions.rōblox.v535})
def _(self: web_server_handler) -> bool:
    '''
    2022M API join endpoint (RBLXHUB-style).
    Returns {"status": 2, "message": null, "joinScript": {...}}.
    '''
    query_args: dict[str, str] = json.loads(
        self.headers.get('Roblox-Session-Id', '{}'),
    ) | self.query

    rcc_host = str(query_args.get('MachineAddress', '127.0.0.1'))
    rcc_port = int(query_args.get('ServerPort', util.const.RFD_DEFAULT_PORT))
    user_code = query_args.get('UserCode')
    if not user_code:
        user_code = self.game_config.server_core.retrieve_default_user_code(
            time.time(),
        )

    result = init_player(self.game_config, user_code)
    if result is None:
        self.send_json({
            'status': 12,
            'message': 'No available server',
            'joinScript': None,
        })
        return True

    (id_num, username) = result
    server_core = self.game_config.server_core

    place_fetch_host = self.hostname
    if 'www.rbolock.tk' in self.hostname:
        place_fetch_host = self.hostname.replace('www.rbolock.tk', 'assetdelivery.rbolock.tk')

    join_script = {
        'ClientPort': 0,
        'MachineAddress': rcc_host,
        'ServerPort': rcc_port,
        'ServerConnections': [
            {
                'Address': rcc_host,
                'Port': rcc_port,
            }
        ],
        'DirectServerReturn': True,
        'PepperId': 1701041219,
        'TokenValue': 'WbTnhqvC68TN2/lveKnrgA==',
        'PingUrl': '',
        'PingInterval': 120,
        'UserName': username,
        'DisplayName': username,
        'HasVerifiedBadge': False,
        'SeleniumTestMode': False,
        'UserId': id_num,
        'RobloxLocale': 'en_us',
        'GameLocale': 'en_us',
        'SuperSafeChat': False,
        'FlexibleChatEnabled': False,
        'CharacterAppearance': f'{self.hostname}/v1.1/avatar-fetch?userId={id_num}',
        'characterAppearanceId': id_num,
        'ClientTicket': 'no',
        'GameId': 'f8a9c0b7-df1a-4eed-b9e3-2c08a38b3a77',
        'PlaceId': util.const.PLACE_IDEN_CONST,
        'UniverseId': util.const.PLACE_IDEN_CONST,
        'BaseUrl': self.hostname,
        'PlaceFetchUrl': f'{place_fetch_host}/asset/?id={util.const.PLACE_IDEN_CONST}',
        'ChatStyle': server_core.chat_style.value,
        'CreatorId': 0,
        'CreatorTypeEnum': 'User',
        'MembershipType': 'None',
        'AccountAge': server_core.retrieve_account_age(id_num, user_code),
        'CookieStoreFirstTimePlayKey': 'rbx_evt_ftp',
        'CookieStoreFiveMinutePlayKey': 'rbx_evt_fmp',
        'CookieStoreEnabled': True,
        'IsUnknownOrUnder13': False,
        'GameChatType': 'AllUsers',
        'SessionId': '',
        'AnalyticsSessionId': 'c89589f1-d1de-46e3-80e0-2703d1159409',
        'DataCenterId': 370,
        'FollowUserId': 0,
        'CountryCode': 'US',
        'AlternateName': '',
        'RandomSeed1': '',
        'ClientPublicKeyData': 'Test',
        'RccVersion': '0.603.3.6030569',
        'ChannelName': '',
        'VerifiedAMP': 0,
        'PrivateServerOwnerID': 0,
        'PrivateServerID': '',
    }

    self.send_json({
        'status': 2,
        'message': None,
        'joinScript': join_script,
    })
    return True


@server_path('/login/negotiate.ashx')
@server_path('/universes/validate-place-join')
def _(self: web_server_handler) -> bool:
    self.send_json(True)
    return True


@server_path('/game/PlaceLauncher.ashx')
@server_path('/game/placelauncher.ashx')
def _(self: web_server_handler) -> bool:

    query_args = json.loads(
        self.headers.get('Roblox-Session-Id', '{}'),
    ) | self.query
    user_code = query_args.get('UserCode')
    if not user_code:
        user_code = self.game_config.server_core.retrieve_default_user_code(
            time.time(),
        )

    result = init_player(self.game_config, user_code)
    if result is None:
        self.send_json({
            'status': 12,
            'jobId': '67',
            'joinScriptUrl': f'{self.hostname}/game/join.ashx?{self.url_split.query}',
            'authenticationUrl': f'{self.hostname}/login/negotiate.ashx',
            'authenticationTicket': '67',
            'message': None,
        })
        return True

    self.send_json({
        'status': 2,
        'joinScriptUrl': f'{self.hostname}/game/join.ashx?{self.url_split.query}',
        'authenticationUrl': f'{self.hostname}/login/negotiate.ashx',
        'authenticationTicket': '67',
        'jobId': '67',
        'message': '',
    })
    return True