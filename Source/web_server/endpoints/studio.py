# Standard library imports
import json
import os
import time
from email.utils import formatdate

# Local application imports
import util.const
import util.versions as versions
from web_server._logic import web_server_handler, server_path


_ROBLOSECURITY = (
    '_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|'
    '_DGJJD464646464dfgdgdgdCUdgjneth4iht4ih64uh4uihy4y4yuhi4yhuiyhui4yhui4uihy4huiyhu4iyhuihu4hhdghdgihdigdhuigdhuig'
    'dhuigihugdgidojgijodijogdijogdjoigdjoidijogijodgijdgiojdgijodgijoF'
)

_RBXID = (
    '_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|'
    '_eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI2NDA3MGQyNC0zYWR4LTQ5NzMtODAxYy0yOWNhNzUyNTA5NjIiLCJzdWfdijogdoijdijogijodcB6YExhM'
)


def _make_cookie(name: str, value: str) -> str:
    '''
    Builds a Set-Cookie header value with a two-week expiry,
    matching PHP's setcookie($name, $value, time()+1209600).
    '''
    expires = formatdate(time.time() + 1209600, usegmt=True)
    return f'{name}={value}; expires={expires}; Max-Age=1209600; path=/; HttpOnly'


@server_path('/studio/e.png')
def _(self: web_server_handler) -> bool:
    self.send_data(b'')
    return True


@server_path('/login/RequestAuth.ashx')
def _(self: web_server_handler) -> bool:
    self.send_data(self.hostname + '/login/negotiate.ashx')
    return True


@server_path('/v2/login')
def _(self: web_server_handler) -> bool:
    self.send_response(200)
    self.send_header('set-cookie', _make_cookie('.ROBLOSECURITY', _ROBLOSECURITY))
    self.send_header('set-cookie', _make_cookie('.RBXID', _RBXID))
    self.send_json({
        'user': {
            'id': 1,
            'name': 'Roblox',
            'displayName': 'Roblox',
        },
    }, status=None)
    return True

#    try:
#        # Password must not contain '1'.  This for debugging purposes only.
#        assert (
#            '1' not in json.loads(self.read_content())['password']
#        )
#        self.send_response(200)
#        self.send_header('set-cookie', '.ROBLOSECURITY=_ROBLOSECURITY_')
#        self.send_json({
#            'user': {
#                'id': 1630228,
#                'name': 'qwer',
#                'displayName': 'qwer',
#            },
#            'isBanned': False,
#        }, status=None)
#    except Exception:
#        self.send_response(401)


@server_path('/Users/1630228')
@server_path('/game/GetCurrentUser.ashx')
def _(self: web_server_handler) -> bool:
    time.sleep(2)  # HACK: Studio 2021E won't work without it.
    self.send_json(1630228)
    return True


@server_path('/users/account-info')
def _(self: web_server_handler) -> bool:
    try:
        user_id_num = json.loads(self.headers['Roblox-Session-Id'])['UserId']
    except TypeError:
        return True

    funds = self.server.storage.funds.check(user_id_num)
    self.send_json({
        "UserId": user_id_num,
        "RobuxBalance": funds or 0,
    })
    return True


@server_path('/device/initialize')
def _(self: web_server_handler) -> bool:
    self.send_json({"browserTrackerId": 1, "appDeviceIdentifier": None}) # TODO: check if setting browserTrackerId to 1 ruins 2018 and 2021 compat?
    return True


@server_path('/v1/users/authenticated')
def _(self: web_server_handler) -> bool:
    self.send_json({
        "id": 1,
        "name": "ROBLOX",
        "displayName": "ROBLOX"
    })
    return True


@server_path(r'/v1/usera/\d+', regex=True)
def _(self: web_server_handler, match) -> bool:
    self.send_json({
        'description': (
            'Welcome to the Roblox profile! This is where you can check out the newest items '
            'in the catalog, and get a jumpstart on exploring and building on our Imagination '
            'Platform. If you want news on updates to the Roblox platform, or great new '
            'experiences to play with friends, check out blog.roblox.com. Please note, this '
            'is an automated account. If you need to reach Roblox for any customer service '
            'needs find help at www.roblox.com/help'
        ),
        'created': '2006-02-27T21:06:40.3Z',
        'isBanned': False,
        'externalAppDisplayName': None,
        'hasVerifiedBadge': True,
        'id': 1,
        'name': 'Roblox',
        'displayName': 'Roblox',
    })
    return True

@server_path('/studio-login/v1/login', versions={versions.rōblox.v535})
def _(self: web_server_handler) -> bool:
    self.send_response(200)
    self.send_header('set-cookie', _make_cookie('.ROBLOSECURITY', _ROBLOSECURITY))
    self.send_header('set-cookie', _make_cookie('.RBXID', _RBXID))
    self.send_json({
        'user': {
            'UserId': 1,
            'Username': 'Roblox',
            'AgeBracket': 0,
            'Roles': [],
            'Email': {
                'value': 'r*********@rbolock.tk',
                'isVerified': True,
            },
            'IsBanned': False,
            'DisplayName': 'Roblox',
        },
        'userAgreements': [],
    }, status=None)
    return True


@server_path('/v1/game-start-info', versions={versions.rōblox.v535})
@server_path('/v1.1/game-start-info', versions={versions.rōblox.v535})
def _(self: web_server_handler) -> bool:
    '''Avatar type and scale configuration for 2022M.'''
    self.send_json({
        'gameAvatarType': 'PlayerChoice',
        'allowCustomAnimations': 'True',
        'universeAvatarCollisionType': 'OuterBox',
        'universeAvatarBodyType': 'Standard',
        'jointPositioningType': 'ArtistIntent',
        'message': '',
        'universeAvatarMinScales': {
            'height': 0.9, 'width': 0.7, 'head': 0.95,
            'depth': 0, 'proportion': 0, 'bodyType': 0,
        },
        'universeAvatarMaxScales': {
            'height': 1.05, 'width': 1, 'head': 1,
            'depth': 0, 'proportion': 0, 'bodyType': 0,
        },
        'universeAvatarAssetOverrides': [],
        'moderationStatus': None,
    })
    return True


@server_path('/studio-open-place/v1/openplace', versions={versions.rōblox.v535})
def _(self: web_server_handler) -> bool:
    '''
    Studio "Open place" endpoint. Returns place/universe metadata for placeId.
    Required when Studio opens place 1818 from the server (api.rbolock.tk).
    '''
    try:
        place_id = int(self.query.get('placeId', util.const.PLACE_IDEN_CONST))
    except (ValueError, TypeError):
        place_id = util.const.PLACE_IDEN_CONST
    self.send_json({
        'universe': {
            'Id': place_id,
            'RootPlaceId': place_id,
            'Name': 'RFD Place',
            'IsArchived': False,
            'CreatorType': 'User',
            'CreatorTargetId': 1,
            'PrivacyType': 'Public',
            'Created': '2022-01-01T00:00:00.00+00:00',
            'Updated': '2022-01-01T00:00:00.00+00:00',
        },
        'teamCreateEnabled': False,
        'place': {
            'Creator': {'CreatorType': 'User', 'CreatorTargetId': 1},
        },
    })
    return True


@server_path('/game/GetCurrentUser.ashx', versions={versions.rōblox.v535})
def _(self: web_server_handler) -> bool:
    self.send_json(1)
    return True


@server_path('/My/settings/json', versions={versions.rōblox.v535})
def _(self: web_server_handler) -> bool:
    '''
    2022M user settings endpoint.  Returns account metadata that Studio
    expects. Ported from RBLXHUB My/settings/json.php.
    '''
    base = self.hostname
    self.send_json({
        'ChangeUsernameEnabled': True,
        'IsAdmin': True,
        'UserId': 1,
        'Name': 'Roblox',
        'DisplayName': 'Roblox',
        'IsEmailOnFile': True,
        'IsEmailVerified': True,
        'IsPhoneFeatureEnabled': True,
        'RobuxRemainingForUsernameChange': 9999999,
        'PreviousUserNames': '',
        'UseSuperSafePrivacyMode': False,
        'IsAppChatSettingEnabled': True,
        'IsGameChatSettingEnabled': True,
        'IsParentalSpendControlsEnabled': True,
        'IsSetPasswordNotificationEnabled': False,
        'ChangePasswordRequiresTwoStepVerification': False,
        'ChangeEmailRequiresTwoStepVerification': False,
        'UserEmail': 'r*********@rbolock.tk',
        'UserEmailMasked': True,
        'UserEmailVerified': True,
        'CanHideInventory': True,
        'CanTrade': True,
        'MissingParentEmail': False,
        'IsUpdateEmailSectionShown': True,
        'IsUnder13UpdateEmailMessageSectionShown': False,
        'IsUserConnectedToFacebook': False,
        'IsTwoStepToggleEnabled': False,
        'AgeBracket': 0,
        'UserAbove13': True,
        'ClientIpAddress': '127.0.0.1',
        'AccountAgeInDays': 360,
        'IsPremium': False,
        'IsBcRenewalMembership': False,
        'PremiumFeatureId': None,
        'HasCurrencyOperationError': False,
        'CurrencyOperationErrorMessage': None,
        'Tab': None,
        'ChangePassword': False,
        'IsAccountPinEnabled': False,
        'IsAccountRestrictionsFeatureEnabled': False,
        'IsAccountRestrictionsSettingEnabled': False,
        'IsAccountSettingsSocialNetworksV2Enabled': False,
        'IsUiBootstrapModalV2Enabled': True,
        'IsDateTimeI18nPickerEnabled': True,
        'InApp': False,
        'MyAccountSecurityModel': {
            'IsEmailSet': True,
            'IsEmailVerified': True,
            'IsTwoStepEnabled': False,
            'ShowSignOutFromAllSessions': True,
            'TwoStepVerificationViewModel': {
                'UserId': 1,
                'IsEnabled': False,
                'CodeLength': 0,
                'ValidCodeCharacters': None,
            },
        },
        'ApiProxyDomain': base,
        'AccountSettingsApiDomain': base,
        'AuthDomain': base,
        'IsDisconnectFacebookEnabled': True,
        'IsDisconnectXboxEnabled': True,
        'NotificationSettingsDomain': base,
        'AllowedNotificationSourceTypes': [
            'Test', 'FriendRequestReceived', 'FriendRequestAccepted',
            'PartyInviteReceived', 'PartyMemberJoined', 'ChatNewMessage',
            'PrivateMessageReceived', 'UserAddedToPrivateServerWhiteList',
            'ConversationUniverseChanged', 'TeamCreateInvite', 'GameUpdate',
            'DeveloperMetricsAvailable', 'GroupJoinRequestAccepted',
            'Sendr', 'ExperienceInvitation',
        ],
        'AllowedReceiverDestinationTypes': ['NotificationStream'],
        'BlacklistedNotificationSourceTypesForMobilePush': [],
        'MinimumChromeVersionForPushNotifications': 50,
        'PushNotificationsEnabledOnFirefox': False,
        'LocaleApiDomain': base,
        'HasValidPasswordSet': True,
        'IsFastTrackAccessible': False,
        'HasFreeNameChange': False,
        'IsAgeDownEnabled': True,
        'IsDisplayNamesEnabled': True,
        'IsBirthdateLocked': False,
    })
    return True


@server_path('/My', versions={versions.rōblox.v535})
@server_path('/My/', versions={versions.rōblox.v535})
def _(self: web_server_handler) -> bool:
    '''2022M My base. Placeholder for RBLXHUB compatibility.'''
    self.send_json({
        'UserId': 1,
        'Name': 'Roblox',
        'DisplayName': 'Roblox',
    })
    return True


@server_path('/My/Places', versions={versions.rōblox.v535})
@server_path('/My/Places.aspx', versions={versions.rōblox.v535})
def _(self: web_server_handler) -> bool:
    '''2022M My Places. Returns empty place list for Studio.'''
    self.send_json({'data': [], 'nextPageCursor': None})
    return True


@server_path('/GetAllowedSecurityKeys/index', versions={versions.rōblox.v535})
@server_path('/GetAllowedSecurityKeys/', versions={versions.rōblox.v535})
def _(self: web_server_handler) -> bool:
    self.send_json({})
    return True


@server_path(r'/universal-app-configuration/v1/behaviors/[^/]+/content', regex=True, versions={versions.rōblox.v535})
def _(self: web_server_handler, match) -> bool:
    self.send_json({})
    return True

_PCSTUDIOAPP_PATH = os.path.join(os.path.dirname(__file__), 'PCStudioApp.json')

@server_path('/v2/settings/application/PCStudioApp', versions={versions.rōblox.v535})
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