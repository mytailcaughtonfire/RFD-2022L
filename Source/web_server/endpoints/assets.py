from web_server._logic import web_server_handler, server_path
import assets.returns as returns
import util.const

#@server_path("/v2/assets")
#@server_path("/v2/assets/")

@server_path("/asset")
@server_path("/asset/")
@server_path("/Asset")
@server_path("/Asset/")
@server_path("/v1/asset")
@server_path("/v1/asset/")
@server_path("/.127.0.0.1/asset/")
def _(self: web_server_handler) -> bool:
    asset_cache = self.game_config.asset_cache

    # Paramater can either be `id` or `assetversionid`.
    asset_id = asset_cache.resolve_asset_query(self.query)

    if asset_id is None:
        self.send_error(404)
        return True

    if (
        asset_id == util.const.PLACE_IDEN_CONST and
        not self.is_privileged
    ):
        self.send_error(
            403,
            "Server hosters don't tend to like exposing their place files.  " +
            "Ask them if they'd be willing to lend this one to you.",
        )
        return True

    # Forward the Accept header so DXT texture requests (rbx-format/spec_dxt,
    # rbx-format/norm_dxt, etc.) get the right format from Roblox CDN,
    # matching RBLXHUB's asset.php special-case handling.
    accept = self.headers.get('Accept')

    asset = asset_cache.get_asset(
        asset_id,
        bypass_blocklist=self.is_privileged,
        accept=accept,
    )

    if isinstance(asset, returns.ret_data):
        self.send_data(asset.data)
        return True
    elif isinstance(asset, returns.ret_none):
        self.send_error(404)
        return True
    elif isinstance(asset, returns.ret_relocate):
        self.send_redirect(asset.url)
        return True
    return False

@server_path('/v1/assets/batch', commands={'POST'})
def _(self: web_server_handler) -> bool:
    '''
    Batch asset delivery endpoint used by v535 to fetch multiple assets at once.
    Request body is gzip-compressed JSON:
        [{"assetId": 123, "assetType": "Image", "requestId": "0"}, ...]
    Response mirrors requestId back so the client can match responses to requests,
    and provides a location URL pointing to our /v1/asset endpoint.
    '''
    import gzip as _gzip
    import json as _json
 
    try:
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length else b''
        if self.headers.get('Content-Encoding', '').lower() == 'gzip':
            body = _gzip.decompress(body)
        requests_list = _json.loads(body)
    except Exception:
        self.send_error(400)
        return True
 
    if not isinstance(requests_list, list):
        self.send_error(400)
        return True
 
    base = self.hostname
    results = []
    for item in requests_list:
        if not isinstance(item, dict):
            continue
        asset_id = item.get('assetId') or item.get('assetid')
        if asset_id is None:
            continue
        results.append({
            'requestId':           item.get('requestId', '0'),
            'assetId':             int(asset_id),
            'location':            f'{base}/v1/asset?id={asset_id}',
            'requestIdType':       'AltAssetId',
            'isHashDynamic':       False,
            'isCopyrightProtected': False,
            'isArchived':          False,
        })
 
    self.send_json(results)
    return True

@server_path('/ownership/hasasset', commands={'GET'})
def _(self: web_server_handler) -> bool:
    '''
    Typically used to check if players own specific catalogue items.
    There are no current plans to implement catalogue APIs in RFD.
    Collective ownership it is...
    '''
    self.send_json('true')
    return True