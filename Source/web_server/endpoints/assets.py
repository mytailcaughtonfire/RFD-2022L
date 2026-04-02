from web_server._logic import web_server_handler, server_path
import assets.returns as returns
import util.const

# Toggle: serve KTX/DXT to Studio via TexturePack resolver.
# False = Studio gets plain XML (handles PBR itself, recommended).
# True  = Studio also gets KTX (experimental).
STUDIO_USE_KTX: bool = True

# Maps DXT accept header → ordered list of TexturePack XML element names to try.
# spec_dxt is ambiguous in old clients; prefer metalness, then roughness.
# Note: `ktx/dxt` is a transport/container accept header and does NOT indicate
# which TexturePack channel the client wants, so it must not be used for
# TexturePack channel resolution.
_DXT_TO_TEXTUREPACK_CHANNELS = {
    'rbx-format/color_dxt': ['color'],
    'rbx-format/norm_dxt':  ['normal'],
    'rbx-format/spec_dxt':  ['metalness', 'roughness'],
}

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
    # Also check the query string — the batch endpoint encodes the accept
    # format as ?accept=rbx-format/color_dxt etc. in the location URL.
    accept = self.headers.get('Accept')
    #if accept == 'ktx/dxt':
    #    self.send_error(404)
    #    return True
    accept_query = self.query.get('accept')
    if accept_query and (accept is None or accept == '*/*'):
        accept = accept_query

    is_studio = 'RobloxStudio' in (self.headers.get('User-Agent') or '')

    if is_studio and not STUDIO_USE_KTX and accept and accept in _DXT_TO_TEXTUREPACK_CHANNELS:
        accept = None

    # TexturePack DXT resolver: load XML from cache, resolve to texture ID, serve KTX.
    #print(f'[dxt check] id={asset_id} accept={accept} is_studio={is_studio}', flush=True)
    
    # For DXT TexturePack requests, we need to check the local cache first
    # regardless of the accept header — DXT path in get_asset bypasses the
    # file cache and goes straight to CDN, which won't have local IDs.
    # So we load the file directly, check if it's a TexturePack XML, and
    # resolve it ourselves before falling through to get_asset.
    if accept and accept in _DXT_TO_TEXTUREPACK_CHANNELS:
        asset_path = asset_cache.get_asset_path(asset_id)
        local_data = asset_cache._load_file(asset_path)
        if local_data is not None and b'<texturepack_version>' in local_data:
            # Prefer CDN's own TexturePack->DXT conversion when possible.
            # This preserves Roblox-side packing semantics for spec_dxt.
            if isinstance(asset_id, int):
                cdn_dxt_data = asset_cache.get_ktx_asset(asset_id, accept)
                if cdn_dxt_data is not None and cdn_dxt_data[:4] == b'\xabKTX':
                    kb = len(cdn_dxt_data) / 1024
                    #print(f'[asset] sending CDN TexturePack DXT id={asset_id} accept={accept} size={kb:.1f}KB magic={cdn_dxt_data[:4]}', flush=True)
                    self.send_data(cdn_dxt_data, content_type='application/gzip')
                    return True

    asset = asset_cache.get_asset(
        asset_id,
        bypass_blocklist=self.is_privileged,
        accept=accept,
    )

    if isinstance(asset, returns.ret_data):
        data = asset.data

        # Also handle the case where get_asset returned the XML
        # (e.g. cache hit before DXT bypass) with a DXT accept header.
        if accept and accept in _DXT_TO_TEXTUREPACK_CHANNELS:
            is_texturepack = (
                b'<texturepack_version>' in data or
                b'texturepack' in data[:256].lower()
            )
            if isinstance(asset_id, int):
                cdn_dxt_data = asset_cache.get_ktx_asset(asset_id, accept)
                if cdn_dxt_data is not None and cdn_dxt_data[:4] == b'\xabKTX':
                    kb = len(cdn_dxt_data) / 1024
                    #print(f'[asset] sending CDN TexturePack DXT id={asset_id} accept={accept} size={kb:.1f}KB magic={cdn_dxt_data[:4]}', flush=True)
                    self.send_data(cdn_dxt_data, content_type='application/gzip')
                    return True

        # Detect content type from magic bytes so the PBR pipeline
        # and other clients get the correct Content-Type header.
        if data[:8] == b'\x89PNG\r\n\x1a\n':
            content_type = 'image/png'
        elif data[:2] == b'\xff\xd8':
            content_type = 'image/jpeg'
        elif data[:4] in (b'<rbl', b'<rob'):
            content_type = 'application/xml'
        else:
            content_type = 'application/octet-stream'
        self.send_data(data, content_type=content_type)
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
    Batch asset delivery endpoint used by v554 to fetch multiple assets at once.
    Request body is gzip-compressed JSON:
        [{"assetId": 123, "assetType": "Image", "requestId": "0"}, ...]
    Response mirrors requestId back so the client can match responses to requests,
    and provides a location URL pointing to our /v1/asset endpoint.
    '''
    import gzip as _gzip
    import json as _json
    import os as _os
    import time as _time

    try:
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length else b''

        # Dump raw + decompressed body and headers for each request to a
        # numbered file so we can inspect all batch calls without overwriting.
        dump_dir = _os.path.join(_os.path.dirname(__file__), 'batch_dumps')
        _os.makedirs(dump_dir, exist_ok=True)
        stamp = f'{_time.time():.3f}_{self.headers.get("User-Agent", "unknown").split("/")[0]}'
        with open(_os.path.join(dump_dir, f'{stamp}.bin'), 'wb') as _f:
            _f.write(body)
        with open(_os.path.join(dump_dir, f'{stamp}.headers.txt'), 'w', encoding='utf-8') as _f:
            for k, v in self.headers.items():
                _f.write(f'{k}: {v}\n')

        if self.headers.get('Content-Encoding', '').lower() == 'gzip':
            body = _gzip.decompress(body)

        with open(_os.path.join(dump_dir, f'{stamp}.json'), 'w', encoding='utf-8') as _f:
            _f.write(body.decode('utf-8', errors='replace'))

        #print(f'[batch] Dumped to {dump_dir}/{stamp}.*', flush=True)

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
        # Pass the accept format as a query param so /v1/asset can forward
        # the correct Accept header to CDN for DXT texture requests.
        accept_fmt = item.get('accept', '')
        if accept_fmt:
            location = f'{base}/v1/asset?id={asset_id}&accept={accept_fmt}'
        else:
            location = f'{base}/v1/asset?id={asset_id}'
        results.append({
            'requestId':           item.get('requestId', '0'),
            'assetId':             int(asset_id),
            'location':            location,
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