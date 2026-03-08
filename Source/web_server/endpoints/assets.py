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


@server_path('/ownership/hasasset', commands={'GET'})
def _(self: web_server_handler) -> bool:
    '''
    Typically used to check if players own specific catalogue items.
    There are no current plans to implement catalogue APIs in RFD.
    Collective ownership it is...
    '''
    self.send_json('true')
    return True