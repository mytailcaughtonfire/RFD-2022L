# Standard library imports
import dataclasses
import functools
import time
import json
import os

# Typing imports
from typing import ClassVar, override

# Local application imports
from routines.rcc import startup_scripts
from config_type.types import wrappers
from .. import _logic as logic
import util.resource
import util.ssl_context
import util.versions
import game_config
import logger


@dataclasses.dataclass(kw_only=True, unsafe_hash=True)
class obj_type(logic.bin_entry, logic.loggable_entry, logic.gameconfig_entry):
    BIN_SUBTYPE = util.resource.bin_subtype.STUDIO
    DIRS_TO_ADD: ClassVar = [
        'logs', 'LocalStorage',
        'InstalledPlugins', 'placeIDEState',
        'ClientSettings',
    ]

    launch_delay: float = 0
    warn_drag: bool = True

    @override
    def get_base_url(self) -> str:
        if self.retr_version() == util.versions.rōblox.v554 and util.ssl_context.use_rblxhub_certs():
            return f'https://www.rbolock.tk:{self.web_port}'
        return f'https://{self.web_host}:{self.web_port}'

    @override
    def get_app_base_url(self) -> str:
        if self.retr_version() == util.versions.rōblox.v554 and util.ssl_context.use_rblxhub_certs():
            return f'https://www.rbolock.tk:{self.web_port}'
        return f'https://localhost:{self.web_port}'

    @override
    def __post_init__(self) -> None:
        super().__post_init__()

        if self.web_host == 'localhost':
            self.web_host = '127.0.0.1'

    @override
    def retr_version(self) -> util.versions.rōblox:
        return self.game_config.retr_version()

    def save_starter_scripts(self) -> None:
        server_path = self.get_versioned_path(os.path.join(
            'Content',
            'Scripts',
            'CoreScripts',
            'RFDStarterScript.lua',
        ))
        with open(server_path, 'w', encoding='utf-8') as f:
            startup_script = startup_scripts.get_script(self.game_config)
            f.write(startup_script)

    @override
    def update_fvars(self) -> None:
        super().update_fvars()
        if self.retr_version() != util.versions.rōblox.v554:
            return
        path = self.get_versioned_path('ClientSettings', 'ClientAppSettings.json')
        with open(path, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
        json_data['FFlagDebugLocalRccServerConnection'] = True
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent='\t')

    def patch_cacert_pem(self) -> None:
        '''
        Appends the RFD CA root certificate to Studio's ssl/cacert.pem so that
        libcurl-based requests trust our HTTPS server. For v554, we also install
        the CA to the Windows root store (see install_ca_to_windows_root) so
        that Studio's content provider trusts asset fetches.
        '''
        if self.retr_version() != util.versions.rōblox.v554:
            return
        ca_pem = util.ssl_context.get_ca_pem_bytes()
        cacert_path = self.get_versioned_path('ssl', 'cacert.pem')
        if not os.path.isfile(cacert_path):
            return

        with open(cacert_path, 'rb') as f:
            existing = f.read()

        if ca_pem in existing:
            return

        with open(cacert_path, 'ab') as f:
            f.write(b'\n# RFD CA\n')
            f.write(ca_pem)

    @functools.cache
    def setup_place(self) -> str:
        rbx_uri = self.game_config.server_core.place_file.rbxl_uri
        # If the file is local, simply have Studio load its path directly.
        if rbx_uri.uri_type == wrappers.uri_type.LOCAL:
            assert isinstance(rbx_uri.value, wrappers.path_str)
            return str(rbx_uri.value)

        # If the file is remote, have RFD fetch the data and save it locally.
        new_path = util.resource.retr_full_path(
            util.resource.dir_type.MISC,
            "_.rbxl",
        )
        rbxl_data = rbx_uri.extract()
        if rbxl_data is None:
            raise Exception('RBXL was not found.')
        with open(new_path, 'wb') as f:
            f.write(rbxl_data)
        return new_path

    @override
    def bootstrap(self) -> None:
        super().bootstrap()
        #self.save_app_settings()
        #self.make_aux_directories()
        # why did cursor remove these? need to check later. 
        # TODO: check
        if self.retr_version() == util.versions.rōblox.v554:
            util.ssl_context.install_ca_to_windows_root(self.logger)
            if util.ssl_context.use_rblxhub_certs():
                util.ssl_context._ensure_rbolock_hosts(self.logger)
        self.patch_cacert_pem()
        self.save_starter_scripts()
        time.sleep(self.launch_delay)
        self.init_popen(
            self.get_versioned_path('RobloxStudioBeta.exe'),
            (
                '-localPlaceFile',
                self.setup_place(),
            ))

    @override
    def wait(self):
        super().wait()
        self.kill()
