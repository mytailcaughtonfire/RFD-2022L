$root = "$PSScriptRoot/.."

pyinstaller `
    --name "RFD" `
    --onefile "$root/Source/_main.py" `
    --paths "$root/Source/" `
    --workpath "$root/PyInstallerWork" `
    --distpath "$root" `
    --icon "$root/Source/Icon.ico" `
    --specpath "$root/PyInstallerWork/Spec" `
    --add-data "$root/Source/*:./Source" `
    --hidden-import requests `
    --hidden-import DracoPy `
    --hidden-import cryptography `
	--hidden-import numpy `
    --hidden-import assets.serialisers.csg `
    --hidden-import assets.serialisers.mesh `
    --hidden-import assets.serialisers.mesh.rbxmesh `
    --hidden-import assets.serialisers.rbxl `
    --hidden-import assets.serialisers.rbxlx `
    --hidden-import assets.serialisers.video `
    --collect-submodules assets.serialisers `
    --collect-submodules assets.serialisers.rbxl