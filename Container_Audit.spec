# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['Container_Audit.py'],
    pathex=[],
    binaries=[],
    datas=[('assets', 'assets'), ('build/release_config', 'config'), ('build/release_tools', 'tools'), ('direct_sync_push.py', '.'), ('direct_sync_runtime.py', '.'), ('producer_runtime_client.py', '.'), ('direct_sync_operator.py', '.'), ('event_log_store.py', '.'), ('storage_policy.py', '.'), ('storage_utils.py', '.'), ('logistics_runtime_profile.py', '.'), ('isolated_qualification.py', '.'), ('kmtech_factory_contracts/bundle', 'kmtech_factory_contracts/bundle'), ('build/factory_contract_identity/build-identity.json', '.'), ('build/factory_contract_identity/build-compatibility.json', '.'), ('contract.lock.json', '.')],
    hiddenimports=['pygame', 'PIL.Image', 'PIL.ImageTk'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='Container_Audit',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['assets\\logo.ico'],
    contents_directory='.',
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='Container_Audit',
)
