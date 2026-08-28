# -*- mode: python ; coding: utf-8 -*-

import os


pure_python_override = os.environ.get('KMTECH_PURE_PYTHON_OVERRIDE', '').strip()
analysis_paths = [pure_python_override] if pure_python_override else []
factory_identity_root = os.environ.get(
    'KMTECH_FACTORY_CONTRACT_IDENTITY_ROOT',
    'build/factory_contract_identity',
).strip()

a = Analysis(
    ['Container_Audit.py'],
    pathex=analysis_paths,
    binaries=[],
    datas=[('assets', 'assets'), ('build/release_config', 'config'), ('build/release_tools', 'tools'), ('direct_sync_push.py', '.'), ('direct_sync_runtime.py', '.'), ('producer_runtime_client.py', '.'), ('direct_sync_operator.py', '.'), ('event_log_store.py', '.'), ('storage_policy.py', '.'), ('storage_utils.py', '.'), ('recovery_two_phase.py', '.'), ('logistics_runtime_profile.py', '.'), ('isolated_qualification.py', '.'), ('kmtech_factory_contracts/bundle', 'kmtech_factory_contracts/bundle'), (os.path.join(factory_identity_root, 'build-identity.json'), '.'), (os.path.join(factory_identity_root, 'build-compatibility.json'), '.'), ('contract.lock.json', '.')],
    hiddenimports=['tools.direct_sync_relay_runner'],
    hookspath=['tools/pyinstaller_hooks'],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'PIL',
        '_cffi_backend',
        'cffi',
        'cryptography',
        'pygame',
        'charset_normalizer.md__mypyc',
        '_brotli',
        'brotli',
        'bcrypt',
        'jsonschema',
        'jsonschema_specifications',
        'numpy',
        'psutil',
        'pywintypes',
        'referencing',
        'rpds',
        'win32',
        'win32pdh',
        'yaml',
    ],
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
