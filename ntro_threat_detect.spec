# -*- mode: python ; coding: utf-8 -*-
"""
ntro_threat_detect.spec — PyInstaller Build Specification for Windows Single-Folder Bundle.

Usage:
    pyinstaller --clean ntro_threat_detect.spec
"""

import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# Collect all dynamic Scapy protocol parsers and data assets
scapy_datas = collect_data_files('scapy')
scapy_submodules = collect_submodules('scapy')

# Collect scikit-learn submodules and hidden imports
sklearn_submodules = collect_submodules('sklearn')

added_datas = [
    ('dashboard/static', 'dashboard/static'),
    ('models', 'models'),
    ('samples/demo', 'samples/demo'),
] + scapy_datas

hidden_imports = [
    'uvicorn.logging',
    'uvicorn.loops.auto',
    'uvicorn.protocols.http.auto',
    'uvicorn.protocols.websockets.auto',
    'uvicorn.lifespan.on',
    'scapy.layers.inet',
    'scapy.layers.dns',
    'scapy.layers.tls.all',
    'scapy.arch.windows',
    'scapy.libs.winpcapy',
    'sqlalchemy.dialects.sqlite',
    'sklearn.ensemble._forest',
    'sklearn.utils._typedefs',
    'sklearn.neighbors._typedefs',
    'sklearn.tree._utils',
] + scapy_submodules + sklearn_submodules

a = Analysis(
    ['launcher.py'],
    pathex=['.'],
    binaries=[],
    datas=added_datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'notebook', 'torch'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='ntro_threat_detect',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='ntro_threat_detect',
)
