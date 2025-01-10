# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['huawei.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['netmiko', 'paramiko', 'textfsm', 'ntc_templates'],
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
    a.binaries,
    a.datas,
    [],
    name='华为交换机配置备份工具',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['D:\\cursor\\huawei.ico'],
)
