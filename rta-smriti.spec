from PyInstaller.utils.hooks import collect_all, collect_data_files


datas = collect_data_files(
    "rta_brain",
    includes=["static/*", "static/assets/*", "data/*.json"],
)
tree_datas, tree_binaries, tree_hiddenimports = collect_all("tree_sitter_language_pack")
crypto_datas, crypto_binaries, crypto_hiddenimports = collect_all("cryptography")
watchdog_datas, watchdog_binaries, watchdog_hiddenimports = collect_all("watchdog")
datas += tree_datas + crypto_datas + watchdog_datas
binaries = tree_binaries + crypto_binaries + watchdog_binaries
hiddenimports = tree_hiddenimports + crypto_hiddenimports + watchdog_hiddenimports

analysis = Analysis(
    ["rta-brain.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "sentence_transformers", "transformers", "torch", "tensorflow",
        "numpy", "scipy", "pandas", "tiktoken",
    ],
    noarchive=False,
)
archive = PYZ(analysis.pure)
executable = EXE(
    archive,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    [],
    name="rta-brain",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
)
