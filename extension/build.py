"""Assemble and zip the CipherVault addon for Chromium and Firefox.

Usage:  python build.py            -> dist/chromium, dist/firefox + both zips
        python build.py --no-zip   -> folders only
"""
import json
import os
import shutil
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
COMMON = os.path.join(HERE, "common")
ICONS = os.path.join(HERE, "icons")
DIST = os.path.join(HERE, "dist")

CHROMIUM = os.path.join(DIST, "chromium")
FIREFOX = os.path.join(DIST, "firefox")

COMMON_FILES = [
    "crypto.js", "api.js", "domains.js", "totp.js", "background.js",
    "content.js", "popup.html", "popup.css", "popup.js",
]

# Chromium MV3: an additionally-named copy of the service worker script. Some
# Chrome builds lazily cache SW script bodies for --load-extension reinstalls,
# so the shipped filename is bumped along with the version to force re-fetch.
CHROMIUM_SW_SCRIPT = "bg.js"

def build(target, manifest_name):
    if os.path.isdir(target):
        shutil.rmtree(target)
    os.makedirs(os.path.join(target, "common"))
    os.makedirs(os.path.join(target, "icons"))
    for name in COMMON_FILES:
        shutil.copy2(os.path.join(COMMON, name), os.path.join(target, "common", name))
    with open(os.path.join(HERE, manifest_name), encoding="utf-8") as fh:
        manifest = json.load(fh)
    sw_path = manifest.get("background", {}).get("service_worker")
    if sw_path:
        # copy the SW script also under CHROMIUM_SW_SCRIPT and point the
        # manifest there (cache-busting name)
        src = os.path.join(target, sw_path)
        dst = os.path.join(target, "common", CHROMIUM_SW_SCRIPT)
        shutil.copy2(src, dst)
        manifest["background"]["service_worker"] = "common/" + CHROMIUM_SW_SCRIPT
    for name in ("16.png", "32.png", "48.png", "128.png"):
        shutil.copy2(os.path.join(ICONS, name), os.path.join(target, "icons", name))
    with open(os.path.join(target, "manifest.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def zip_dir(target, out_path, version):
    if os.path.exists(out_path):
        os.remove(out_path)
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        manifest = os.path.join(target, "manifest.json")
        zf.write(manifest, "manifest.json")
        for root, _dirs, files in os.walk(target):
            for name in sorted(files):
                full = os.path.join(root, name)
                rel = os.path.relpath(full, target).replace("\\", "/")
                if rel == "manifest.json":
                    continue
                zf.write(full, rel)
    # Pointer for human release notes; not part of the package.
    print("zip:", out_path, "version:", version)


def main():
    make_zips = "--no-zip" not in sys.argv
    with open(os.path.join(HERE, "manifest.chromium.json"), encoding="utf-8") as fh:
        version = json.load(fh)["version"]
    build(CHROMIUM, "manifest.chromium.json")
    build(FIREFOX, "manifest.firefox.json")
    if make_zips:
        os.makedirs(DIST, exist_ok=True)
        zip_dir(CHROMIUM, os.path.join(DIST, f"ciphervault-addon-{version}-chromium.zip"), version)
        zip_dir(FIREFOX, os.path.join(DIST, f"ciphervault-addon-{version}-firefox.zip"), version)
    print("version:", version)
    print("built  ->", CHROMIUM)
    print("built  ->", FIREFOX)


if __name__ == "__main__":
    main()
