#!/usr/bin/env python3
"""MITRE の attack-stix-data から Enterprise ATT&CK の STIX バンドルを取得する。

    python3 tools/download_stix.py --list               # 取得できる版の一覧
    python3 tools/download_stix.py --latest             # 最新版を取得
    python3 tools/download_stix.py --version 20.0 19.2  # 版を指定して取得
    python3 tools/download_stix.py --latest --build     # 取得して lookup まで作る

取得先は stix/enterprise-attack-<版>.json。既に同名のファイルがあれば取得しない。
--build を付けると、取得した版ごとに tools/build_lookups.py を実行する。
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.request

INDEX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
COLLECTION = "Enterprise ATT&CK"
# Detection Strategy / Analytic を前提にしているため、それが入った v18 より前は扱わない。
MIN_MAJOR = 18

APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STIX_DIR = os.path.join(APP_ROOT, "stix")


def fetch(url):
    with urllib.request.urlopen(url) as resp:
        return resp.read()


def list_versions():
    """index.json の版一覧を新しい順で返す。[(version, url, modified), ...]"""
    index = json.loads(fetch(INDEX_URL))
    for collection in index["collections"]:
        if collection["name"] == COLLECTION:
            return [(v["version"], v["url"], v.get("modified", "")) for v in collection["versions"]]
    sys.exit(f"index.json に {COLLECTION} がありません")


def supported(version):
    return int(version.split(".")[0]) >= MIN_MAJOR


def download(version, url):
    os.makedirs(STIX_DIR, exist_ok=True)
    path = os.path.join(STIX_DIR, f"enterprise-attack-{version}.json")
    if os.path.exists(path):
        print(f"  {version}: 取得済み ({path})")
        return path
    print(f"  {version}: {url}")
    body = fetch(url)
    bundle = json.loads(body)  # 壊れたファイルを保存しないための確認
    if bundle.get("type") != "bundle":
        sys.exit(f"{url} は STIX バンドルではありません")
    tmp = path + ".part"
    with open(tmp, "wb") as fh:
        fh.write(body)
    os.rename(tmp, path)
    print(f"  {version}: 保存しました ({len(bundle['objects'])} オブジェクト, {len(body) // 1024 // 1024} MB)")
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--list", action="store_true", help="取得できる版の一覧を表示する")
    parser.add_argument("--latest", action="store_true", help="最新版を取得する")
    parser.add_argument("--version", nargs="+", default=[], help="取得する版（例: 20.0 19.2）")
    parser.add_argument("--build", action="store_true", help="取得後に lookup を作る")
    args = parser.parse_args()

    versions = list_versions()
    if args.list or not (args.latest or args.version):
        print(f"{COLLECTION} の版（新しい順。* はこのアプリで扱える版）")
        for version, _, modified in versions:
            mark = "*" if supported(version) else " "
            print(f"  {mark} {version:6s} {modified[:10]}")
        return

    by_version = {v: url for v, url, _ in versions}
    wanted = list(args.version)
    if args.latest:
        wanted.insert(0, versions[0][0])
    for version in wanted:
        if version not in by_version:
            sys.exit(f"版 {version} は index.json にありません。--list で確認してください")
        if not supported(version):
            sys.exit(f"版 {version} は扱えません（v{MIN_MAJOR}.0 以降が対象）")

    print("取得")
    paths = [download(v, by_version[v]) for v in dict.fromkeys(wanted)]
    if args.build:
        build = os.path.join(APP_ROOT, "tools", "build_lookups.py")
        for path in paths:
            print(f"lookup を作成: {os.path.basename(path)}")
            subprocess.run([sys.executable, build, "--stix", path], check=True)


if __name__ == "__main__":
    main()
