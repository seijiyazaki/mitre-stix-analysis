# STIX のダウンロードと版の追加

MITRE が公開している Enterprise ATT&CK の STIX バンドルを取得し、このアプリに
新しい版（または過去の版）を取り込むための手順です。

## 目的

ATT&CK はおおむね年 2 回、メジャー版とマイナー版が更新されます。版が上がると
Technique の追加・改名・廃止、Tactic の新設（例: v20 の `Defense Impairment`）、
検知経路の見直しが入ります。

このアプリでは複数の版を同時に取り込み、各画面の「ATT&CK の版」で切り替えて表示できます。
次のような使い方を想定しています。

- 新しい版が出たら取り込み、自社の検知ルールやログ収集計画への影響を確認する
- 前の版と並べて、Technique 数やデータソースごとのカバレッジがどう変わったかを見る
- 顧客や社内で古い版を前提にした資料がある場合に、その版の内容を確認する

## 必要なもの

- Python 3.9 以降（標準ライブラリのみ。追加のパッケージは不要）
- `raw.githubusercontent.com` へのインターネット接続（ダウンロード時のみ）

## スクリプト

| ファイル | 役割 |
| --- | --- |
| `download_stix.py` | MITRE の [attack-stix-data](https://github.com/mitre-attack/attack-stix-data) から STIX バンドルを取得する。`--build` で lookup の作成まで続けて行う |
| `build_lookups.py` | STIX バンドルを版付きの CSV lookup に変換する |
| `build_dashboards.py` | ダッシュボード定義（`default/data/ui/views/*.xml`）を作る |

## 使い方

### 1. 取得できる版を確認する

```sh
python3 tools/download_stix.py --list
```

```
Enterprise ATT&CK の版（新しい順。* はこのアプリで扱える版）
  * 20.1   2026-11-05
  * 20.0   2026-10-13
  * 19.2   2026-08-05
  ...
    17.1   2025-05-06
```

版の一覧は MITRE の `index.json` から取っているので、新しい版が公開されると自動で一覧に出ます。
`*` が付いていない v17 以前は扱えません。このアプリは v18 で導入された
Detection Strategy / Analytic を前提にしているためです。

### 2. 取得して lookup を作る

```sh
# 最新版
python3 tools/download_stix.py --latest --build

# 版を指定（複数可）
python3 tools/download_stix.py --version 20.0 19.2 --build
```

- STIX は `stix/enterprise-attack-<版>.json` に保存します（1 版あたり約 50 MB）。
  `build_lookups.py --stix` で別の場所のファイルを使う場合も、版はバンドルの中の情報から自動で判定します。
  同じ版のファイルが既にあれば、ダウンロードせずにそれを使います。
- `--build` を付けると、取得した版ごとに `build_lookups.py` を実行します。
  付けなかった場合は、あとで `python3 tools/build_lookups.py --stix stix/enterprise-attack-<版>.json` を実行してください。
- `stix/` は Git でも tgz でも除外しています。lookup を作ったあとは消しても構いません。

### 3. ダッシュボードを作り直す

```sh
python3 tools/build_dashboards.py
```

版の選択メニューの既定値（最新版）はこの時点の `lookups/attack_versions.csv` で決まります。
新しい版を取り込んだら必ず実行してください。

### 4. Splunk に入れ直す

`default/app.conf` の `version` を上げてから tgz を作り、Splunk に入れ直します
（手順はリポジトリ直下の README の「デプロイ」を参照）。

## 出力されるファイル

`build_lookups.py` は版ごとに次のファイルを `lookups/` に出力します。

| ファイル | 内容 |
| --- | --- |
| `attack_<種別>_v<版>.csv` | 版付きの lookup（例: `attack_techniques_v20.1.csv`）。16 種別 |
| `attack_<種別>.csv` | 版なしの lookup。取り込み済みの版のうち**最も新しい版**の複製 |
| `attack_versions.csv` | 取り込み済みの版の一覧。画面の「ATT&CK の版」メニューはこれを読む |

画面は選んだ版の `attack_<種別>_v<版>.csv` を読みます。版なしのファイルは、
ES の相関サーチなど他アプリから `| inputlookup attack_techniques.csv` で
常に最新版を引けるように残しています。

古い版をあとから取り込んでも、版なしのファイルは最新版のままです。

## 版を削除する

1. `lookups/attack_*_v<版>.csv` を削除する
2. `lookups/attack_versions.csv` から該当する行を削除する
3. `python3 tools/build_dashboards.py` を実行する

最新版を削除した場合は、残った中で最も新しい版を `build_lookups.py` でもう一度作ってください。
版なしのファイルがその版に置き換わります。
`stix/` を消していた場合は `python3 tools/download_stix.py --version <その版> --build` で取り直しと作成を一度に行えます。

## つまずきやすい点

- **アプリが大きくなる。** lookup は 1 版あたり約 10 MB（tgz では約 2 MB）です。
  必要な版だけを取り込んでください。
- **画面に版の選択メニューが出ない。** Splunk Web でダッシュボードを編集・保存すると、
  その画面は `local/` の保存版が優先され、`default/` の更新が反映されません。
  `$SPLUNK_HOME/etc/apps/miter_stix_analysis/local/data/ui/views/` を確認してください。
- **ダウンロードが失敗する。** プロキシ環境では `HTTPS_PROXY` 環境変数を設定してから実行してください
  （Python の `urllib` がこれを読みます）。
