# MITRE STIX Analysis（Splunk アプリ）

MITRE ATT&CK の STIX バンドルを Splunk の CSV lookup として取り込み、Dashboard Studio の
各画面で参照する Splunk アプリです。アプリ ID は `miter_stix_analysis` です。

現在の同梱データは **Enterprise ATT&CK v20.1 と v20.0** です。各画面上部の「ATT&CK の版」で切り替えて表示できます。
新しい版は `tools/download_stix.py` で MITRE から取得して追加できます（[tools/README.md](tools/README.md)）。

## 目的

ATT&CK は Web サイトや ATT&CK Navigator で参照できますが、SOC の現場では
「自社のログでどの Technique を検知できるか」「どの Tactic が手薄か」を
Splunk の中で、手元のデータと並べて考えたい場面が多くあります。

このアプリは次のことを目的にしています。

- **ATT&CK を Splunk の中で引けるようにする。** STIX の全オブジェクトを lookup にするので、
  `| inputlookup` や `| lookup` で ES の相関サーチや自作のサーチから参照できます。
- **検知に必要なログを逆引きする。** ATT&CK v18 以降、Technique と Data Component は
  Detection Strategy → Analytic を挟んだ 4 ホップの関係になり、Web サイトでは追いにくくなりました。
  この経路を 1 行に平坦化し、Technique から必要な Log Source まで一度にたどれるようにします。
- **カバレッジの検討材料を作る。** データソース × Tactic のマトリクスで、
  どのログを取れば多くの Technique を検知できるか、どの Tactic にどのログが効くかを把握します。
- **Group / Software / Campaign / Mitigation から関係をたどる。** 脅威アクター起点の調査や、
  緩和策の優先度付けに使います。
- **版の違いを確認する。** 複数の ATT&CK の版を取り込み、画面で切り替えて比べられます。

## 想定する利用者

- Splunk Enterprise / Enterprise Security を運用する SOC アナリスト、検知エンジニア
- ログ収集の優先順位を検討するセキュリティアーキテクト
- ATT&CK を使った説明資料やワークショップを準備する人

## 動作環境

- Splunk Enterprise 10.x（Dashboard Studio を使用。9.x 以前は未確認）
- 外部ネットワーク接続は不要です（lookup は同梱済み）
- lookup を作り直す場合のみ Python 3.9 以降（標準ライブラリのみ使用）

## クイックスタート

1. [Releases](../../releases) から `miter_stix_analysis-<バージョン>.tgz` をダウンロードします。
2. Splunk Web → Apps → Manage Apps → **Install app from file** でアップロードします。
3. 再起動を求められたら再起動します。
4. アプリ一覧の **MITRE STIX Analysis** を開くと Navigator が表示されます。

## 画面

| ナビゲーション | ビュー | 内容 |
| --- | --- | --- |
| Navigator | `attack_navigator` | ATT&CK Navigator と同じ Tactic × Technique のマトリクス。Platform / Sub-technique / セル指標で絞り込む |
| Data Source Matrix | `attack_ds_matrix` | データソース（Data Component / Log Source を切り替え）× Tactic の Technique 数。マトリクス表、積み上げ縦棒グラフ（合計上位 30 件）、Tactic 別・データソース別の円グラフ |
| ATT&CK Data | `attack_data` | オブジェクト種別ごとの 11 タブ（analytics / campaigns / datacomponents / detectionstrategies / groups / matrices / mitigations / relationships / software / tactics / techniques） |
| Relation → Technique | `attack_rel_technique` | Technique を起点に relationships を双方向にたどる |
| Relation → Mitigation | `attack_rel_mitigation` | Mitigation が緩和する Technique と、その Technique 経由で見える観点 |
| Relation → Data Component | `attack_rel_datacomponent` | 検知経路から Technique を割り出し、そこから Mitigation / Software 等をたどる |
| Relation → Software | `attack_rel_software` | Software が使う Technique と、それを使う Group / Campaign |
| Relation → Group | `attack_rel_group` | Group が使う Technique / Software |
| Relation → Campaign | `attack_rel_campaign` | Campaign で使われた Technique / Software と帰属 Group |
| Search | `search` | 標準のサーチ画面 |

Relation の 6 画面はいずれも対象を **複数選択**できる。各表の「対象 ID」列で、どの対象から
出た行かが分かる。種別によって構造上必ず空になるパネル（例: Mitigation と Software の
直接の関係）は出さず、代わりに `Technique 経由で関連する …` という 2 ホップのパネルを出している。

## 言語について

lookup のカラムと値は **MITRE 公式 STIX の英語原文のまま**にしている。日本語化が必要な場合は
`lookups/*.csv` 側で列を足す運用とする。画面側のテーブルは
`tools/build_dashboards.py` の `csv_fields()` が CSV のヘッダを読んでカラム順を決めるため、
CSV に列を足せばダッシュボードにもそのまま出る。

## データモデル上の注意

ATT&CK v18 以降、**Technique と Data Component の間に直接の関係オブジェクト（SRO）は存在しない**。
`Technique → Detection Strategy → Analytic → Data Component` の 4 ホップに分解されている。

このアプリでは次の 2 つの lookup でその経路を扱う。

- `attack_detection_path.csv` — 4 ホップを 1 行に平坦化したもの（4,209 行）。Log Source 名と channel まで含む
- `attack_relationships.csv` — `uses` / `mitigates` / `detects` / `subtechnique-of` / `attributed-to` / `revoked-by` の生データ（21,822 行）

そのため `Relation → Data Component` の画面には relationships 由来のパネルを置いていない。
検知経路から Technique を割り出し、そこを起点に Mitigation / Software / Group / Campaign を
たどる構成にしている。

## lookup 一覧

下の表は版なしのファイル（最新版の複製）です。画面は版付きの `attack_<種別>_v<版>.csv` を読みます。
取り込み済みの版の一覧は `attack_versions.csv` にあります。詳しくは [tools/README.md](tools/README.md) を参照してください。

| ファイル | 行数 | 主キー |
| --- | --- | --- |
| `attack_techniques.csv` | 706 | `technique_id` |
| `attack_navigator.csv` | 881 | `tactic_id` + `technique_id` |
| `attack_tactics.csv` | 15 | `tactic_id` |
| `attack_matrices.csv` | 15 | `matrix_id` + `tactic_order` |
| `attack_groups.csv` | 178 | `group_id` |
| `attack_software.csv` | 842 | `software_id` |
| `attack_mitigations.csv` | 44 | `mitigation_id` |
| `attack_campaigns.csv` | 57 | `campaign_id` |
| `attack_datacomponents.csv` | 106 | `dc_id` |
| `attack_dc_log_sources.csv` | 3,560 | `dc_id` + `log_source_name` |
| `attack_detectionstrategies.csv` | 706 | `det_id` |
| `attack_analytics.csv` | 1,773 | `an_id` |
| `attack_detection_path.csv` | 4,209 | `an_id` + `dc_id` |
| `attack_relationships.csv` | 21,822 | － |
| `attack_entities.csv` | 2,654 | `entity_type` + `entity_id` |
| `attack_about.csv` | 19 | `key` |

`metadata/default.meta` で `transforms` と `lookups` をグローバル公開しているため、ES の相関サーチなど
他アプリからも `| inputlookup attack_techniques.csv` で参照できる。

## デプロイ

### 方法 A: Web UI からインストール

[Releases](../../releases) の `miter_stix_analysis-<バージョン>.tgz` を使う（手元で作る場合は後述の「tgz を作り直す」）。

1. Splunk Web → Apps → Manage Apps → Install app from file
2. tgz を選んでアップロード
3. 再起動を求められたら再起動する（lookup とビューの反映に必要）

### 方法 B: サーバに直接配置

```sh
tar xzf dist/miter_stix_analysis-1.3.0.tgz -C "$SPLUNK_HOME/etc/apps/"
"$SPLUNK_HOME/bin/splunk" restart
```

### tgz を作り直す

```sh
COPYFILE_DISABLE=1 tar czf dist/miter_stix_analysis-1.3.0.tgz \
  --exclude='.DS_Store' --exclude='__pycache__' --exclude='dist' --exclude='stix' \
  --exclude='.git' --exclude='.gitignore' \
  -C .. miter_stix_analysis
```

## デプロイ後の動作確認

### 1. lookup の行数が一致するか

`tools/verify_lookups.spl` をサーチ画面に貼って実行する。`attack_about.csv` に記録された生成時の
行数と、実際に読める行数を 15 データセット分突き合わせる。**全行が `OK` になれば lookup の
配置と権限は正常**。`MISMATCH` の行が先頭に来るようソートしている。

`actual` が 0 のデータセットがある場合は lookup ファイルが読めていない。`metadata/default.meta` が
配置されているか、Settings → Lookups → Lookup table files で当該 CSV が見えるかを確認する。

### 2. 4 ホップの結合が成立しているか

```
| inputlookup attack_detection_path.csv
| search technique_id="T1190"
| stats dc(an_id) as analytics, dc(dc_id) as data_components, dc(log_source_name) as log_sources by technique_id, det_id
```

期待値は次の 1 行。これが出れば Technique → Detection Strategy → Analytic → Data Component の
経路が正しく平坦化されている。

| technique_id | det_id | analytics | data_components | log_sources |
| --- | --- | --- | --- | --- |
| T1190 | DET0080 | 7 | 6 | 12 |

### 3. relationships が双方向に引けるか

```
| inputlookup attack_relationships.csv
| search source_id="T1190" OR target_id="T1190"
| eval peer_type = if(source_id=="T1190", target_type, source_type)
| stats count by relationship_type, peer_type
| sort 0 - count
```

期待値は合計 86 行、内訳は `uses`/group が 47、`uses`/campaign が 22、`mitigates`/mitigation が 8、
`uses`/software が 8、`detects`/detectionstrategy が 1。

### 4. 画面の確認

| 画面 | 確認すること |
| --- | --- |
| ナビゲーション | Navigator / ATT&CK Data / Relation（6 項目のドロップダウン）/ Search が出て、既定が Navigator |
| アイコン | Apps 一覧とナビゲーションバーに格子模様のアイコンとロゴが出る（`static/appIcon*.png`、`static/appLogo*.png`） |
| Navigator | マトリクスの列が `01 Reconnaissance` から `15 Impact` まで 15 列。Platform を `Linux` にすると列と行が減る |
| ATT&CK Data | タブが 11 枚。`techniques` タブで行数が 706、フィルタに `T1190` を入れると 1 行、`platforms="Linux"` で 13 行、`Linux AND "Valid Accounts"` で 22 行 |
| Relation → Technique | 既定で T1190。対象メニューで T1210 を追加選択すると各表に「対象 ID」が 2 種類出る |
| Relation → Data Component | 既定で DC0038。検知経路から判明する Technique が 104 行 |
| Data Source Matrix | 既定（Data Component）で 98 行、先頭が `DC0032 Process Creation`（合計 581）。Log Source に切り替えると 269 行で、先頭が `WinEventLog:Sysmon`（534） |

### フィルタとカラム順について

`inputlookup` の結果には `_raw` が無いため、`| search T1190` のようにフィールド名を書かない
検索は 1 件もヒットしない。ATT&CK Data の各タブでは全カラムを連結した `_raw` を
`| eval` で組み立ててから `| search $q$` に渡しているので、素の単語・`field="値"`・`AND` の
組み合わせがすべて使える。

カラムの並びは Dashboard Studio の表がアルファベット順にしてしまうため、
各クエリの末尾で `| table` に lookup のヘッダ順を明示して固定している。
ヘッダ順は `tools/build_dashboards.py` の `csv_fields()` が `lookups/*.csv` から
読み取るので、lookup のカラムを増やせば画面側も自動で追従する。

### つまずきやすい点

- **新規アプリの初回反映には splunkd の再起動が必要**。`etc/apps` に置いただけでは名前空間が
  登録されず、サーチは `404 Action forbidden` になる。無停止で反映するには
  `POST /services/apps/local/_reload` を叩くしかないが、`| rest` コマンドは `_reload` を明示的に
  拒否する（`The '_reload' action can't be used with the 'rest' search command`）。
  `splunk _internal call` には Splunk のログインが必要で、これは OS/SSH のログインとは別物。
  つまり **Splunk の認証情報がなければ再起動が唯一の手段**。
- **MCP の `splunk_run_query` で一覧系パネルを検証するときは `| head` を付ける**。
  返す行が概ね 1,000 行を超えると結果が空で返るため、`attack_analytics`(1773) や
  `attack_relationships`(21822) の一覧クエリがそのままでは空に見える。画面側の表示は正常。
- **`Relation → Technique` の「関連する Technique」が空になることがある**。
  technique 同士の関係は `subtechnique-of`(481) と `revoked-by`(149) だけなので、
  sub-technique を持たない T1190 などでは行が出ない。T1505 を選べば 4 件の sub-technique が出る。
- **以前に同名のアプリを入れていた場合**、`local/` 配下の設定が `default/` を上書きする。
  ビューを UI で編集したあとに `tools/build_dashboards.py` を再実行しても画面が変わらないのは
  これが原因。`$SPLUNK_HOME/etc/apps/miter_stix_analysis/local/data/ui/views/` を確認する。
- **Dashboard Studio がスキーマエラーを出す場合**、`layout` にフラットな `"type"` が
  入っていないか確認する。Splunk 10.x は `tabs` + `layoutDefinitions` 形式のみを受け付ける。
- **lookup が他アプリから見えない場合**、`metadata/default.meta` の `export = system` が
  効いているかを Settings → Lookups → Lookup definitions の Sharing 列で確認する。

## データの更新

```sh
# 取得できる版を確認する
python3 tools/download_stix.py --list

# 最新版を取得して lookup を作る（版付きのファイルが追加される）
python3 tools/download_stix.py --latest --build

# ダッシュボード定義を作り直す（UI で編集した内容は上書きされる）
python3 tools/build_dashboards.py
```

手順の詳細、出力されるファイル、版の削除方法は [tools/README.md](tools/README.md) にまとめています。

`tools/build_dashboards.py` は書き出し前に JSON を自己チェックする。Splunk 10.x のスキーマバリデータは
フラットな `"layout": {"type": ...}` を受け付けないため、タブが 1 枚のビューでも
`tabs` + `layoutDefinitions` 形式で出力している。

## v20.1 での変更点

Tactic が 14 個から 15 個に増えている。`Defense Evasion` が `Stealth`（TA0005）に改名され、
`Defense Impairment`（TA0112）が新設された。Navigator のマトリクスはマトリクスオブジェクトの
`tactic_refs` の順序をそのまま使うため、この変更は自動的に反映される。

## ディレクトリ構成

```
miter_stix_analysis/
├── default/            app.conf、transforms.conf、ナビゲーション、ダッシュボード（views）
├── lookups/            STIX から生成した CSV lookup（版ごとに 16 ファイル＋最新版の複製＋版の一覧）
├── metadata/           権限と公開範囲（lookup はグローバル公開）
├── static/             アプリのアイコンとロゴ
├── stix/               ダウンロードした STIX バンドル（Git・tgz には含めない）
└── tools/              STIX の取得、lookup・ダッシュボード・アイコンの生成スクリプトと確認用 SPL
```

## 出典と利用条件

`lookups/` のデータは MITRE ATT&CK® の STIX データ
（[mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data)）から生成しています。
ATT&CK の利用条件は [Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) を参照してください。

© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.

MITRE ATT&CK および ATT&CK は The MITRE Corporation の登録商標です。
このアプリは MITRE の公式製品ではなく、Splunk / Cisco の公式アプリでもありません。
