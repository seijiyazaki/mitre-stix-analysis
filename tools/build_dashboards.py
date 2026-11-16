#!/usr/bin/env python3
"""Dashboard Studio のビュー XML を生成する。

Splunk 10.x のスキーマバリデータはフラットな "layout": {"type": ...} を受け付けないため、
タブが 1 枚だけのダッシュボードでも tabs + layoutDefinitions 形式で出力する。

    python3 tools/build_dashboards.py
"""
from __future__ import annotations

import csv
import json
import os
from xml.sax.saxutils import escape

APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VIEW_DIR = os.path.join(APP_ROOT, "default", "data", "ui", "views")
LOOKUP_DIR = os.path.join(APP_ROOT, "lookups")

HIDDEN_ELEMENTS = {
    "hideEdit": False,
    "hideOpenInSearch": False,
    "hideExport": False,
}


# ---------------------------------------------------------------------------
# lookup のカラム定義
# ---------------------------------------------------------------------------
_FIELD_CACHE = {}


def csv_fields(csv_name):
    """lookup CSV のヘッダ順を返す。テーブルのカラム順はこの順に固定する。"""
    if csv_name not in _FIELD_CACHE:
        with open(os.path.join(LOOKUP_DIR, csv_name), encoding="utf-8") as fh:
            _FIELD_CACHE[csv_name] = next(csv.reader(fh))
    return _FIELD_CACHE[csv_name]


def raw_eval(fields):
    """`search` コマンドに素の単語を渡せるよう _raw を組み立てる。

    inputlookup の結果には _raw が無いため `| search T1190` のような
    フィールド名を書かない検索が 1 件もヒットしない。全カラムを連結した
    _raw を作っておくと、素の単語と field=value の両方が使えるようになる。
    """
    parts = '." ".'.join(f'coalesce({f},"")' for f in fields)
    return f"| eval _raw = {parts}"


def lookup_query(csv_name, sort_field, extra=""):
    fields = csv_fields(csv_name)
    lines = [
        f"| inputlookup {csv_name}",
        raw_eval(fields),
        "| search $q$",
        f"| sort 0 {sort_field}",
        "| table " + ", ".join(fields),
    ]
    if extra:
        lines.append(extra)
    return "\n".join(lines)


def lookup_count_query(csv_name):
    return "\n".join(
        [
            f"| inputlookup {csv_name}",
            raw_eval(csv_fields(csv_name)),
            "| search $q$",
            "| stats count as rows",
        ]
    )


def entity_default(entity_type, preferred):
    """既定で選ばせる ID。想定の ID が無ければその種別の先頭を使う。"""
    ids = [
        row["entity_id"]
        for row in csv.DictReader(
            open(os.path.join(LOOKUP_DIR, "attack_entities.csv"), encoding="utf-8")
        )
        if row["entity_type"] == entity_type
    ]
    return preferred if preferred in ids else (ids[0] if ids else preferred)


# ---------------------------------------------------------------------------
# 部品
# ---------------------------------------------------------------------------
def ds(query, name):
    return {"type": "ds.search", "options": {"query": query}, "name": name}


def table(ds_id, title, description="", count=20):
    viz = {
        "type": "splunk.table",
        "dataSources": {"primary": ds_id},
        "title": title,
        "options": {"count": count},
    }
    if description:
        viz["description"] = description
    return viz


def markdown(text):
    return {"type": "splunk.markdown", "options": {"markdown": text}}


def single(ds_id, title):
    return {
        "type": "splunk.singlevalue",
        "dataSources": {"primary": ds_id},
        "title": title,
        "options": {"numberPrecision": 0},
    }


def column(ds_id, title, x_title, y_title):
    return {
        "type": "splunk.column",
        "dataSources": {"primary": ds_id},
        "title": title,
        "options": {
            "xAxisTitleText": x_title,
            "yAxisTitleText": y_title,
            "legendDisplay": "right",
        },
    }


def pie(ds_id, title):
    return {
        "type": "splunk.pie",
        "dataSources": {"primary": ds_id},
        "title": title,
        "options": {"showDonutHole": False, "labelDisplay": "valuesAndPercentage"},
    }


def dynamic_input(
    ds_id,
    token,
    title,
    label_field,
    value_field,
    default=None,
    statics=None,
    multiple=False,
):
    """検索結果でメニューを作る入力。label / value は context で写像する。

    multiple=True のときは input.multiselect になる。複数選択時のトークンは
    カンマ区切りで展開されるため、SPL 側は `field IN ($token$)` で受ける。
    """
    context = {
        "formattedConfig": {"number": {"prefix": ""}},
        "label": f'>primary | seriesByName("{label_field}") | renameSeries("label") | formatByType(formattedConfig)',
        "value": f'>primary | seriesByName("{value_field}") | renameSeries("value") | formatByType(formattedConfig)',
    }
    options = {"token": token}
    if statics:
        context["statics"] = [[s[0] for s in statics], [s[1] for s in statics]]
        context["formattedStatics"] = ">statics | formatByType(formattedConfig)"
        options["items"] = ">frame(label, value) | prepend(formattedStatics) | objects()"
    else:
        options["items"] = ">frame(label, value) | objects()"
        if not multiple:
            options["selectFirstSearchResult"] = True
    if default is not None:
        options["defaultValue"] = default
    return {
        "type": "input.multiselect" if multiple else "input.dropdown",
        "title": title,
        "dataSources": {"primary": ds_id},
        "options": options,
        "context": context,
    }


def static_dropdown(token, title, items, default):
    return {
        "type": "input.dropdown",
        "title": title,
        "options": {
            "token": token,
            "defaultValue": default,
            "items": [{"label": lbl, "value": val} for lbl, val in items],
        },
    }


def text_input(token, title, default):
    return {
        "type": "input.text",
        "title": title,
        "options": {"token": token, "defaultValue": default},
    }


def grid(rows, width=1200):
    """[[(viz_id, w, h), ...], ...] を grid の structure に落とす。"""
    structure = []
    y = 0
    for row in rows:
        x = 0
        height = max(h for _, _, h in row)
        for viz_id, w, h in row:
            structure.append(
                {"item": viz_id, "type": "block", "position": {"x": x, "y": y, "w": w, "h": h}}
            )
            x += w
        y += height
    return structure


def write_view(filename, label, description, definition):
    os.makedirs(VIEW_DIR, exist_ok=True)
    body = json.dumps(definition, ensure_ascii=False, indent=4)
    xml = (
        '<dashboard version="2">\n'
        f"  <label>{escape(label)}</label>\n"
        f"  <description>{escape(description)}</description>\n"
        "  <definition><![CDATA[\n"
        f"{body}\n"
        "  ]]></definition>\n"
        '  <meta type="hiddenElements"><![CDATA[\n'
        f"{json.dumps(HIDDEN_ELEMENTS, indent=4)}\n"
        "  ]]></meta>\n"
        "</dashboard>\n"
    )
    path = os.path.join(VIEW_DIR, filename)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(xml)
    json.loads(body)  # 壊れた JSON を書き出さないための自己チェック
    print(f"  {filename:30s} {len(body):7d} bytes  viz={len(definition['visualizations'])}")


# ---------------------------------------------------------------------------
# 1. Navigator
# ---------------------------------------------------------------------------
NAV_FILTER = '| search is_sub_technique="$subtech$" platforms="*$platform$*"'

MATRIX_QUERY = f"""| inputlookup attack_navigator.csv
{NAV_FILTER}
| eval metric = $metric$
| sort 0 tactic_order, technique_id
| streamstats count as row by tactic_name
| eval col = printf("%02d", tactic_order)." ".tactic_name
| eval cell = technique_id." ".technique_name." [".metric."]"
| xyseries row col cell
| fields - row"""

TACTIC_COUNT_QUERY = f"""| inputlookup attack_navigator.csv
{NAV_FILTER}
| eval metric = $metric$
| stats count as techniques, sum(metric) as metric_total by tactic_order, tactic_name
| sort 0 tactic_order
| eval tactic = printf("%02d", tactic_order)." ".tactic_name
| table tactic, techniques, metric_total
| rename techniques as "Technique 数", metric_total as "$metric$ 合計" """

COVERAGE_QUERY = f"""| inputlookup attack_navigator.csv
{NAV_FILTER}
| eval metric = $metric$
| stats values(tactic_name) as tactics, max(metric) as metric by technique_id, technique_name, platforms
| eval tactics = mvjoin(tactics, ", ")
| sort 0 - metric, technique_id
| head 100
| table technique_id, technique_name, tactics, platforms, metric
| rename technique_id as "Technique ID", technique_name as "Technique", tactics as "Tactic", platforms as "Platform", metric as "$metric$" """

NAV_DETAIL_FIELDS = [
    "technique_id",
    "name",
    "tactics",
    "platforms",
    "detection_strategies",
    "analytics",
    "data_components",
    "mitigations",
    "groups",
    "software",
    "campaigns",
]

NAV_DETAIL_QUERY = f"""| inputlookup attack_techniques.csv
| search is_sub_technique="$subtech$" platforms="*$platform$*"
| sort 0 technique_id
| table {", ".join(NAV_DETAIL_FIELDS)}
| rename technique_id as "Technique ID", name as "Technique", tactics as "Tactic", platforms as "Platform", detection_strategies as "DET 数", analytics as "AN 数", data_components as "Data Component", mitigations as "Mitigation 数", groups as "Group 数", software as "Software 数", campaigns as "Campaign 数" """


def build_navigator():
    definition = {
        "title": "Navigator",
        "description": "ATT&CK Navigator と同じ Tactic × Technique のマトリクス表示",
        "inputs": {
            "input_platform": dynamic_input(
                "ds_platforms",
                "platform",
                "Platform",
                "label",
                "value",
                default="*",
                statics=[("すべて", "*")],
            ),
            "input_subtech": static_dropdown(
                "subtech",
                "Sub-technique",
                [("含める", "*"), ("親 Technique のみ", "false"), ("Sub-technique のみ", "true")],
                "*",
            ),
            "input_metric": static_dropdown(
                "metric",
                "セルに出す指標",
                [
                    ("Analytic 数", "analytics"),
                    ("Detection Strategy 数", "detection_strategies"),
                    ("Data Component 数", "data_component_count"),
                    ("Mitigation 数", "mitigations"),
                    ("Group 数", "groups"),
                    ("Software 数", "software"),
                ],
                "analytics",
            ),
        },
        "defaults": {},
        "visualizations": {
            "viz_nav_header": markdown(
                "## ATT&CK Navigator\n"
                "列が Tactic、セルが Technique です。角括弧の数値は上の「セルに出す指標」で選んだ件数です。"
                "Platform と Sub-technique の絞り込みはこのページの全パネルに効きます。"
                            ),
            "viz_nav_version": single("ds_version", "ATT&CK バージョン"),
            "viz_nav_tech_count": single("ds_tech_count", "Technique 数（絞り込み後）"),
            "viz_nav_tactic_count": single("ds_tactic_count", "Tactic 数"),
            "viz_nav_matrix": table(
                "ds_matrix",
                "Tactic × Technique マトリクス",
                "横スクロールで全 Tactic を参照できます",
                count=100,
            ),
            "viz_nav_counts": column(
                "ds_tactic_counts", "Tactic 別の Technique 数と指標合計", "Tactic", "件数"
            ),
            "viz_nav_coverage": table(
                "ds_coverage", "選択した指標の上位 Technique（上位 100 件）", count=25
            ),
            "viz_nav_detail": table("ds_nav_detail", "Technique 一覧（全指標）", count=25),
        },
        "dataSources": {
            "ds_platforms": ds(
                "| inputlookup attack_navigator.csv\n"
                '| eval value = split(platforms, ", ")\n'
                "| mvexpand value\n"
                "| stats count by value\n"
                "| eval label = value\n"
                "| sort 0 label\n"
                "| fields label, value",
                "Platform 一覧",
            ),
            "ds_version": ds(
                '| inputlookup attack_about.csv\n| search key="attack_version"\n| fields value',
                "ATT&CK バージョン",
            ),
            "ds_tech_count": ds(
                f"| inputlookup attack_navigator.csv\n{NAV_FILTER}\n"
                "| stats dc(technique_id) as techniques",
                "Technique 数",
            ),
            "ds_tactic_count": ds(
                f"| inputlookup attack_navigator.csv\n{NAV_FILTER}\n"
                "| stats dc(tactic_name) as tactics",
                "Tactic 数",
            ),
            "ds_matrix": ds(MATRIX_QUERY, "マトリクス"),
            "ds_tactic_counts": ds(TACTIC_COUNT_QUERY, "Tactic 別件数"),
            "ds_coverage": ds(COVERAGE_QUERY, "指標上位"),
            "ds_nav_detail": ds(NAV_DETAIL_QUERY, "Technique 一覧"),
        },
        "layout": {
            "globalInputs": ["input_platform", "input_subtech", "input_metric"],
            "tabs": {
                "items": [{"label": "Navigator", "layoutId": "layout_navigator"}],
                "options": {"barPosition": "top", "showTabBar": False},
            },
            "layoutDefinitions": {
                "layout_navigator": {
                    "type": "grid",
                    "options": {"display": "auto"},
                    "structure": grid(
                        [
                            [("viz_nav_header", 1200, 90)],
                            [
                                ("viz_nav_version", 400, 120),
                                ("viz_nav_tech_count", 400, 120),
                                ("viz_nav_tactic_count", 400, 120),
                            ],
                            [("viz_nav_matrix", 1200, 760)],
                            [("viz_nav_counts", 1200, 360)],
                            [("viz_nav_coverage", 600, 480), ("viz_nav_detail", 600, 480)],
                        ]
                    ),
                }
            },
        },
    }
    write_view("attack_navigator.xml", "Navigator", "ATT&CK Navigator 相当のマトリクス表示", definition)


# ---------------------------------------------------------------------------
# 2. ATT&CK Data（11 タブ）
# ---------------------------------------------------------------------------
DATASETS = [
    ("analytics", "analytics", "attack_analytics.csv", "an_id"),
    ("campaigns", "campaigns", "attack_campaigns.csv", "campaign_id"),
    ("datacomponents", "datacomponents", "attack_datacomponents.csv", "dc_id"),
    ("detectionstrategies", "detectionstrategies", "attack_detectionstrategies.csv", "det_id"),
    ("groups", "groups", "attack_groups.csv", "group_id"),
    ("matrices", "matrices", "attack_matrices.csv", "tactic_order"),
    ("mitigations", "mitigations", "attack_mitigations.csv", "mitigation_id"),
    ("relationships", "relationships", "attack_relationships.csv", "source_id"),
    ("software", "software", "attack_software.csv", "software_id"),
    ("tactics", "tactics", "attack_tactics.csv", "tactic_order"),
    ("techniques", "techniques", "attack_techniques.csv", "technique_id"),
]


def build_attack_data():
    visualizations = {
        "viz_data_header": markdown(
            "## ATT&CK Data\n"
            "STIX バンドルから生成した lookup をオブジェクト種別ごとのタブで参照します。"
            "カラムの並びは lookup の定義順（ID → 名称 → 件数 → URL → 説明）に固定しています。\n\n"
            "**フィルタの書き方**: 全カラムを連結した `_raw` を内部で作っているため、"
            "`T1190` のような素の単語、`platforms=\"Linux\"` のような field=value、"
            "`Linux AND \"Valid Accounts\"` のような組み合わせがそのまま使えます。"
            "全件表示に戻すときは `*` を入れてください（空欄はエラーになります）。"
        )
    }
    data_sources = {}
    tabs = []
    layout_definitions = {}

    for key, label, csv_name, sort_field in DATASETS:
        ds_table = f"ds_{key}"
        ds_count = f"ds_{key}_count"
        viz_table = f"viz_{key}"
        viz_count = f"viz_{key}_count"
        data_sources[ds_table] = ds(lookup_query(csv_name, sort_field), f"{label} 一覧")
        data_sources[ds_count] = ds(lookup_count_query(csv_name), f"{label} 件数")
        visualizations[viz_count] = single(ds_count, f"{label} 行数（フィルタ適用後）")
        visualizations[viz_table] = table(ds_table, f"{label}（{csv_name}）", count=50)
        layout_id = f"layout_{key}"
        tabs.append({"label": label, "layoutId": layout_id})
        layout_definitions[layout_id] = {
            "type": "grid",
            "options": {"display": "auto"},
            "structure": grid(
                [
                    [("viz_data_header", 1200, 150)],
                    [(viz_count, 1200, 120)],
                    [(viz_table, 1200, 820)],
                ]
            ),
        }

    definition = {
        "title": "ATT&CK Data",
        "description": "STIX 由来の lookup をオブジェクト種別ごとのタブで参照する",
        "inputs": {"input_q": text_input("q", "フィルタ（search 構文）", "*")},
        "defaults": {},
        "visualizations": visualizations,
        "dataSources": data_sources,
        "layout": {
            "globalInputs": ["input_q"],
            "tabs": {"items": tabs, "options": {"barPosition": "top", "showTabBar": True}},
            "layoutDefinitions": layout_definitions,
        },
    }
    write_view("attack_data.xml", "ATT&CK Data", "オブジェクト種別ごとのタブ表示", definition)


# ---------------------------------------------------------------------------
# 3. Relation（種別ごとに 1 ダッシュボード）
# ---------------------------------------------------------------------------
# 選択したエンティティを起点に relationships を双方向でたどる共通の前処理。
# 複数選択に対応するため、等価比較ではなく IN で受ける。
PEER_BASE = """| inputlookup attack_relationships.csv
| search source_id IN ($entity$) OR target_id IN ($entity$)
| eval is_source = if(source_id IN ($entity$), 1, 0)
| eval self_id = if(is_source==1, source_id, target_id)
| eval self_name = if(is_source==1, source_name, target_name)
| eval direction = if(is_source==1, "この対象 → 相手", "相手 → この対象")
| eval peer_id = if(is_source==1, target_id, source_id)
| eval peer_name = if(is_source==1, target_name, source_name)
| eval peer_type = if(is_source==1, target_type, source_type)"""

REL_SUMMARY_QUERY = f"""{PEER_BASE}
| chart count over peer_type by relationship_type"""

REL_TECH_QUERY = f"""{PEER_BASE}
| where peer_type == "technique"
| lookup attack_techniques technique_id AS peer_id OUTPUT tactics, platforms, analytics, detection_strategies, data_component_count
| stats values(relationship_type) as relationship, values(direction) as direction, values(description) as mapping_description by self_id, peer_id, peer_name, tactics, platforms, analytics, detection_strategies, data_component_count
| eval relationship = mvjoin(relationship, ", "), direction = mvjoin(direction, ", "), mapping_description = mvjoin(mapping_description, " / ")
| sort 0 self_id, peer_id
| table self_id, peer_id, peer_name, tactics, platforms, analytics, detection_strategies, data_component_count, relationship, direction, mapping_description
| rename self_id AS "対象 ID", peer_id AS "Technique ID", peer_name AS "Technique", tactics AS "Tactic", platforms AS "Platform", analytics AS "AN 数", detection_strategies AS "DET 数", data_component_count AS "DC 数", relationship AS "関係", direction AS "向き", mapping_description AS "関係の説明" """

REL_ACTOR_QUERY = f"""{PEER_BASE}
| where peer_type IN ("software", "group", "campaign")
| stats values(relationship_type) as relationship, values(direction) as direction by self_id, peer_type, peer_id, peer_name
| eval relationship = mvjoin(relationship, ", "), direction = mvjoin(direction, ", ")
| sort 0 self_id, peer_type, peer_id
| table self_id, peer_type, peer_id, peer_name, relationship, direction
| rename self_id AS "対象 ID", peer_type AS "種別", peer_id AS "ID", peer_name AS "名称", relationship AS "関係", direction AS "向き" """

REL_MITIGATION_QUERY = f"""{PEER_BASE}
| where peer_type == "mitigation"
| lookup attack_mitigations mitigation_id AS peer_id OUTPUT techniques AS covered_techniques, description AS mitigation_description
| stats values(description) as mapping_description by self_id, peer_id, peer_name, covered_techniques, mitigation_description
| eval mapping_description = mvjoin(mapping_description, " / ")
| sort 0 self_id, peer_id
| table self_id, peer_id, peer_name, covered_techniques, mapping_description, mitigation_description
| rename self_id AS "対象 ID", peer_id AS "Mitigation ID", peer_name AS "Mitigation", covered_techniques AS "対象 Technique 数", mapping_description AS "この関係の説明", mitigation_description AS "Mitigation の説明" """

# Software や Group を選んだときも、その Technique 経由で検知経路までたどる。
REL_DETECT_QUERY = """| inputlookup attack_detection_path.csv
| search technique_id IN ($entity$) OR dc_id IN ($entity$) OR det_id IN ($entity$) OR an_id IN ($entity$) OR [
    | inputlookup attack_relationships.csv
    | search source_id IN ($entity$) OR target_id IN ($entity$)
    | eval technique_id = if(source_id IN ($entity$), target_id, source_id)
    | eval peer_type = if(source_id IN ($entity$), target_type, source_type)
    | where peer_type == "technique"
    | append [| makeresults count=1 | eval technique_id="__none__"]
    | dedup technique_id
    | fields technique_id ]
| sort 0 technique_id, an_id, dc_id
| table technique_id, technique_name, det_id, an_id, platforms, dc_id, dc_name, log_source_name, channel
| rename technique_id AS "Technique ID", technique_name AS "Technique", det_id AS "DET", an_id AS "AN", platforms AS "Platform", dc_id AS "DC", dc_name AS "Data Component", log_source_name AS "Log Source", channel AS "Channel（要求される内容）" """

REL_RAW_QUERY = f"""{PEER_BASE}
| sort 0 self_id, peer_type, relationship_type, peer_id
| table self_id, relationship_type, direction, peer_type, peer_id, peer_name, description
| rename self_id AS "対象 ID", relationship_type AS "関係", direction AS "向き", peer_type AS "相手の種別", peer_id AS "相手 ID", peer_name AS "相手の名称", description AS "説明" """

# 選択した対象から到達できる Technique の集合。relationships 経由（Group/Software/
# Campaign/Mitigation）、対象そのものが Technique の場合、検知経路経由（Data Component /
# DET / AN）の 3 系統を合わせる。Mitigation や Software を選んだときに
# 「Technique 経由で見える観点」を出すための土台。
TECH_SCOPE_SUB = """[
    | inputlookup attack_relationships.csv
    | search source_id IN ($entity$) OR target_id IN ($entity$)
    | eval tech = if(source_id IN ($entity$), target_id, source_id)
    | eval ptype = if(source_id IN ($entity$), target_type, source_type)
    | where ptype == "technique"
    | fields tech
    | append [| inputlookup attack_techniques.csv | search technique_id IN ($entity$) | eval tech = technique_id | fields tech]
    | append [| inputlookup attack_detection_path.csv | search dc_id IN ($entity$) OR det_id IN ($entity$) OR an_id IN ($entity$) | eval tech = technique_id | fields tech]
    | append [| makeresults count=1 | eval tech = "__none__"]
    | dedup tech
    | rename tech AS target_id
    | fields target_id ]"""

MIT_VIA_TECH_QUERY = f"""| inputlookup attack_relationships.csv
| search relationship_type="mitigates" AND source_type="mitigation" {TECH_SCOPE_SUB}
| lookup attack_mitigations mitigation_id AS source_id OUTPUT description AS mitigation_description
| stats dc(target_id) as technique_hits, values(target_id) as techniques by source_id, source_name, mitigation_description
| eval techniques = mvjoin(techniques, ", ")
| sort 0 - technique_hits, source_id
| table source_id, source_name, technique_hits, techniques, mitigation_description
| rename source_id AS "Mitigation ID", source_name AS "Mitigation", technique_hits AS "該当 Technique 数", techniques AS "該当 Technique", mitigation_description AS "Mitigation の説明" """

ACTOR_VIA_TECH_QUERY = f"""| inputlookup attack_relationships.csv
| search relationship_type="uses" AND (source_type="software" OR source_type="group" OR source_type="campaign") {TECH_SCOPE_SUB}
| stats dc(target_id) as technique_hits, values(target_id) as techniques by source_type, source_id, source_name
| eval techniques = mvjoin(techniques, ", ")
| sort 0 - technique_hits, source_type, source_id
| table source_type, source_id, source_name, technique_hits, techniques
| rename source_type AS "種別", source_id AS "ID", source_name AS "名称", technique_hits AS "該当 Technique 数", techniques AS "該当 Technique" """

# Data Component / DET / AN を選んだときは検知経路から Technique を割り出す。
SCOPE_TECH_QUERY = """| inputlookup attack_detection_path.csv
| search dc_id IN ($entity$) OR det_id IN ($entity$) OR an_id IN ($entity$)
| stats dc(an_id) as analytics, dc(dc_id) as data_components, values(det_id) as det_ids by technique_id, technique_name
| eval det_ids = mvjoin(det_ids, ", ")
| sort 0 - analytics, technique_id
| table technique_id, technique_name, det_ids, analytics, data_components
| rename technique_id AS "Technique ID", technique_name AS "Technique", det_ids AS "DET", analytics AS "AN 数", data_components AS "DC 数" """

ENTITY_OVERVIEW_QUERY = """| inputlookup attack_entities.csv
| search entity_type="{entity_type}" AND entity_id IN ($entity$)
| sort 0 entity_id
| table entity_id, entity_name, description, url
| rename entity_id AS "ID", entity_name AS "名称", description AS "説明", url AS "URL" """

# (種別キー, 画面名, 既定で選ぶ ID, ファイル名, ヘッダの補足)
RELATION_VIEWS = [
    (
        "technique",
        "Technique",
        "T1190",
        "attack_rel_technique.xml",
        "選んだ Technique に紐づく Tactic・Software・Group・Campaign・Mitigation と、"
        "検知経路（DET → AN → DC → Log Source）を表示します。"
        "「関連する Technique」には sub-technique 関係（subtechnique-of）が出ます。",
    ),
    (
        "mitigation",
        "Mitigation",
        "M1050",
        "attack_rel_mitigation.xml",
        "選んだ Mitigation が緩和する Technique と、その Technique の検知経路を表示します。",
    ),
    (
        "datacomponent",
        "Data Component",
        "DC0038",
        "attack_rel_datacomponent.xml",
        "**ATT&CK v18 以降、Data Component と Technique の間に直接の関係オブジェクトはありません。**"
        "そのため relationships 由来のパネルは空になり、"
        "「検知経路」パネル（DC → AN → DET → Technique）だけが埋まります。",
    ),
    (
        "software",
        "Software",
        "S0002",
        "attack_rel_software.xml",
        "選んだ Software が使う Technique、その Software を使う Group / Campaign、"
        "および Technique 経由の検知経路を表示します。",
    ),
    (
        "group",
        "Group",
        "G0016",
        "attack_rel_group.xml",
        "選んだ Group が使う Technique と Software、関連する Campaign、"
        "および Technique 経由の検知経路を表示します。",
    ),
    (
        "campaign",
        "Campaign",
        "C0001",
        "attack_rel_campaign.xml",
        "選んだ Campaign で使われた Technique と Software、帰属する Group、"
        "および Technique 経由の検知経路を表示します。",
    ),
]


#   パネル ID -> (タイトル, dataSource ID, SPL, 高さ)
#   種別によって常に 0 件になるパネルがあるため、出すパネルは種別ごとに選ぶ。
#   例えば Mitigation は Software や Group と直接の関係を持たないので、
#   直接の関係パネルではなく「Technique 経由」のパネルを出す。
ALL_PANELS = {
    "summary": ("関係の種別ごとの件数", "ds_rel_summary", REL_SUMMARY_QUERY, 360),
    "tech": ("関連する Technique", "ds_rel_tech", REL_TECH_QUERY, 460),
    "scope_tech": ("検知経路から判明する Technique", "ds_scope_tech", SCOPE_TECH_QUERY, 460),
    "actor": ("関連する Software / Group / Campaign", "ds_rel_actor", REL_ACTOR_QUERY, 440),
    "actor_via": (
        "Technique 経由で関連する Software / Group / Campaign",
        "ds_actor_via",
        ACTOR_VIA_TECH_QUERY,
        440,
    ),
    "mit": ("関連する Mitigation", "ds_rel_mitigation", REL_MITIGATION_QUERY, 440),
    "mit_via": (
        "Technique 経由で関連する Mitigation",
        "ds_mit_via",
        MIT_VIA_TECH_QUERY,
        440,
    ),
    "detect": (
        "検知経路（Technique → Detection Strategy → Analytic → Data Component → Log Source）",
        "ds_rel_detect",
        REL_DETECT_QUERY,
        500,
    ),
    "raw": ("リレーション生データ", "ds_rel_raw", REL_RAW_QUERY, 500),
}

PANELS_BY_TYPE = {
    "technique": ["summary", "tech", "actor", "mit", "detect", "raw"],
    "mitigation": ["summary", "tech", "actor_via", "mit_via", "detect", "raw"],
    "software": ["summary", "tech", "actor", "mit_via", "detect", "raw"],
    "group": ["summary", "tech", "actor", "mit_via", "detect", "raw"],
    "campaign": ["summary", "tech", "actor", "mit_via", "detect", "raw"],
    # Data Component は relationships を持たないため、検知経路から導けるものだけ。
    "datacomponent": ["scope_tech", "actor_via", "mit_via", "detect"],
}

PANEL_TITLE_OVERRIDE = {
    ("technique", "tech"): "関連する Technique（sub-technique / 改訂の関係）",
}


def build_relation(entity_type, label, preferred_id, filename, note):
    default_id = entity_default(entity_type, preferred_id)
    panel_keys = PANELS_BY_TYPE[entity_type]
    visualizations = {}
    data_sources = {}
    rows = [[("viz_rel_header", 1200, 180)], [("viz_rel_entity", 1200, 360)]]
    for key in panel_keys:
        title, ds_id, query, height = ALL_PANELS[key]
        title = PANEL_TITLE_OVERRIDE.get((entity_type, key), title)
        viz_id = f"viz_{key}"
        data_sources[ds_id] = ds(query, title)
        if key == "summary":
            visualizations[viz_id] = column(ds_id, title, "相手の種別", "件数")
        else:
            visualizations[viz_id] = table(ds_id, title, count=25)
        rows.append([(viz_id, 1200, height)])

    definition = {
        "title": f"Relation - {label}",
        "description": f"{label} を起点に relationships から他の観点をたどる",
        "inputs": {
            "input_entity": dynamic_input(
                "ds_entities",
                "entity",
                label,
                "label",
                "value",
                default=f'"{default_id}"',
                multiple=True,
            )
        },
        "defaults": {},
        "visualizations": dict(
            visualizations,
            viz_rel_header=markdown(
                f"## Relation - {label}\n"
                f"上の「{label}」は複数選択できます。選んだものすべてを起点に "
                "`attack_relationships.csv` を双方向でたどった結果を表示します。"
                "どの対象から出た行かは各表の「対象 ID」列で分かります。\n\n"
                f"{note}"
            ),
            viz_rel_entity=table("ds_entity", f"選択した {label} の概要", count=20),
        ),
        "dataSources": dict(
            data_sources,
            ds_entities=ds(
                "| inputlookup attack_entities.csv\n"
                f'| search entity_type="{entity_type}"\n'
                "| sort 0 entity_id\n"
                '| eval value = "\\"".entity_id."\\""\n'
                "| fields label, value",
                f"{label} 一覧",
            ),
            ds_entity=ds(
                ENTITY_OVERVIEW_QUERY.format(entity_type=entity_type), "対象の概要"
            ),
        ),
        "layout": {
            "globalInputs": ["input_entity"],
            "tabs": {
                "items": [{"label": label, "layoutId": "layout_relation"}],
                "options": {"barPosition": "top", "showTabBar": False},
            },
            "layoutDefinitions": {
                "layout_relation": {
                    "type": "grid",
                    "options": {"display": "auto"},
                    "structure": grid(rows),
                }
            },
        },
    }
    write_view(filename, f"Relation - {label}", f"{label} 視点のリレーション", definition)


# ---------------------------------------------------------------------------
# 4. Data Source Matrix（データソース × Tactic）
# ---------------------------------------------------------------------------
# v18 以降の旧 Data Source オブジェクトは全て deprecated で、Data Component との
# 参照も無い。そのため「データソース」は Data Component か Log Source 名を選ばせる。
# 検知経路で source に届く Technique を、その Technique が属する Tactic ごとに数える。
DSM_BASE = """| inputlookup attack_detection_path.csv
| where isnotnull(technique_id) AND technique_id!=""
| eval source = if("$unit$"=="dc", dc_id." ".dc_name, trim(log_source_name))
| where isnotnull(source) AND source!=""
| stats count by source, technique_id
| lookup attack_navigator technique_id OUTPUT tactic_order, tactic_name
| eval pair = mvzip(tactic_order, tactic_name, "|")
| mvexpand pair
| eval tactic = printf("%02d", tonumber(mvindex(split(pair, "|"), 0)))." ".mvindex(split(pair, "|"), 1)
| stats dc(technique_id) as techniques by source, tactic"""

DSM_MATRIX_QUERY = f"""{DSM_BASE}
| xyseries source tactic techniques
| fillnull value=0
| addtotals fieldname=total
| sort 0 -total, +source
| table source, total, *
| rename source AS "データソース", total AS "合計" """

DSM_COLUMN_QUERY = f"""{DSM_BASE}
| xyseries source tactic techniques
| fillnull value=0
| addtotals fieldname=total
| sort 0 -total, +source
| head 30
| fields - total"""

DSM_TACTIC_PIE_QUERY = f"""{DSM_BASE}
| stats sum(techniques) as count by tactic
| sort 0 - count"""

DSM_SOURCE_PIE_QUERY = f"""{DSM_BASE}
| stats sum(techniques) as count by source
| sort 0 -count, +source
| streamstats count as rank
| eval source = if(rank <= 15, source, "その他（16 位以下）")
| stats sum(count) as count, min(rank) as rank by source
| sort 0 rank
| fields source, count"""


def build_ds_matrix():
    definition = {
        "title": "Data Source Matrix",
        "description": "データソース × Tactic の Technique 数",
        "inputs": {
            "input_unit": static_dropdown(
                "unit",
                "データソースの単位",
                [("Data Component", "dc"), ("Log Source", "ls")],
                "dc",
            ),
        },
        "defaults": {},
        "visualizations": {
            "viz_dsm_header": markdown(
                "## Data Source Matrix\n"
                "行がデータソース、列が Tactic、セルはそのデータソースで検知できる Technique の数です"
                "（sub-technique を含む）。検知経路 Technique → Detection Strategy → Analytic → "
                "Data Component → Log Source（`attack_detection_path.csv`）から数えています。"
                "複数の Tactic に属する Technique は、それぞれの Tactic で 1 件ずつ数えます。\n\n"
                "「合計」と 2 つの円グラフの件数は、マトリクスのセルを行または列で足した値です。"
                "上の「データソースの単位」で Data Component と Log Source を切り替えられます。"
                "ATT&CK v18 以降は旧来の Data Source（Process など）が廃止されているため、この 2 つから選びます。"
            ),
            "viz_dsm_matrix": table(
                "ds_dsm_matrix", "データソース × Tactic マトリクス（合計の多い順）", count=50
            ),
            "viz_dsm_column": column(
                "ds_dsm_column",
                "データソース別・Tactic 別の Technique 数（合計の上位 30 件）",
                "データソース",
                "Technique 数",
            ),
            "viz_dsm_tactic_pie": pie("ds_dsm_tactic_pie", "Tactic 別の件数"),
            "viz_dsm_source_pie": pie("ds_dsm_source_pie", "データソース別の件数（上位 15 件）"),
        },
        "dataSources": {
            "ds_dsm_matrix": ds(DSM_MATRIX_QUERY, "マトリクス"),
            "ds_dsm_column": ds(DSM_COLUMN_QUERY, "縦棒グラフ"),
            "ds_dsm_tactic_pie": ds(DSM_TACTIC_PIE_QUERY, "Tactic 別件数"),
            "ds_dsm_source_pie": ds(DSM_SOURCE_PIE_QUERY, "データソース別件数"),
        },
        "layout": {
            "globalInputs": ["input_unit"],
            "tabs": {
                "items": [{"label": "Data Source Matrix", "layoutId": "layout_dsm"}],
                "options": {"barPosition": "top", "showTabBar": False},
            },
            "layoutDefinitions": {
                "layout_dsm": {
                    "type": "grid",
                    "options": {"display": "auto"},
                    "structure": grid(
                        [
                            [("viz_dsm_header", 1200, 150)],
                            [("viz_dsm_matrix", 1200, 760)],
                            [("viz_dsm_column", 1200, 720)],
                            [("viz_dsm_tactic_pie", 600, 460), ("viz_dsm_source_pie", 600, 460)],
                        ]
                    ),
                }
            },
        },
    }
    # データソース名が長く 30 本並ぶため、自動だとラベルが間引かれる。縦書きにして全件出す。
    definition["visualizations"]["viz_dsm_column"]["options"].update(
        {"stackMode": "stacked", "xAxisLabelVisibility": "show", "xAxisLabelRotation": -90}
    )
    write_view(
        "attack_ds_matrix.xml", "Data Source Matrix", "データソース × Tactic の Technique 数", definition
    )


if __name__ == "__main__":
    print("writing views")
    build_navigator()
    build_ds_matrix()
    build_attack_data()
    for params in RELATION_VIEWS:
        build_relation(*params)
    stale = os.path.join(VIEW_DIR, "attack_relation.xml")
    if os.path.exists(stale):
        os.remove(stale)
        print("  removed attack_relation.xml (6 画面に分割したため)")
    print("done")
