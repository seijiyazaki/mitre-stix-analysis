#!/usr/bin/env python3
"""MITRE ATT&CK の STIX バンドルを Splunk の CSV lookup に変換する。

使い方:
    python3 tools/build_lookups.py                      # v20.1 を取得して lookups/ に出力
    python3 tools/build_lookups.py --version 18.1       # 別バージョン
    python3 tools/build_lookups.py --stix path/to.json  # ローカルの STIX を使う

出力は版ごとの attack_<種別>_v<版>.csv（例: attack_techniques_v20.1.csv）。
ダッシュボードはこの版付きのファイルを画面上で選んだ版で読む。
取り込み済みの版のうち最も新しい版だけは、版なしの attack_<種別>.csv にも複製する
（他アプリから `| inputlookup attack_techniques.csv` で最新版を引けるようにするため）。
取り込み済みの版の一覧は attack_versions.csv に記録する。

v18 以降 Technique と Data Component の間に直接の関係オブジェクトは無い。
Technique -> Detection Strategy -> Analytic -> Data Component の 4 ホップを
たどって attack_detection_path.csv に平坦化している。
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import sys
import urllib.request
from collections import Counter, defaultdict

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
    "/enterprise-attack/enterprise-attack-{version}.json"
)

APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOOKUP_DIR = os.path.join(APP_ROOT, "lookups")

CITATION_RE = re.compile(r"\(Citation:[^)]*\)")
MARKDOWN_LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]*\)")
WHITESPACE_RE = re.compile(r"\s+")

SOFTWARE_TYPES = {"malware": "malware", "tool": "tool"}


def clean(text, limit=1200):
    """CSV lookup に入れられるよう 1 行に畳む。引用記法とリンクは落とす。"""
    if not text:
        return ""
    text = MARKDOWN_LINK_RE.sub(r"\1", str(text))
    text = CITATION_RE.sub("", text)
    text = WHITESPACE_RE.sub(" ", text).strip()
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text


def attack_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def attack_url(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url", "")
    return ""


def is_live(obj):
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def load_stix(args):
    if args.stix:
        with open(args.stix, encoding="utf-8") as fh:
            return json.load(fh), os.path.basename(args.stix)
    url = STIX_URL.format(version=args.version)
    sys.stderr.write(f"downloading {url}\n")
    with urllib.request.urlopen(url) as resp:
        return json.loads(resp.read().decode("utf-8")), os.path.basename(url)


STIX_NAME_RE = re.compile(r"enterprise-attack-(\d+\.\d+)\.json$")
VERSIONS_CSV = "attack_versions.csv"
WRITTEN = []  # この実行で書いた版なしのファイル名
VERSION_SUFFIX = ""


def versioned(name, version):
    """attack_techniques.csv -> attack_techniques_v20.1.csv"""
    return name[: -len(".csv")] + f"_v{version}.csv"


def version_key(version):
    return tuple(int(x) for x in version.split("."))


def write_csv(name, fieldnames, rows):
    os.makedirs(LOOKUP_DIR, exist_ok=True)
    WRITTEN.append(name)
    name = versioned(name, VERSION_SUFFIX)
    path = os.path.join(LOOKUP_DIR, name)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    sys.stderr.write(f"  {name:38s} {len(rows):6d} rows\n")
    return len(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", default="20.1")
    parser.add_argument("--stix")
    args = parser.parse_args()

    bundle, source_name = load_stix(args)
    if args.stix:
        # 版はバンドル内の collection オブジェクトから取る。無ければファイル名から取る。
        # --version の既定値（20.1）を別の版のデータに誤って付けないため。
        collection_version = next(
            (o.get("x_mitre_version") for o in bundle["objects"] if o["type"] == "x-mitre-collection"),
            None,
        )
        match = STIX_NAME_RE.search(os.path.basename(args.stix))
        if collection_version:
            args.version = collection_version
        elif match:
            args.version = match.group(1)
        else:
            sys.exit(f"{args.stix} の版が分かりません（collection オブジェクトもファイル名の版もありません）")
    global VERSION_SUFFIX
    VERSION_SUFFIX = args.version
    objects = bundle["objects"]
    by_stix_id = {o["id"]: o for o in objects}

    techniques = {o["id"]: o for o in objects if o["type"] == "attack-pattern" and is_live(o)}
    tactics = {o["id"]: o for o in objects if o["type"] == "x-mitre-tactic" and is_live(o)}
    groups = {o["id"]: o for o in objects if o["type"] == "intrusion-set" and is_live(o)}
    software = {
        o["id"]: o for o in objects if o["type"] in SOFTWARE_TYPES and is_live(o)
    }
    mitigations = {
        o["id"]: o for o in objects if o["type"] == "course-of-action" and is_live(o)
    }
    campaigns = {o["id"]: o for o in objects if o["type"] == "campaign" and is_live(o)}
    datacomponents = {
        o["id"]: o for o in objects if o["type"] == "x-mitre-data-component" and is_live(o)
    }
    strategies = {
        o["id"]: o
        for o in objects
        if o["type"] == "x-mitre-detection-strategy" and is_live(o)
    }
    analytics = {
        o["id"]: o for o in objects if o["type"] == "x-mitre-analytic" and is_live(o)
    }
    matrices = [o for o in objects if o["type"] == "x-mitre-matrix" and is_live(o)]

    # ---- tactic の並び順はマトリクスの tactic_refs が持っている
    tactic_order = {}
    for matrix in matrices:
        for order, ref in enumerate(matrix.get("tactic_refs", []), start=1):
            tactic_order[ref] = order
    shortname_to_tactic = {
        t.get("x_mitre_shortname"): t for t in tactics.values() if t.get("x_mitre_shortname")
    }

    # ---- relationship を両方向で引けるようにする
    relationships = [o for o in objects if o["type"] == "relationship" and is_live(o)]
    out_rel = defaultdict(list)  # source_stix_id -> [rel]
    in_rel = defaultdict(list)  # target_stix_id -> [rel]
    for rel in relationships:
        out_rel[rel["source_ref"]].append(rel)
        in_rel[rel["target_ref"]].append(rel)

    def type_label(obj):
        if obj is None:
            return ""
        return {
            "attack-pattern": "technique",
            "intrusion-set": "group",
            "malware": "software",
            "tool": "software",
            "course-of-action": "mitigation",
            "campaign": "campaign",
            "x-mitre-data-component": "datacomponent",
            "x-mitre-detection-strategy": "detectionstrategy",
            "x-mitre-analytic": "analytic",
            "x-mitre-tactic": "tactic",
            "x-mitre-data-source": "datasource",
        }.get(obj["type"], obj["type"])

    # ---- Technique -> Detection Strategy -> Analytic -> Data Component
    strategy_to_technique = {}
    for rel in relationships:
        if rel["relationship_type"] != "detects":
            continue
        if rel["source_ref"] in strategies and rel["target_ref"] in techniques:
            strategy_to_technique[rel["source_ref"]] = rel["target_ref"]
    analytic_to_strategy = {
        an_ref: s_id
        for s_id, strat in strategies.items()
        for an_ref in strat.get("x_mitre_analytic_refs", [])
    }

    detection_path = []
    technique_analytics = Counter()
    technique_components = defaultdict(set)
    component_analytics = defaultdict(set)
    component_techniques = defaultdict(set)
    for an_id, analytic in analytics.items():
        strat_id = analytic_to_strategy.get(an_id)
        strat = strategies.get(strat_id)
        tech = techniques.get(strategy_to_technique.get(strat_id, ""))
        platforms = ", ".join(analytic.get("x_mitre_platforms", []) or [])
        if tech is not None:
            technique_analytics[tech["id"]] += 1
        for log_source in analytic.get("x_mitre_log_source_references", []) or []:
            dc = datacomponents.get(log_source.get("x_mitre_data_component_ref", ""))
            if dc is None:
                continue
            component_analytics[dc["id"]].add(an_id)
            if tech is not None:
                technique_components[tech["id"]].add(dc["id"])
                component_techniques[dc["id"]].add(tech["id"])
            detection_path.append(
                {
                    "technique_id": attack_id(tech) if tech else "",
                    "technique_name": tech["name"] if tech else "",
                    "det_id": attack_id(strat) if strat else "",
                    "det_name": strat["name"] if strat else "",
                    "an_id": attack_id(analytic),
                    "platforms": platforms,
                    "dc_id": attack_id(dc),
                    "dc_name": dc["name"],
                    "log_source_name": log_source.get("name", ""),
                    "channel": clean(log_source.get("channel", ""), 400),
                    "analytic_description": clean(analytic.get("description"), 600),
                }
            )

    # ---- relationship 由来の件数集計
    def related_count(stix_id, rel_type, peer_set, direction):
        source = out_rel if direction == "out" else in_rel
        peer_key = "target_ref" if direction == "out" else "source_ref"
        return len(
            {
                rel[peer_key]
                for rel in source.get(stix_id, [])
                if rel["relationship_type"] == rel_type and rel[peer_key] in peer_set
            }
        )

    sys.stderr.write("writing lookups\n")
    counts = {}

    # ---------------------------------------------------------------- techniques
    rows = []
    navigator_rows = []
    for stix_id, tech in sorted(techniques.items(), key=lambda kv: attack_id(kv[1])):
        tid = attack_id(tech)
        if not tid:
            continue
        parent_id = ""
        parent_name = ""
        if tech.get("x_mitre_is_subtechnique"):
            parent_id = tid.split(".")[0]
        tactic_names = []
        for phase in tech.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") != "mitre-attack":
                continue
            tac = shortname_to_tactic.get(phase.get("phase_name"))
            if tac:
                tactic_names.append(tac["name"])
        platforms = ", ".join(tech.get("x_mitre_platforms", []) or [])
        dcs = sorted(attack_id(by_stix_id[d]) for d in technique_components.get(stix_id, ()))
        row = {
            "technique_id": tid,
            "name": tech["name"],
            "is_sub_technique": "true" if tech.get("x_mitre_is_subtechnique") else "false",
            "parent_id": parent_id,
            "parent_name": parent_name,
            "tactics": ", ".join(tactic_names),
            "platforms": platforms,
            "detection_strategies": related_count(stix_id, "detects", strategies, "in"),
            "analytics": technique_analytics.get(stix_id, 0),
            "data_components": ", ".join(dcs),
            "data_component_count": len(dcs),
            "mitigations": related_count(stix_id, "mitigates", mitigations, "in"),
            "groups": related_count(stix_id, "uses", groups, "in"),
            "software": related_count(stix_id, "uses", software, "in"),
            "campaigns": related_count(stix_id, "uses", campaigns, "in"),
            "url": attack_url(tech),
            "description": clean(tech.get("description")),
        }
        rows.append(row)
        for tactic_name in tactic_names:
            tac = next(
                (t for t in tactics.values() if t["name"] == tactic_name), None
            )
            navigator_rows.append(
                {
                    "tactic_order": tactic_order.get(tac["id"], 99) if tac else 99,
                    "tactic_id": attack_id(tac) if tac else "",
                    "tactic_name": tactic_name,
                    "tactic_shortname": tac.get("x_mitre_shortname", "") if tac else "",
                    "technique_id": tid,
                    "technique_name": tech["name"],
                    "is_sub_technique": row["is_sub_technique"],
                    "parent_id": parent_id,
                    "platforms": platforms,
                    "analytics": row["analytics"],
                    "detection_strategies": row["detection_strategies"],
                    "mitigations": row["mitigations"],
                    "groups": row["groups"],
                    "software": row["software"],
                    "data_component_count": row["data_component_count"],
                }
            )
    # 親の名前を埋める
    name_by_id = {r["technique_id"]: r["name"] for r in rows}
    for row in rows:
        if row["parent_id"]:
            row["parent_name"] = name_by_id.get(row["parent_id"], "")
    counts["techniques"] = write_csv(
        "attack_techniques.csv",
        [
            "technique_id",
            "name",
            "is_sub_technique",
            "parent_id",
            "parent_name",
            "tactics",
            "platforms",
            "detection_strategies",
            "analytics",
            "data_components",
            "data_component_count",
            "mitigations",
            "groups",
            "software",
            "campaigns",
            "url",
            "description",
        ],
        rows,
    )

    navigator_rows.sort(key=lambda r: (r["tactic_order"], r["technique_id"]))
    counts["navigator"] = write_csv(
        "attack_navigator.csv",
        [
            "tactic_order",
            "tactic_id",
            "tactic_name",
            "tactic_shortname",
            "technique_id",
            "technique_name",
            "is_sub_technique",
            "parent_id",
            "platforms",
            "analytics",
            "detection_strategies",
            "mitigations",
            "groups",
            "software",
            "data_component_count",
        ],
        navigator_rows,
    )

    # ------------------------------------------------------------------ tactics
    technique_per_tactic = Counter(r["tactic_name"] for r in navigator_rows)
    rows = [
        {
            "tactic_id": attack_id(t),
            "name": t["name"],
            "shortname": t.get("x_mitre_shortname", ""),
            "tactic_order": tactic_order.get(sid, 99),
            "techniques": technique_per_tactic.get(t["name"], 0),
            "url": attack_url(t),
            "description": clean(t.get("description")),
        }
        for sid, t in tactics.items()
    ]
    rows.sort(key=lambda r: r["tactic_order"])
    counts["tactics"] = write_csv(
        "attack_tactics.csv",
        [
            "tactic_id",
            "name",
            "shortname",
            "tactic_order",
            "techniques",
            "url",
            "description",
        ],
        rows,
    )

    # ----------------------------------------------------------------- matrices
    rows = []
    for matrix in matrices:
        for order, ref in enumerate(matrix.get("tactic_refs", []), start=1):
            tac = tactics.get(ref)
            if tac is None:
                continue
            rows.append(
                {
                    "matrix_id": attack_id(matrix),
                    "matrix_name": matrix["name"],
                    "tactic_order": order,
                    "tactic_id": attack_id(tac),
                    "tactic_name": tac["name"],
                    "tactic_shortname": tac.get("x_mitre_shortname", ""),
                    "techniques": technique_per_tactic.get(tac["name"], 0),
                    "url": attack_url(matrix),
                }
            )
    counts["matrices"] = write_csv(
        "attack_matrices.csv",
        [
            "matrix_id",
            "matrix_name",
            "tactic_order",
            "tactic_id",
            "tactic_name",
            "tactic_shortname",
            "techniques",
            "url",
        ],
        rows,
    )

    # ------------------------------------------------------------------- groups
    rows = [
        {
            "group_id": attack_id(g),
            "name": g["name"],
            "aliases": ", ".join(g.get("aliases", []) or []),
            "techniques": related_count(sid, "uses", techniques, "out"),
            "software": related_count(sid, "uses", software, "out"),
            "campaigns": related_count(sid, "attributed-to", campaigns, "in"),
            "url": attack_url(g),
            "description": clean(g.get("description")),
        }
        for sid, g in groups.items()
    ]
    rows.sort(key=lambda r: r["group_id"])
    counts["groups"] = write_csv(
        "attack_groups.csv",
        ["group_id", "name", "aliases", "techniques", "software", "campaigns", "url", "description"],
        rows,
    )

    # ----------------------------------------------------------------- software
    rows = [
        {
            "software_id": attack_id(s),
            "name": s["name"],
            "software_type": SOFTWARE_TYPES[s["type"]],
            "platforms": ", ".join(s.get("x_mitre_platforms", []) or []),
            "aliases": ", ".join(s.get("x_mitre_aliases", []) or []),
            "techniques": related_count(sid, "uses", techniques, "out"),
            "groups": related_count(sid, "uses", groups, "in"),
            "campaigns": related_count(sid, "uses", campaigns, "in"),
            "url": attack_url(s),
            "description": clean(s.get("description")),
        }
        for sid, s in software.items()
    ]
    rows.sort(key=lambda r: r["software_id"])
    counts["software"] = write_csv(
        "attack_software.csv",
        [
            "software_id",
            "name",
            "software_type",
            "platforms",
            "aliases",
            "techniques",
            "groups",
            "campaigns",
            "url",
            "description",
        ],
        rows,
    )

    # -------------------------------------------------------------- mitigations
    rows = [
        {
            "mitigation_id": attack_id(m),
            "name": m["name"],
            "techniques": related_count(sid, "mitigates", techniques, "out"),
            "url": attack_url(m),
            "description": clean(m.get("description")),
        }
        for sid, m in mitigations.items()
    ]
    rows.sort(key=lambda r: r["mitigation_id"])
    counts["mitigations"] = write_csv(
        "attack_mitigations.csv",
        [
            "mitigation_id",
            "name",
            "techniques",
            "url",
            "description",
        ],
        rows,
    )

    # ---------------------------------------------------------------- campaigns
    rows = [
        {
            "campaign_id": attack_id(c),
            "name": c["name"],
            "first_seen": (c.get("first_seen") or "")[:10],
            "last_seen": (c.get("last_seen") or "")[:10],
            "aliases": ", ".join(c.get("aliases", []) or []),
            "techniques": related_count(sid, "uses", techniques, "out"),
            "software": related_count(sid, "uses", software, "out"),
            "groups": related_count(sid, "attributed-to", groups, "out"),
            "url": attack_url(c),
            "description": clean(c.get("description")),
        }
        for sid, c in campaigns.items()
    ]
    rows.sort(key=lambda r: r["campaign_id"])
    counts["campaigns"] = write_csv(
        "attack_campaigns.csv",
        [
            "campaign_id",
            "name",
            "first_seen",
            "last_seen",
            "aliases",
            "techniques",
            "software",
            "groups",
            "url",
            "description",
        ],
        rows,
    )

    # ----------------------------------------------------------- datacomponents
    rows = []
    for sid, dc in datacomponents.items():
        log_sources = dc.get("x_mitre_log_sources", []) or []
        rows.append(
            {
                "dc_id": attack_id(dc),
                "name": dc["name"],
                "log_sources": len(log_sources),
                "log_source_names": ", ".join(sorted({ls.get("name", "") for ls in log_sources})),
                "analytics": len(component_analytics.get(sid, ())),
                "techniques": len(component_techniques.get(sid, ())),
                "url": attack_url(dc),
                "description": clean(dc.get("description")),
            }
        )
    rows.sort(key=lambda r: (-r["techniques"], r["dc_id"]))
    counts["datacomponents"] = write_csv(
        "attack_datacomponents.csv",
        [
            "dc_id",
            "name",
            "log_sources",
            "log_source_names",
            "analytics",
            "techniques",
            "url",
            "description",
        ],
        rows,
    )

    # ------------------------------------------------- data component log sources
    rows = []
    for sid, dc in datacomponents.items():
        for log_source in dc.get("x_mitre_log_sources", []) or []:
            rows.append(
                {
                    "dc_id": attack_id(dc),
                    "dc_name": dc["name"],
                    "log_source_name": log_source.get("name", ""),
                    "channel": clean(log_source.get("channel", ""), 400),
                }
            )
    rows.sort(key=lambda r: (r["dc_id"], r["log_source_name"]))
    counts["dc_log_sources"] = write_csv(
        "attack_dc_log_sources.csv",
        ["dc_id", "dc_name", "log_source_name", "channel"],
        rows,
    )

    # ------------------------------------------------------ detection strategies
    rows = []
    for sid, strat in strategies.items():
        tech = techniques.get(strategy_to_technique.get(sid, ""))
        an_ids = [a for a in strat.get("x_mitre_analytic_refs", []) if a in analytics]
        platforms = sorted(
            {
                p
                for a in an_ids
                for p in (analytics[a].get("x_mitre_platforms") or [])
            }
        )
        rows.append(
            {
                "det_id": attack_id(strat),
                "name": strat["name"],
                "technique_id": attack_id(tech) if tech else "",
                "technique_name": tech["name"] if tech else "",
                "analytics": len(an_ids),
                "analytic_ids": ", ".join(sorted(attack_id(analytics[a]) for a in an_ids)),
                "platforms": ", ".join(platforms),
                "url": attack_url(strat),
            }
        )
    rows.sort(key=lambda r: r["det_id"])
    counts["detectionstrategies"] = write_csv(
        "attack_detectionstrategies.csv",
        [
            "det_id",
            "name",
            "technique_id",
            "technique_name",
            "analytics",
            "analytic_ids",
            "platforms",
            "url",
        ],
        rows,
    )

    # ----------------------------------------------------------------- analytics
    rows = []
    for sid, analytic in analytics.items():
        strat_id = analytic_to_strategy.get(sid)
        strat = strategies.get(strat_id)
        tech = techniques.get(strategy_to_technique.get(strat_id, ""))
        log_sources = analytic.get("x_mitre_log_source_references", []) or []
        mutable = analytic.get("x_mitre_mutable_elements", []) or []
        rows.append(
            {
                "an_id": attack_id(analytic),
                "det_id": attack_id(strat) if strat else "",
                "det_name": strat["name"] if strat else "",
                "technique_id": attack_id(tech) if tech else "",
                "technique_name": tech["name"] if tech else "",
                "platforms": ", ".join(analytic.get("x_mitre_platforms", []) or []),
                "log_source_names": ", ".join(
                    sorted({ls.get("name", "") for ls in log_sources})
                ),
                "data_components": ", ".join(
                    sorted(
                        {
                            attack_id(datacomponents[ls["x_mitre_data_component_ref"]])
                            for ls in log_sources
                            if ls.get("x_mitre_data_component_ref") in datacomponents
                        }
                    )
                ),
                "mutable_elements": ", ".join(m.get("field", "") for m in mutable),
                "mutable_detail": clean(
                    "; ".join(f"{m.get('field')}: {m.get('description')}" for m in mutable),
                    800,
                ),
                "url": attack_url(analytic),
                "description": clean(analytic.get("description")),
            }
        )
    rows.sort(key=lambda r: r["an_id"])
    counts["analytics"] = write_csv(
        "attack_analytics.csv",
        [
            "an_id",
            "det_id",
            "det_name",
            "technique_id",
            "technique_name",
            "platforms",
            "log_source_names",
            "data_components",
            "mutable_elements",
            "mutable_detail",
            "url",
            "description",
        ],
        rows,
    )

    # ------------------------------------------------------------ detection path
    detection_path.sort(key=lambda r: (r["technique_id"], r["an_id"], r["dc_id"]))
    counts["detection_path"] = write_csv(
        "attack_detection_path.csv",
        [
            "technique_id",
            "technique_name",
            "det_id",
            "det_name",
            "an_id",
            "platforms",
            "dc_id",
            "dc_name",
            "log_source_name",
            "channel",
            "analytic_description",
        ],
        detection_path,
    )

    # ------------------------------------------------------------ relationships
    rows = []
    for rel in relationships:
        src = by_stix_id.get(rel["source_ref"])
        tgt = by_stix_id.get(rel["target_ref"])
        src_id = attack_id(src) if src else ""
        tgt_id = attack_id(tgt) if tgt else ""
        if not src_id and not tgt_id:
            continue
        rows.append(
            {
                "relationship_type": rel["relationship_type"],
                "source_id": src_id,
                "source_name": src["name"] if src and "name" in src else "",
                "source_type": type_label(src),
                "target_id": tgt_id,
                "target_name": tgt["name"] if tgt and "name" in tgt else "",
                "target_type": type_label(tgt),
                "description": clean(rel.get("description"), 600),
            }
        )
    rows.sort(key=lambda r: (r["source_type"], r["source_id"], r["target_id"]))
    counts["relationships"] = write_csv(
        "attack_relationships.csv",
        [
            "relationship_type",
            "source_id",
            "source_name",
            "source_type",
            "target_id",
            "target_name",
            "target_type",
            "description",
        ],
        rows,
    )

    # ----------------------------------------------------------------- entities
    entity_sets = [
        ("technique", techniques),
        ("mitigation", mitigations),
        ("datacomponent", datacomponents),
        ("software", software),
        ("group", groups),
        ("campaign", campaigns),
        ("tactic", tactics),
        ("detectionstrategy", strategies),
    ]
    rows = []
    for entity_type, collection in entity_sets:
        for obj in collection.values():
            eid = attack_id(obj)
            if not eid:
                continue
            rows.append(
                {
                    "entity_type": entity_type,
                    "entity_id": eid,
                    "entity_name": obj["name"],
                    "label": f"{eid} - {obj['name']}",
                    "url": attack_url(obj),
                    "description": clean(obj.get("description"), 800),
                }
            )
    rows.sort(key=lambda r: (r["entity_type"], r["entity_id"]))
    counts["entities"] = write_csv(
        "attack_entities.csv",
        [
            "entity_type",
            "entity_id",
            "entity_name",
            "label",
            "url",
            "description",
        ],
        rows,
    )

    # -------------------------------------------------------------------- about
    version = bundle.get("x_mitre_version") or args.version
    write_csv(
        "attack_about.csv",
        ["key", "value"],
        [
            {"key": "attack_version", "value": args.version},
            {"key": "stix_bundle", "value": source_name},
            {"key": "stix_objects", "value": len(objects)},
            {"key": "spec_version", "value": version},
        ]
        + [{"key": f"rows_{k}", "value": v} for k, v in sorted(counts.items())],
    )
    update_versions(args.version, source_name, len(objects), bundle)
    sys.stderr.write("done\n")


def update_versions(version, source_name, object_count, bundle):
    """attack_versions.csv を更新し、最新版なら版なしのファイルにも複製する。"""
    path = os.path.join(LOOKUP_DIR, VERSIONS_CSV)
    rows = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            rows = {r["version"]: r for r in csv.DictReader(fh)}
    modified = next(
        (o.get("modified", "") for o in bundle["objects"] if o["type"] == "x-mitre-collection"), ""
    )
    rows[version] = {
        "version": version,
        "label": f"v{version}",
        "stix_bundle": source_name,
        "stix_objects": object_count,
        "released": modified[:10],
    }
    ordered = sorted(rows.values(), key=lambda r: version_key(r["version"]), reverse=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["version", "label", "stix_bundle", "stix_objects", "released"])
        writer.writeheader()
        writer.writerows(ordered)
    sys.stderr.write(f"  {VERSIONS_CSV:38s} {len(ordered):6d} rows\n")

    if ordered[0]["version"] == version:
        for name in WRITTEN:
            shutil.copyfile(
                os.path.join(LOOKUP_DIR, versioned(name, version)), os.path.join(LOOKUP_DIR, name)
            )
        sys.stderr.write(f"  v{version} が最新のため版なしの lookup にも複製しました\n")


if __name__ == "__main__":
    main()
