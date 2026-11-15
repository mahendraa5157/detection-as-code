"""Build the ATT&CK coverage artifacts from the rule set.

Scans rules/ for `attack.txxxx` tags and emits:
  * mappings/attack_navigator_layer.json  -- importable into MITRE ATT&CK Navigator
  * docs/coverage_heatmap.svg              -- self-contained heatmap for the README
  * docs/coverage_summary.md               -- technique/tactic/level table

Color scale is by number of rules per technique. Run:
  python scripts/build_coverage_heatmap.py
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

from sigma.rule import SigmaRule

REPO = Path(__file__).resolve().parent.parent
RULES = sorted((REPO / "rules").rglob("*.yml"))

# Minimal technique -> (tactic, display name) map for techniques used in this repo.
TACTIC_OF = {
    "T1059.001": ("execution", "PowerShell"),
    "T1059.003": ("execution", "Windows Command Shell"),
    "T1047": ("execution", "WMI"),
    "T1053.005": ("persistence", "Scheduled Task"),
    "T1136.001": ("persistence", "Create Local Account"),
    "T1547.001": ("persistence", "Registry Run Keys"),
    "T1548.002": ("privilege-escalation", "Bypass UAC"),
    "T1003.001": ("credential-access", "LSASS Memory"),
    "T1021.001": ("lateral-movement", "Remote Desktop Protocol"),
    "T1218.011": ("defense-evasion", "Rundll32"),
    "T1218.010": ("defense-evasion", "Regsvr32"),
    "T1218.005": ("defense-evasion", "Mshta"),
    "T1070.001": ("defense-evasion", "Clear Windows Event Logs"),
    "T1562.001": ("defense-evasion", "Disable or Modify Tools"),
    "T1197": ("defense-evasion", "BITS Jobs"),
    "T1140": ("defense-evasion", "Deobfuscate/Decode"),
    "T1027": ("defense-evasion", "Obfuscated Files or Information"),
    "T1112": ("defense-evasion", "Modify Registry"),
    "T1105": ("command-and-control", "Ingress Tool Transfer"),
    "T1016": ("discovery", "System Network Configuration Discovery"),
    "T1057": ("discovery", "Process Discovery"),
    "T1082": ("discovery", "System Information Discovery"),
    "T1087.001": ("discovery", "Local Account Discovery"),
    "T1069.001": ("discovery", "Permission Groups Discovery"),
    "T1033": ("discovery", "System Owner/User Discovery"),
    "T1490": ("impact", "Inhibit System Recovery"),
}

TACTIC_ORDER = [
    "initial-access", "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact",
]
TACTIC_LABEL = {t: t.replace("-", " ").title() for t in TACTIC_ORDER}


def tech_tags(rule: SigmaRule) -> list[str]:
    out = []
    for t in rule.tags:
        s = str(t)
        m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", s)
        if m:
            out.append(m.group(1).upper())
    return out


def collect():
    counts: dict[str, int] = defaultdict(int)
    levels: dict[str, str] = {}
    rule_names: dict[str, list[str]] = defaultdict(list)
    for path in RULES:
        rule = SigmaRule.from_yaml(path.read_text(encoding="utf-8"))
        for tid in tech_tags(rule):
            counts[tid] += 1
            rule_names[tid].append(rule.title)
            levels[tid] = rule.level.name.lower() if rule.level else "medium"
    return counts, levels, rule_names


def color_for(n: int) -> str:
    # green scale: more rules = darker green
    return {1: "#9fd8a3", 2: "#52b36a", 3: "#2e8b57"}.get(min(n, 3), "#1f6b40")


def write_navigator(counts, rule_names):
    techniques = []
    for tid, n in sorted(counts.items()):
        techniques.append({
            "techniqueID": tid,
            "score": n,
            "color": color_for(n),
            "comment": "; ".join(rule_names[tid]),
            "enabled": True,
            "metadata": [{"name": "rules", "value": str(n)}],
        })
    layer = {
        "name": "Detection-as-Code Coverage",
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Techniques covered by Sigma rules in mahendraa5157/detection-as-code. "
                       "Score = number of rules mapped to the technique.",
        "sorting": 3,
        "techniques": techniques,
        "gradient": {"colors": ["#9fd8a3", "#1f6b40"], "minValue": 1, "maxValue": 3},
        "legendItems": [
            {"label": "1 rule", "color": "#9fd8a3"},
            {"label": "2 rules", "color": "#52b36a"},
            {"label": "3+ rules", "color": "#1f6b40"},
        ],
    }
    out = REPO / "mappings" / "attack_navigator_layer.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8", newline="\n")
    return out


def write_svg(counts):
    by_tactic: dict[str, list[str]] = defaultdict(list)
    for tid in counts:
        tac = TACTIC_OF.get(tid, ("execution", tid))[0]
        by_tactic[tac].append(tid)
    used_tactics = [t for t in TACTIC_ORDER if by_tactic.get(t)]

    col_w, cell_h, head_h, pad = 150, 34, 56, 16
    gap = 6
    max_rows = max(len(by_tactic[t]) for t in used_tactics)
    width = pad * 2 + len(used_tactics) * (col_w + gap)
    height = pad * 2 + head_h + max_rows * (cell_h + gap) + 30

    def esc(s):
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family="Segoe UI, Arial, sans-serif">',
        f'<rect width="{width}" height="{height}" fill="#0f1420"/>',
        f'<text x="{pad}" y="{pad+18}" fill="#e6e6e6" font-size="18" font-weight="700">'
        f'ATT&amp;CK Coverage — {len(counts)} techniques, {sum(counts.values())} rules</text>',
    ]
    for ci, tac in enumerate(used_tactics):
        x = pad + ci * (col_w + gap)
        y0 = pad + 30
        parts.append(
            f'<rect x="{x}" y="{y0}" width="{col_w}" height="{head_h-10}" rx="4" fill="#1c2436"/>'
        )
        label = TACTIC_LABEL[tac]
        parts.append(
            f'<text x="{x+col_w/2}" y="{y0+18}" fill="#8fb3ff" font-size="12" '
            f'font-weight="700" text-anchor="middle">{esc(label)}</text>'
        )
        parts.append(
            f'<text x="{x+col_w/2}" y="{y0+34}" fill="#5f7599" font-size="10" '
            f'text-anchor="middle">{len(by_tactic[tac])} technique(s)</text>'
        )
        for ri, tid in enumerate(sorted(by_tactic[tac])):
            cy = y0 + head_h + ri * (cell_h + gap)
            n = counts[tid]
            name = TACTIC_OF.get(tid, ("", tid))[1]
            parts.append(
                f'<rect x="{x}" y="{cy}" width="{col_w}" height="{cell_h}" rx="4" '
                f'fill="{color_for(n)}"/>'
            )
            parts.append(
                f'<text x="{x+8}" y="{cy+14}" fill="#0f1420" font-size="11" '
                f'font-weight="700">{esc(tid)}</text>'
            )
            parts.append(
                f'<text x="{x+8}" y="{cy+27}" fill="#0f1420" font-size="9">'
                f'{esc(name[:26])}</text>'
            )
    parts.append('</svg>')
    out = REPO / "docs" / "coverage_heatmap.svg"
    out.write_text("\n".join(parts) + "\n", encoding="utf-8", newline="\n")
    return out


def write_summary(counts, levels, rule_names):
    lines = ["# ATT&CK Coverage Summary", "",
             f"**{len(counts)} techniques** across "
             f"**{len({TACTIC_OF.get(t, ('?',))[0] for t in counts})} tactics**, "
             f"**{sum(counts.values())} rules**.", "",
             "| Tactic | Technique | Name | Rules | Level |",
             "|---|---|---|---|---|"]
    for tid in sorted(counts, key=lambda t: (TACTIC_ORDER.index(TACTIC_OF.get(t, ('execution',))[0]), t)):
        tac, name = TACTIC_OF.get(tid, ("?", tid))
        lines.append(f"| {TACTIC_LABEL.get(tac, tac)} | {tid} | {name} | "
                     f"{counts[tid]} | {levels[tid]} |")
    out = REPO / "docs" / "coverage_summary.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return out


def main():
    counts, levels, rule_names = collect()
    nav = write_navigator(counts, rule_names)
    svg = write_svg(counts)
    summ = write_summary(counts, levels, rule_names)
    print(f"Techniques: {len(counts)}  Rules: {sum(counts.values())}")
    for p in (nav, svg, summ):
        print(f"  wrote {p.relative_to(REPO)}")


if __name__ == "__main__":
    main()
