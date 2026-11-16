#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "rich>=15.0.0",
# ]
# ///

"""
Count HIGH/CRITICAL CVEs per image in the Kubecost Helm chart, split by base image (OS
packages) vs. language binaries/packages (gobinary, python-pkg, jar, ...).

Unknown args are passed to `helm template`, e.g.:
    ./scripts/kubecost-cves.py --version 3.1.0
    ./scripts/kubecost-cves.py --version 3.1.0 -o json > cves.json
    ./scripts/kubecost-cves.py --nightly   # latest nightly chart
"""

import argparse
import io
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

from rich.box import Box
from rich.console import Console
from rich.table import Table
from rich.text import Text

console = Console()
err_console = Console(stderr=True)
SEVERITIES = ("CRITICAL", "HIGH")
# box.ROUNDED with a heavy top edge that doubles as the title bar's bottom.
TABLE_BOX = Box("┡━┯┩\n│ ││\n├─┼┤\n│ ││\n├─┼┤\n├─┼┤\n│ ││\n╰─┴╯\n")


GA_REPO = "https://kubecost.github.io/kubecost"
NIGHTLY_REPO = "https://kubecost.github.io/nightly-helm-chart"


def chart_images(helm_args: list[str], repo: str) -> tuple[str, list[str]]:
    """Return (chart version, unique images) from the rendered chart."""
    rendered = subprocess.run(
        [
            "helm",
            "template",
            "kubecost-ga",
            "--repo",
            repo,
            "kubecost",
            *helm_args,
            "--skip-tests",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    images = subprocess.run(
        ["yq", "-r", ".. | .image? | select(. != null)"],
        input=rendered,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    version = re.search(r"helm\.sh/chart: kubecost-(\S+)", rendered)
    return version.group(1) if version else "unknown", sorted(
        {
            line.strip()
            for line in images.splitlines()
            if line.strip() and line.strip() != "---"
        }
    )


def scan(image: str, ignore_unfixed: bool) -> dict:
    # --image-src remote: same reason as internal/imageScan (local store export breaks multi-arch indexes)
    cmd = [
        "trivy",
        "image",
        "--quiet",
        "--image-src",
        "remote",
        "-f",
        "json",
        "--severity",
        ",".join(SEVERITIES),
        "--pkg-types",
        "os,library",
        "--scanners",
        "vuln",
        image,
    ]
    if ignore_unfixed:
        cmd.insert(2, "--ignore-unfixed")
    return json.loads(
        subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    )


def summarize(report: dict) -> dict[str, dict[str, int]]:
    """Unique CVE IDs per component: 'base (<os>)' for OS packages, else the trivy package type."""
    ids: dict[str, dict[str, set]] = defaultdict(lambda: {s: set() for s in SEVERITIES})
    for result in report.get("Results") or []:
        component = (
            f"base ({result.get('Type')})"
            if result.get("Class") == "os-pkgs"
            else result.get("Type")
        )
        for vuln in result.get("Vulnerabilities") or []:
            if vuln.get("Severity") in SEVERITIES:
                ids[component][vuln["Severity"]].add(vuln["VulnerabilityID"])
    out = {c: {s: len(v) for s, v in sevs.items()} for c, sevs in ids.items()}
    # Keep the base row first even when clean, so every image shows its OS.
    os_name = (report.get("Metadata") or {}).get("OS", {}).get("Family", "os")
    if not any(c.startswith("base") for c in out):
        out = {f"base ({os_name})": dict.fromkeys(SEVERITIES, 0), **out}
    return dict(
        sorted(out.items(), key=lambda kv: (not kv[0].startswith("base"), kv[0]))
    )


def render(
    console: Console, results: dict[str, dict], version: str, ignore_unfixed: bool
) -> None:
    scope = "showing fixable only" if ignore_unfixed else "showing all CVEs"
    title = (
        f"[bold white]Kubecost [bold cyan]{version}[/bold cyan] - "
        f"[bold magenta]trivy report[/bold magenta] [yellow]({scope})[/yellow][/bold white]"
    )
    table = Table(
        box=TABLE_BOX,
        header_style="bold blue",
        border_style="bright_blue",
    )
    table.add_column("Image", style="cyan", overflow="fold")
    table.add_column("Component")
    for sev in SEVERITIES:
        table.add_column(sev, justify="right")
    for image, components in results.items():
        if "error" in components:
            table.add_row(image, "[red]scan failed[/red]", "-", "-", end_section=True)
            continue
        items = list(components.items())
        for i, (component, counts) in enumerate(items):
            table.add_row(
                image if i == 0 else "",
                component,
                *(
                    f"[{'bold red' if counts[s] else 'green'}]{counts[s]}[/]"
                    for s in SEVERITIES
                ),
                end_section=i == len(items) - 1,
            )
    # Heavy title bar drawn by hand; the table's top edge (┡━┯┩) closes it, joining the two.
    width = console.measure(table).maximum
    console.print(f"[bright_blue]┏{'━' * (width - 2)}┓[/]")
    title_text = Text.from_markup(title)
    title_text.align("center", width - 2)
    console.print(Text("┃", "bright_blue") + title_text + Text("┃", "bright_blue"))
    console.print(table)


def _icon(components: dict) -> str:
    return "🔴" if any(sum(c.values()) for c in components.values()) else "🟢"


def markdown(results: dict[str, dict], version: str, ignore_unfixed: bool) -> str:
    scope = "fixable only" if ignore_unfixed else "all CVEs"
    lines = [
        f"### Kubecost {version} - trivy report ({scope})",
        "",
        "| Image | Component | CRITICAL | HIGH |",
        "|---|---|--:|--:|",
    ]
    for image, components in results.items():
        if "error" in components:
            lines.append(f"| `{image}` | scan failed | - | - |")
            continue
        for i, (component, counts) in enumerate(components.items()):
            first = f"{_icon(components)} `{image}`" if i == 0 else ""
            lines.append(
                f"| {first} | {component} | {counts['CRITICAL']} | {counts['HIGH']} |"
            )
    return "\n".join(lines) + "\n"


def slack_text(results: dict[str, dict], version: str, ignore_unfixed: bool) -> str:
    """Plain text: the Slack Workflow Builder trigger inserts it without any formatting."""
    scope = "fixable only" if ignore_unfixed else "all CVEs"
    lines = [f"Kubecost {version} - trivy report ({scope})"]
    for image, components in results.items():
        if "error" in components:
            lines.append(f"⚠️ {image}: scan failed")
            continue
        detail = "; ".join(
            f"{c}: {n['CRITICAL']} critical, {n['HIGH']} high"
            for c, n in components.items()
        )
        lines.append(f"{_icon(components)} {image} ({detail})")
    return "\n".join(lines) + "\n"


def save(
    out_dir: Path, results: dict, version: str, ignore_unfixed: bool, name: str
) -> None:
    """Write json, markdown, slack text and an SVG of the Rich table to out_dir/<name>.*"""
    out_dir.mkdir(parents=True, exist_ok=True)
    base = out_dir / name
    base.with_suffix(".json").write_text(json.dumps(results, indent=2))
    base.with_suffix(".md").write_text(markdown(results, version, ignore_unfixed))
    base.with_suffix(".slack.txt").write_text(
        slack_text(results, version, ignore_unfixed)
    )
    # Forced colour so the SVG matches the terminal table even without a TTY (CI).
    svg = Console(
        record=True,
        file=io.StringIO(),
        force_terminal=True,
        color_system="truecolor",
        width=100,
    )
    render(svg, results, version, ignore_unfixed)
    svg.save_svg(str(base.with_suffix(".svg")), title=f"Kubecost {version}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-o", "--output", choices=("table", "json"), default="table")
    parser.add_argument(
        "--ignore-unfixed",
        action="store_true",
        help="Only count CVEs with a fix available.",
    )
    parser.add_argument(
        "--nightly",
        action="store_true",
        help=f"Use the nightly chart repo ({NIGHTLY_REPO}) instead of GA.",
    )
    parser.add_argument(
        "--save",
        type=Path,
        metavar="DIR",
        help="Also write DIR/{ga,nightly}.{json,md,slack.txt,svg}.",
    )
    args, helm_args = parser.parse_known_args()

    try:
        version, images = chart_images(
            helm_args, NIGHTLY_REPO if args.nightly else GA_REPO
        )
    except subprocess.CalledProcessError as exc:
        err_console.print(f"[bold red]helm/yq failed:[/bold red] {exc.stderr}")
        return 1

    results: dict[str, dict] = {}
    with err_console.status("") as status:
        for n, image in enumerate(images, 1):
            status.update(f"Scanning {n}/{len(images)}: {image}")
            try:
                results[image] = summarize(scan(image, args.ignore_unfixed))
            except subprocess.CalledProcessError as exc:
                err_console.print(
                    f"[red]trivy failed for {image}:[/red] {exc.stderr.strip()[-500:]}"
                )
                results[image] = {"error": exc.stderr.strip()}

    if args.output == "json":
        print(json.dumps(results, indent=2))
    else:
        render(console, results, version, args.ignore_unfixed)
    if args.save:
        save(
            args.save,
            results,
            version,
            args.ignore_unfixed,
            "nightly" if args.nightly else "ga",
        )
    return 1 if any("error" in r for r in results.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
