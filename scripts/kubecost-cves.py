#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "rich>=14.0.0",
# ]
# ///

"""
Count HIGH/CRITICAL CVEs per image in the Kubecost Helm chart, split by base image (OS
packages) vs. language binaries/packages (gobinary, python-pkg, jar, ...).

Unknown args are passed to `helm template`, e.g.:
    ./scripts/kubecost-cves.py --version 3.1.0
    ./scripts/kubecost-cves.py --version 3.1.0 -o json > cves.json
"""

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict

from rich.box import Box
from rich.console import Console
from rich.table import Table
from rich.text import Text

console = Console()
err_console = Console(stderr=True)
SEVERITIES = ("CRITICAL", "HIGH")
# box.ROUNDED with a heavy top edge that doubles as the title bar's bottom.
TABLE_BOX = Box("┡━┯┩\n│ ││\n├─┼┤\n│ ││\n├─┼┤\n├─┼┤\n│ ││\n╰─┴╯\n")


def chart_images(helm_args: list[str]) -> tuple[str, list[str]]:
    """Return (chart version, unique images) from the rendered chart."""
    rendered = subprocess.run(
        [
            "helm",
            "template",
            "kubecost-ga",
            "--repo",
            "https://kubecost.github.io/kubecost",
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


def render(results: dict[str, dict], version: str, ignore_unfixed: bool) -> None:
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
    args, helm_args = parser.parse_known_args()

    try:
        version, images = chart_images(helm_args)
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
        render(results, version, args.ignore_unfixed)
    return 1 if any("error" in r for r in results.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
