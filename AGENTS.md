# Repository Guidelines

## Project Structure & Module Organization

Helmscan is a Go CLI for scanning container images and comparing Helm chart vulnerabilities. `cmd/helmscan/main.go` handles arguments and orchestration. Internal packages separate chart operations (`internal/helmscan`), scanner execution (`internal/imageScan`), shared types (`internal/helmScanTypes`), and Markdown/JSON reporting (`internal/reports`).

`scripts/weekly-report.sh` produces Kubecost comparison reports. `scripts/kubecost-cves.py` is a standalone one-off (not part of the Go CLI) that counts HIGH/CRITICAL CVEs per Kubecost chart image; see below. `.github/workflows/` contains release and weekly-scan automation; `.goreleaser.yaml` configures release packaging, and `helmscan.rb` defines the Homebrew formula. Generated scans live under `working-files/`; release artifacts go under `dist/`.

## Build, Test, and Development Commands

Use Go 1.26, matching `go.mod` and release CI.

- `make build`: build `./helmscan` with version linker flags.
- `go test -v ./...`: run package tests, matching CI.
- `go vet ./...`: check Go code for common mistakes.
- `go run ./cmd/helmscan --report docker.io/library/ubuntu:22.04`: run a local image scan.
- `make build-all`: build the platform targets listed in the Makefile.
- `make snapshot`: create local GoReleaser packages without publishing.

Install Trivy for default scans or Grype for `--scanner grype`. Chart and automation workflows also use Helm, yq, and jq. Live scans require registry and vulnerability-database access.

### `scripts/kubecost-cves.py`

A PEP 723 script run with `uv` (dependencies are declared inline; only `rich`). It needs `helm`, `yq`, and `trivy` on `PATH`.

- `./scripts/kubecost-cves.py`: latest chart, Rich table.
- `./scripts/kubecost-cves.py --version 3.3.1 -o json`: pinned chart version, JSON to stdout.
- `./scripts/kubecost-cves.py --ignore-unfixed`: count only CVEs that have a fix.

How it works:

- **Arguments:** any arguments the script doesn't recognize go straight to `helm template kubecost-ga --repo https://kubecost.github.io/kubecost kubecost ... --skip-tests`. Images are extracted with `yq '.. | .image?'`. The chart version in the title comes from the rendered `helm.sh/chart: kubecost-X` label.
- **Scanning:** each image is scanned one at a time with `trivy image --image-src remote --severity CRITICAL,HIGH --pkg-types os,library --scanners vuln`, the same `--image-src remote` reasoning as `internal/imageScan`. Scans are sequential because concurrent Trivy processes contend for the cache lock.
- **Counting:** counts are unique CVE IDs per image and component. Trivy `os-pkgs` results become `base (<os>)`, and `lang-pkgs` results keep their Trivy type (`gobinary`, `python-pkg`, `jar`, ...). Every image gets a base row, even when it is clean.
- **Output:** progress and errors go to stderr, so JSON on stdout is safe to pipe. The script exits 1 if helm/yq fails or any image scan fails; a failed image shows as `scan failed` in the table and as `{"error": ...}` in the JSON.
- **Table layout:** the hand-drawn heavy title bar joins the table through the custom `TABLE_BOX` top edge (`┡━┯┩`). Keep the two in sync if you change the box style.

Format with `uvx ruff format scripts/kubecost-cves.py` and check with `uvx ruff check scripts/kubecost-cves.py`.

## Coding Style & Naming Conventions

Format changed Go files with `gofmt`; use standard Go tab indentation, exported `PascalCase` identifiers, and unexported `camelCase` identifiers. Preserve existing package names such as `imageScan`. Keep scanner parsing separate from report formatting. No dedicated lint configuration is tracked.

## Testing Guidelines

No tests or coverage threshold are currently tracked. Add standard-library `testing` tests in adjacent `*_test.go` files, named `TestXxx`. Favor deterministic fixtures for scanner JSON parsing, severity aggregation, and comparison logic. For live validation, exercise the affected scanner and inspect generated reports; record prerequisites and results in the PR.

## Commit & Pull Request Guidelines

History uses short, descriptive subjects such as `Add grype scanner, use it weekly (#15)`; no uniform Conventional Commits scheme is established. Use focused commits. PRs should explain the behavior change, link relevant issues, and list validation results. Include sample Markdown/JSON output when reporting changes.

## Configuration & Agent Instructions

Keep credentials and Slack webhook URLs out of commits. The weekly script deletes `out/` and `working-files/scans/` before generating reports. Verify guidance against 2026 tooling and use maintained libraries for new code. After significant work, end with concise outcome and validation bullets; label the last bullet **Things you should know** and state review items or that none remain.
