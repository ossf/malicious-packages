# Purpose

This document explains how to **consume** the OpenSSF Malicious Packages
dataset to protect your projects: scanning a codebase for known malware with
[osv-scanner](https://google.github.io/osv-scanner/), querying
[osv.dev](https://osv.dev) directly, using the raw reports offline, and wiring
detection into CI and [Renovate](https://docs.renovatebot.com/).

If you instead want to *contribute* reports, see the
[Contributing Guide](../CONTRIBUTING.md).

# Background

Every report in this repository is an [OSV Schema](https://ossf.github.io/osv-schema/)
record describing a malicious package published to an open source registry
(npm, PyPI, RubyGems, NuGet, Go, crates.io, Maven, Packagist, VS Code
Marketplace / Open VSX, and others).

A few properties of the data are worth knowing before you consume it:

- Reports live under `./osv/malicious/[ecosystem]/[package_name]/` as
  `MAL-YYYY-NNNN.json` files. `[package_name]` is the *package* name, so a few
  of those directories are themselves named `something.json` — see the warning
  under [With the raw JSON reports](#with-the-raw-json-reports).
- Every record carries a `MAL-` id. Some records — those imported from sources
  that supply it — are additionally tagged with
  [CWE-506 (Embedded Malicious Code)](https://cwe.mitre.org/data/definitions/506.html)
  under `affected[].database_specific.cwes`, but most are not, so do not build a
  gate that requires the CWE to be present.
- Reports later found to be false positives are **withdrawn** — moved to
  `./osv/withdrawn/` and given a `withdrawn` timestamp — rather than deleted.
  Consumers should treat withdrawn records as non-malicious.
- `./osv/unmergable/` holds reports that could not be assigned an id (their `id`
  field is the empty string). They are not part of the dataset you want to
  consume; skip that directory too.
- This dataset is ingested by [osv.dev](https://osv.dev), so any tool backed by
  the osv.dev database surfaces these reports. `osv-scanner` picks them up with
  no extra configuration; Renovate needs `osvVulnerabilityAlerts` turned on
  (see [below](#wiring-detection-into-renovate)).

Because a malicious package implies full compromise of any machine it ran on, a
match should be treated as an **incident**, not a routine upgrade. See
[Responding to a match](#responding-to-a-match) below.

# Option 1: Scan a project with osv-scanner (recommended)

[osv-scanner](https://google.github.io/osv-scanner/) is the official OSV
frontend. It resolves your project's dependencies and queries osv.dev, which
includes this dataset, so `MAL-` advisories for any package you depend on are
reported alongside ordinary vulnerabilities.

Install it (see the
[installation guide](https://google.github.io/osv-scanner/installation/) for
all options):

```shell
# Go toolchain
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest

# or Homebrew
brew install osv-scanner
```

Scan a project directory recursively (osv-scanner discovers lockfiles such as
`package-lock.json`, `poetry.lock`, `Cargo.lock`, `go.mod`, etc.):

```shell
osv-scanner scan source --recursive ./
```

Scan a single lockfile:

```shell
osv-scanner scan source --lockfile package-lock.json
```

A match against this dataset appears as a `MAL-` id in the results, for example:

```
Total 1 package affected by 1 known vulnerability (0 Critical, 0 High, 0 Medium, 0 Low, 1 Unknown) from 1 ecosystem.
0 vulnerabilities can be fixed.

+-------------------------------+------+-----------+----------------+---------+---------------+-------------------+
| OSV URL                       | CVSS | ECOSYSTEM | PACKAGE        | VERSION | FIXED VERSION | SOURCE            |
+-------------------------------+------+-----------+----------------+---------+---------------+-------------------+
| https://osv.dev/MAL-2022-6113 |      | npm       | shubholic-test | 1.0.0   | --            | package-lock.json |
+-------------------------------+------+-----------+----------------+---------+---------------+-------------------+
```

Malicious package reports carry no CVSS score and no fixed version, so those
columns stay empty — the remediation is removal, not an upgrade.

osv-scanner exits `1` when it finds anything; a `MAL-` id in that output means a
known-malicious package is in your dependency tree — stop and triage before
proceeding.

# Option 2: Query osv.dev directly

The [osv.dev API](https://google.github.io/osv.dev/api/) is useful for
ad-hoc checks and for building your own tooling.

Check a specific package version:

```shell
curl -s -X POST https://api.osv.dev/v1/query \
  -d '{"package": {"ecosystem": "npm", "name": "shubholic-test"}, "version": "1.0.0"}'
```

Look up a single report by id:

```shell
curl -s https://api.osv.dev/v1/vulns/MAL-2022-6113
```

Check many packages in one request with the batch endpoint:

```shell
curl -s -X POST https://api.osv.dev/v1/querybatch -d '{
  "queries": [
    {"package": {"ecosystem": "npm", "name": "shubholic-test"}},
    {"package": {"ecosystem": "PyPI", "name": "some-package"}}
  ]
}'
```

A response containing a vuln whose `id` starts with `MAL-` indicates a match in
this dataset.

# Option 3: Use the raw dataset offline

For air-gapped environments, custom allow/deny tooling, or bulk analysis, you
can consume the data without calling osv.dev at scan time.

## With osv-scanner's local database

If the machine can reach the network once, this is the simplest offline path —
osv-scanner downloads the OSV databases (which include this dataset) and then
matches against them locally:

```shell
# One-time (or periodic) download into ./osv-db
osv-scanner scan source --offline-vulnerabilities --download-offline-databases \
  --local-db-path ./osv-db --lockfile package-lock.json

# Subsequent runs, fully offline
osv-scanner scan source --offline-vulnerabilities \
  --local-db-path ./osv-db --lockfile package-lock.json
```

See the [offline mode
docs](https://google.github.io/osv-scanner/usage/offline-mode/) for details.
Re-run the download periodically — the local copy is only as fresh as its last
fetch.

## With the raw JSON reports

If you need the reports themselves — to build a denylist, feed another system,
or do bulk analysis — consume them straight from this repository.

Clone the dataset:

```shell
git clone https://github.com/ossf/malicious-packages.git
```

To pull only one ecosystem, use a sparse checkout:

```shell
git clone --filter=blob:none --sparse https://github.com/ossf/malicious-packages.git
cd malicious-packages
git sparse-checkout set osv/malicious/npm
```

Build a denylist of all known-malicious package names for an ecosystem (requires
[jq](https://jqlang.github.io/jq/)):

```shell
find osv/malicious/npm -type f -name '*.json' \
  -exec jq -r '.affected[].package.name' {} + | sort -u > npm-malicious.txt
```

`-type f` is not optional. Some malicious packages are themselves named
`*.json` (on npm today: `packages.json`, `packages-lock.json`, `pattern.json`,
`ethers.json`, and others), so their report *directories* also match
`-name '*.json'`. Without `-type f`, `jq` aborts on `Is a directory` partway
through a batch and you silently get a short denylist.

Check whether a specific package is reported, including the matching `MAL-` ids:

```shell
grep -rl '"name": "shubholic-test"' osv/malicious/npm/ \
  | xargs -I{} jq -r '.id' {}
```

When building your own gate, restrict yourself to `osv/malicious/` — that
excludes both withdrawn (false-positive) records under `osv/withdrawn/` and
un-assigned reports under `osv/unmergable/`. The repository is the source of
truth, but it is updated continuously — re-pull regularly so your local copy
does not go stale. Current report totals are published at
[ossf.github.io/malicious-packages/stats](https://ossf.github.io/malicious-packages/stats/).

# Wiring detection into CI

Run osv-scanner on every push and pull request with the official GitHub Action.
The reusable workflow below fails the build if any known vulnerability or
malicious package is found in the dependency tree:

```yaml
# .github/workflows/osv-scanner.yml
name: OSV-Scanner

on:
  pull_request:
  push:
    branches: [main]

permissions:
  # Required to upload the SARIF file to code scanning.
  # See https://github.com/github/codeql-action/issues/2117
  actions: read
  contents: read
  security-events: write

jobs:
  scan:
    uses: google/osv-scanner-action/.github/workflows/osv-scanner-reusable.yml@v2.5.1
    with:
      scan-args: |-
        --recursive
        ./
```

See the [osv-scanner GitHub Action
docs](https://google.github.io/osv-scanner/github-action/) for SARIF upload,
scheduled scans, and pinning the action to a commit SHA.

For other CI systems, run `osv-scanner scan source --recursive ./` as a build
step and gate on its exit code.

# Wiring detection into Renovate

[Renovate](https://docs.renovatebot.com/) can source security data from OSV,
which includes this dataset. With `osvVulnerabilityAlerts` enabled, Renovate
downloads the OSV database locally and, when it sees a malicious package, warns
in its logs and refuses to raise the update — an available update found to be
malicious is skipped and marked `skipReason: malicious-update-proposed`.

Two limits are worth knowing before you rely on this: OSV-based alerts cover
**direct dependencies only**, and only these datasources — `crate`, `go`,
`hackage`, `hex`, `maven`, `npm`, `nuget`, `packagist`, `pypi`, `rubygems`.
Renovate also flags `osvVulnerabilityAlerts` as experimental, so treat it as a
second layer behind an osv-scanner CI gate rather than as your only control.

Add to your `renovate.json`:

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:recommended"],
  "osvVulnerabilityAlerts": true,
  "vulnerabilityAlerts": {
    "enabled": true
  }
}
```

See the Renovate documentation for
[`osvVulnerabilityAlerts`](https://docs.renovatebot.com/configuration-options/#osvvulnerabilityalerts)
and
[`vulnerabilityAlerts`](https://docs.renovatebot.com/configuration-options/#vulnerabilityalerts).

# Responding to a match

Treat a match as a security incident, not a dependency bump. Per the guidance
embedded in the reports themselves: any machine that installed or ran a
malicious package should be considered fully compromised. At a minimum:

1. Remove the package and pin to a known-good version (or remove the dependency
   entirely).
2. Rotate every secret, token, and key that was accessible from the affected
   machine, from a *different*, trusted machine.
3. Review build, CI, and developer-machine logs for exfiltration or follow-on
   activity.

If you believe a flagged package is **not** malicious, see
[False Positives](../README.md#false-positives) in the README for how to report
it; withdrawn reports are moved to `./osv/withdrawn/` and should be ignored by
consumers.
