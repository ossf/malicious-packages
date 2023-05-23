# OpenSSF Malicious Packages

This repository is a collection of reports of malicious packages identified in
Open Source package repositories consumable via the
[Open Source Vulnerability (OSV)](https://osv.dev) format.

This project is closely related to the [OpenSSF
Package Analysis project](https://github.com/ossf/package-analysis).

## About

### Background

Attacks against open source ecosystems are gaining popularaity. Typosquating,
dependency confusion, account takeovers, etc are happening more frequently each
year.

While some protection can be found through various security solutions, there
does not exist any comprehensive database of malicious packages published to
open source package repositories.

### Objective

The aim of this project and repository is to be a comprehensive, high quality,
open source database of reports of malicious packages published on open source
package repositories.

These public reports help protect the open source community, and provide a data
source for the security community to improve their ability to find and detect
new open source malware.

### Scope

What is in scope?

- any package that belongs to an ecosystem supported by the [OSV Schema](https://ossf.github.io/osv-schema/)
- malicious packages published under typosquating or dependency confusion type attacks
- malicious packages published through account takeover
- security researcher activity

Out-of-scope:

- vulnerability reports
- compromised infrastructure
- non-malicious packages

### Prior Work

- GitHub's [Advisory Database (filtered by malware)](https://github.com/advisories?query=type%3Amalware), for the NPM ecosystem.

## Get Involved

### Contribute Malicious Package Reports

#### Pull Requests

We accept new reports, and updates to existing reports.

#### Automated Sources (Coming Soon!)

If you regularly produce high-quality, low false positive, detections and
have them accumulating in a database, we can consume them as OSV from a cloud
storage environment (S3, GCS).

### Comms

- Most communication occurs in the [OpenSSF Package Analysis Slack channel](https://openssf.slack.com/archives/package_analysis)
- Official communications occur on the https://lists.openssf.org/g/openssf-wg-securing-crit-prjs mailing list. \
[Manage your subscriptions to Open SSF mailing lists](https://lists.openssf.org/g/main/subgroups).

### Meeting Times

- Every other Thursday @ either an APAC or EMEA friendly time (See [shared calendar](https://calendar.google.com/calendar/u/2?cid=czYzdm9lZmhwNWk5cGZsdGI1cTY3bmdwZXNAZ3JvdXAuY2FsZW5kYXIuZ29vZ2xlLmNvbQ)).
- [Meeting Minutes](https://docs.google.com/document/d/1MIXxadtWsaROpFcJnBtYnQPoyzTCIDhd0IGV8PIV0mQ/edit).

## Governance

This work is associated with the
[Package Analysis project](https://github.com/ossf/package-analysis).

This project belongs to the [Securing Critical Projects Working Group](https://github.com/ossf/wg-securing-critical-projects) in the [OpenSSF](https://openssf.org/) ([Slack](https://openssf.slack.com/archives/wg_securing_critical_projects)).

The working group's [CHARTER.md](https://github.com/ossf/wg-securing-critical-projects/blob/main/CHARTER.md) outlines the scope and governance of our group activities.
