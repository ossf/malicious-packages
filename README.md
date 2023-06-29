# OpenSSF Malicious Packages

This repository is a collection of reports of malicious packages identified in
Open Source package repositories, consumable via the
[Open Source Vulnerability (OSV)](https://osv.dev) format.

This project is closely related to the [OpenSSF
Package Analysis project](https://github.com/ossf/package-analysis).

## About

### Background

Attacks against open source ecosystems are gaining popularity. Typosquatting,
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

- any package that belongs to an ecosystem supported by the
  [OSV Schema](https://ossf.github.io/osv-schema/)
- malicious packages published under typosquatting or dependency
  confusion type attacks
- malicious packages published through account takeover
- prebuilt binaries for a package that are malicious
- security researcher activity

Out-of-scope:

- vulnerability reports
- compromised infrastructure
- non-malicious packages

### Prior Work

- GitHub's [Advisory Database (filtered by malware)](https://github.com/advisories?query=type%3Amalware), for the NPM ecosystem.

## Get Involved

### Contribute Malicious Package Reports

See our [contributing guide](CONTRIBUTING.md) for complete details.

#### OSV reports via Pull Request

We accept new reports, and updates to existing reports.

We will also accept bulk imports via PR (please create an issue first).

#### Automated Sources

If you regularly produce high-quality detections with few
false-positives, and have them accumulating in a database, we can
automatically consume them as OSV from a cloud storage
environment (S3, GCS).

### Comms

- Most communication occurs in the [OpenSSF Package Analysis Slack channel](https://openssf.slack.com/archives/package_analysis)
- Official communications occur on the https://lists.openssf.org/g/openssf-wg-securing-crit-prjs mailing list. \
[Manage your subscriptions to Open SSF mailing lists](https://lists.openssf.org/g/main/subgroups).

### Meeting Times

- Every other Thursday @ either an APAC or EMEA friendly time (See
  [shared calendar](https://calendar.google.com/calendar/u/2?cid=czYzdm9lZmhwNWk5cGZsdGI1cTY3bmdwZXNAZ3JvdXAuY2FsZW5kYXIuZ29vZ2xlLmNvbQ)).
- [Meeting Minutes](https://docs.google.com/document/d/1MIXxadtWsaROpFcJnBtYnQPoyzTCIDhd0IGV8PIV0mQ/edit).

## False Positives

While we do our best to ensure false positives are not present, they may
be present in our dataset from time-to-time.

If you see a non-malicious package is flagged as malicious
[create an issue](https://github.com/ossf/malicious-packages/issues/new).
Please include the following:

- The affected ecosystem and package.
- Which versions are false positives, if specific versions are false
  positives.
- Any relelvant links.

We will then either:

- Move the entire report into the `./withdrawn/` directory and add the
  `withdrawn` time to the report - if the whole report is a false positive.
- Move the affected versions into a `database_specific` array
  indicating that which versions were false positives - if
  some versions are malicious and some are false positives.

**Note:** support for handling false positives is TBC.

## Governance

This work is associated with the
[Package Analysis project](https://github.com/ossf/package-analysis).

This project belongs to the [Securing Critical Projects Working Group](https://github.com/ossf/wg-securing-critical-projects) in the [OpenSSF](https://openssf.org/) ([Slack](https://openssf.slack.com/archives/wg_securing_critical_projects)).

The working group's [CHARTER.md](https://github.com/ossf/wg-securing-critical-projects/blob/main/CHARTER.md)
outlines the scope and governance of our group activities.
