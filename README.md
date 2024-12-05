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

While some protection can be found through various security solutions, there is
no comprehensive database of malicious packages published to
open source package repositories.

### Objective

The aim of this project and repository is to be a comprehensive, high quality,
open source database of reports of malicious packages published on open source
package repositories.

These public reports help protect the open source community, and provide a data
source for the security community to improve their ability to find and detect
new open source malware.

## Scope

What is in scope?

- any package that belongs to an ecosystem supported by the
  [OSV Schema](https://ossf.github.io/osv-schema/)
- malicious packages published under typosquatting type attacks
- malicious packages published through account takeover
- malicious prebuilt binaries downloaded or installed with a package
- security researcher activity
- dependency and manifest confusion

Borderline:

- typosquatting, or spam packages that are empty or trivial, while not
  malicious, are allowed to be present in the dataset

Out-of-scope:

- non-malicious packages
- vulnerability reports
- compromised infrastructure
- offensive security tools, unless they execute malicious payloads on install

## Definition of a Malicious Package

Below is the definition of what this repository considers a malicious package.

- a package publicly available in a package registry
- and either:
  - when installed or used, would require some sort of incident response due to
    the loss of confidentiality, availability and/or integrity; or
  - exfiltrates an identifier that can be directly used to launch a subsequent 
    attack against the victim (e.g. username for phishing or password
    bruteforcing)
- and also either:
  - violates the terms of the package registry; or
  - would be reasonably considered to require removal from the package registry

### Dependency and manifest confusion

[Dependency confusion](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)
and [manifest confusion](https://blog.vlt.sh/blog/the-massive-hole-in-the-npm-ecosystem)
are techniques that exploit quirks in the behavior of package systems and how
they are used within organizations. Packages using these attacks are malicious.

Very occasionally someone may unintentionally encounter these quirks, but
this is considered infrequent.

Manifest confusion requires someone to bypass the NPM command line tool and
deliberately provide an altered manifest.

Dependency confusion are effectively the same as an account takeover where an
attacker replaces a package's code with their own. This means even trivial or
empty dependency confusion packages would require incident response.

### Spam and typosquating

Spam, typosquatting are not malicious, unless the package itself exhibits
malicious behavior as-per the definition above.

These types of packages are often empty (i.e. no functional code), or consist of
only useless trivial functionality (e.g. printing a message). While these
packages are not malicious, they are a nuisance and generally unwanted.

Typosquatting packages may be hard to distinguish from dependency confusion. As
a result, these reports are allowed to be present in the malicious packages
repository.

### Reverse engineering protection (e.g. obfuscation)

Reverse engineering protections are not malicious, unless it exhibits malicious
behavior as-per the definition above.

Obfuscation, debugger evasion, and other reverse engineering protection
techniques, are used by both developers seeking to protect their source code
and attackers seeking to evade detection.

### Telemetry

Telemetry, on its own, is not malicious.

Many open source packages use telemetry to track installs or the behavior and
performance of the package.

However, if telemetry is abused to exfiltrate and steal sensitive data, or
provide remote access, this can be considered malicious.

### Protestware

Protestware is not malicious if it does not affect the availability, integrity
or confidentiality of the systems the package is run on. For example, a message
logged to a console may be annoying to a developer, but is not malicious.

However, protestware that destroys files, slows performance, or otherwise
affects availability, integrity or confidentiality as part of the protest may be
considered malicious.

### Offensive Security Tools

Offensive security tools, libraries, hacking tools, etc are not malicious.

While an offensive security tool being discovered in an environment may
indicate the presence of compromise, the package itself is not itself malicious.

These packages don't necessarily violate the terms of the registries hosting
them, and are often used by security researchers.

However, offensive security tools that execute malicious payloads during
installation are considered malicious packages.

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
- Any relevant links.

We will then either:

- Move the entire report into the `./osv/withdrawn/` directory and add the
  `withdrawn` time to the report - if the whole report is a false positive.
- Move the affected versions into a `database_specific` array
  indicating that which versions were false positives - if
  some versions are malicious and some are false positives.

Finally, reports that have been added to the malicious packages repository will
not be removed.

**Note:** support for handling false positives is TBC.

## Prior and Related Work

- GitHub's [Advisory Database (filtered by malware)](https://github.com/advisories?query=type%3Amalware), for the NPM ecosystem.
- https://github.com/lxyeternal/pypi_malregistry (PyPI)
- https://dasfreak.github.io/Backstabbers-Knife-Collection/ (PyPI and npm), by Marc Ohm et al.
- https://github.com/datadog/malicious-software-packages-dataset (PyPI), by Datadog

## Governance

This work is associated with the
[Package Analysis project](https://github.com/ossf/package-analysis).

This project belongs to the [Securing Critical Projects Working Group](https://github.com/ossf/wg-securing-critical-projects) in the [OpenSSF](https://openssf.org/) ([Slack](https://openssf.slack.com/archives/wg_securing_critical_projects)).

The working group's [CHARTER.md](https://github.com/ossf/wg-securing-critical-projects/blob/main/CHARTER.md)
outlines the scope and governance of our group activities.
