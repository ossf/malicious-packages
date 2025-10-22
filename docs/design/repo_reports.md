# Git based Malicious Reports

- Author: calebbrown
- Last Updated: 2025-10-03
- Status: Draft

## Objective

Design documenting how the Malicious Packages repository will support Git based malicious repositories.

## Background

### Use case

Not all malicious open source software is distributed through artifact based registries like NPM and PyPI. Source repositories are often used to develop and host malicious software.

Additionally, some ecosystems, such as C and C++, do not have a well defined centralized artifact repository and package manager. Instead they depend on more ad hoc techniques for associating dependencies, such as subrepositories, or vendoring.

Finally, malicious code in source repositories can find its way into packages across multiple open source repositories and ecosystems.

A classic example of this is the XZ Utils attack. While part of the attack used a build script external to the source repository (`m4/build-to-host.m4`), test files containing malicious payloads were submitted to the repository, along with other minor changes that enabled the attack.

### Why the Malicious Packages repo?

Historically the Malicious Packages repository has been focused on artifacts uploaded to public open source package repositories. The name "malicious packages" embodies this.

There are a few key reasons why malicious source repositories belong in the Malicious Packages repository.

Firstly, having malicious repository reports in the Malicious Packages repository maintains a clear single source for these reports. This helps both consumers and producers of reports as they have a single origin.

Secondly, keeping them together avoids fragmenting the OSV ID "MAL" prefix space. If the malicious repository reports were in a new repository would likely need a separate ID prefix. By keeping the "MAL" prefix across all reports consumers can clearly identify malicious from vulnerability reports.

Finally, keeping all the malicious reports together makes it easier to manage the tool and automation needed to manage the data set.

Combining all package and repository based malicious reports is not without its drawbacks either. There is the potential for additional confusion, the tooling becomes more complex, and the rules around what is considered to be malicious need to be slightly different between package and repository based reports.

### OSV for Git Repositories

The [OSV schema](https://ossf.github.io/osv-schema) has support for Git repositories. This support is not through the `package` field in the `affected` object. The `package` field is largely for supporting artifact or package based registries.

Git support is instead achieved through the `ranges` field in the `affected` object. For example ([src](https://storage.googleapis.com/cve-osv-conversion/osv-output/CVE-2024-52279.json)):

```json
{
 "affected": [
    {
      "ranges": [
        {
          "type": "GIT",
          "events": [
            {
              "introduced": "4419b4deeac67c0c7a1aeff388fa18ad6a086ddf"
            },
            {
              "fixed": "9e0fcc7b8ea48167be3e71d135378a934e3f4b25"
            }
          ],
          "repo": "https://github.com/apache/zeppelin"
        }
      ]
    }
  ]
}
```

Each `range` object must have `"type": "GIT"` and the `"repo"` field must contain the URL to the Git repository. Finally each entry in `"events"` should refer to a commit ID hash (unless it is `"introduced": "0"`).

### Existing Tooling Implementation

Current tooling for the Malicious Packages repository only supports packages published to ecosystems supported by the `.affected[0].package` object.

Currently one and only one `package` *must* be present, with an appropriate `name` and `ecosystem`. If a pURL is present it must match the `name` and `ecosystem`.

The `name` and `ecosystem` are used to define the directory structure organizing the OSV reports.

Finally, the tooling is used to validate the repository and while ingesting, to ensure the reports are valid and remain valid.

## Design

### OSV Usage Changes

The primary change is to make `.affected[0].package` optional for Malicious Package reports. This is because source repositories do not have a package, and the field is optional for OSV.

If `.affected[0].package` is not present then the following rules apply for Git based repositories.

* `.affected[0].versions` must not be present.  
* `.affected[0].ranges` must have at least one entry.  
* For each `range` entry:  
  * It must have `type: "GIT"`.  
  * It must have the `repo` field populated with the specific Git repository, and must equal the `repo` field in every other entry.  
  * There must be a plausible commit ID present in the range. `"introduced": "0"` is to be avoided for repositories as name recycling is possible on services like GitHub. However, if the repository has been pulled, the repository name is sufficiently distinct, and no data is available, `"introduced": "0"` may be considered acceptable.

### Repo Canonicalization

Canonicalizing a git URL is non-trivial. Git supports both scp-like repository names (e.g. `git@host:path.git`) and URL repository names (e.g. `ssh://git@host/path.git`).

Furthermore, popular git hosting services like GitHub, GitLab, etc support both HTTPS and SSH based transports. This means that multiple repository names can point to the same repository. For example `https://github.com/org/repo.git`, `ssh://git@github.com/org/repo.git` and `git@github.com:org/repo.git` all refer to the same repository.

To handle this scenario git URLs will need to be canonicalized as best as possible to ensure reports can be merged successfully.

For common Git hosting services this will involve transforming repository names to https-based Git URLs. Organization/user and repository names will be lowercased to avoid case-sensitivity issues.

For less-common Git-based hosting services, repositories will only be converted to a URL style repository naming structure, from scp-like SSH  names.

It is expected that issues around the canonicalization of less-common Git-based hosting services will be infrequent, as attackers tend to favour popular services.

### Directory Structure

Basic structure:

* `osv/malicious/git/github.com/org/repo/MAL-2025-00001.json`

The `git` directory is a pseudo ecosystem used to group all Git source repository based reports together.

The directory following contains a canonicalized git URL without the scheme (e.g. "https://" or "git://") and without any ".git" suffix.

#### Case handling

Currently Malicious Packages does not handle ecosystems that have case sensitive package names (i.e. NPM, Go) when creating directories. Presently this is not a problem as there are no cases where two malicious packages have a package name that differs only by letter case.

The delay in introducing strong support for casing is due to the need for Malicious Package paths to work on case-insensitive file systems (e.g. macos).

This is a potential problem for Git based repository support, however the majority of Git repositories are hosted on GitHub and GitLab whose repository URLs are case insensitive (even if paths within the repositories are not).

Since this is the case, case handling will continue to be deferred until there is a requirement for it.

### Ingestion and Merging Behavior

Source repository report ingestion and merging should work without modification. The directory structure and OSV validation ensures that only repository reports are merged with repository reports.

### Malicious Definition

Malicious repositories differ from malicious packages, and as a result require additional detail defining what repo reports are acceptable for the Malicious Packages repository.

#### Intended Use

The intended malicious repositories for inclusion are those that attack or compromise maintainers or users of the source repository and its contents, as part of the normal documented use and development of the repository.

#### Less Junk

Since GitHub makes it easy to create a source repository, there are many repositories with few commits and no content. Junk packages have been tolerated in Malicious Packages for pragmatism, but for repositories a higher bar should exist to avoid reports proliferating.

#### Forking Problem

Forking on GitHub is easy. Forking is also how contributors prepare pull requests. This is great for open source, but problematic for tracking malicious repositories.

Forks of malicious repositories intended to preserve or proliferate a malicious repository are suitable for inclusion.

To avoid excessive reports, forks that are purely for developing and preparing pull requests should be excluded. There is often clear evidence that a fork is for development based on pull requests, merges from the upstream repository, and the fork's owner being a principal committer.

#### PoC, Hacking Tools, etc

Attack proof-of-concepts and offensive hacking tools are frequently created using repositories hosted on shared git repository hosting services. If the repositories are clear in this intention then, they do not belong in the Malicious Packages repository.

However it is also [common for attackers](https://www.vulncheck.com/blog/fake-repos-deliver-malicious-implant) to hide malicious payloads in proof-of-concept repositories, etc. Repositories which hide malicious payloads attacking security researchers are suitable for inclusion.

### Source Based Package Managers and Complimentary Reports

Some ecosystems are built around source-based package management tools. Popular examples include Go, Composer/Packagist, and Swift.

Since these are source based, a malicious package report for one of these ecosystems could be represented as both a normal ecosystem based report, or as a Git repository based report.

From a consumer's perspective it should not matter whether they are attempting to locate a malicious report by its package name, or by its Git repository.

Ideally, any malicious repo report for one of these ecosystems, *should* be accompanied by a corresponding malicious package report (and visa-versa).

However, ensuring complimentary reports are published in the repository is considered beyond the scope of this design. Contributors can be encouraged to submit both reports, but making this a harder requirement becomes challenging, particularly when refs are mutated, repositories are removed or force pushed, or commits are orphaned.