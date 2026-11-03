# Purpose

This document explains how the OpenSSF Malicious Packages project handles
[dependency confusion](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)
reports and addresses "false positive" issues raised by owners of similarly
named internal or private packages.

# Scope and Stance

- **Public Registries Only:** All reports in this repository apply strictly to
   packages published on **public package registries** (e.g., npm, PyPI,
   Crates.io). They do not apply to packages published to private or internal
   registries (e.g. Artifactory, internal mirrors).
- **Dependency Confusion Packages Are Malicious:** A package published to a
   public registry to exploit dependency confusion is equivalent to an
   unauthorized actor replacing an organization's code with their own. These
   packages meet our
   [definition of a malicious package](../README.md#definition-of-a-malicious-package)
   and belong in this database.
- **Behavior Over Intent:** Our priority is to evaluate packages on their
   behavior, not the author's intent. Packages published during penetration
   tests, bug bounty research, or security probing (such as install-time beacons
   exfiltrating hostnames, usernames, or paths to OAST/collaborator domains) are
   considered malicious and will not be excluded.
- **Permanent Historical Record:** Public registries frequently remove
   malicious packages silently. Reports are intentionally retained to allow
   organizations to determine if they ever installed a compromised public
   version and to provide a historical record for the security community.

# Why "False Positives" Occur

Organizations often report false positives when vulnerability scanners flag
their legitimate internal packages against a `MAL-` advisory. This typically
happens for two reasons:

1. **Scanner Limitations:** Many security scanners match dependencies solely by
   ecosystem and package name without verifying whether the package was resolved
   from a public registry or a private internal registry.
2. **Open-Ended Version Ranges:** Upstream advisory sources
   frequently publish malware advisories with an open-ended range
   (`"introduced": "0"`), marking all versions of the package as affected.
   
When 1 and 2 are combined this results in every internal version of an internal
package being flagged.

> [!IMPORTANT]
> If you encounter a situation where an internally publish package matches a
> report for a malicious public package, please ensure that you have not
> *actually* fallen victim to a dependency confusion attack!
>
> Ensure you are secure from dependency confusion attacks before assuming the
> report is incorrect.

# Policy: Constraining Affected Versions

**We will not delete or withdraw valid dependency confusion reports.**

However, to minimize disruption to projects that mix public and private
packages, *we will constrain reports to only the specific versions that were
published to the public registry.*

By removing open-ended ranges (such as `"introduced": "0"`) and listing only the
explicit malicious versions (e.g., `0.0.1`, `99.99.99`), scanners that evaluate
version numbers will no longer flag legitimate internal versions, while users
who inadvertently pulled the malicious public version remain protected.

# Requesting a Version Constraint

If a dependency confusion report with an open-ended range is flagging your
internal package, please submit a Pull Request (preferred) or open an
[issue](https://github.com/ossf/malicious-packages/issues/new):

1. Identify the affected `MAL-` report(s) in `osv/malicious/`.
2. Remove the open-ended `ranges` block from the top-level `affected` entry and
   ensure `versions` contains only the versions that existed on the public
   registry:

```diff
       "package": {
         "ecosystem": "npm",
         "name": "@example-org/internal-pkg"
       },
-      "ranges": [
-        {
-          "type": "SEMVER",
-          "events": [
-            {
-              "introduced": "0"
-            }
-          ]
-        }
-      ],
       "versions": [
         "99.0.0"
       ]
```

# Important Notes

- **Do not edit `database_specific`:** Leave the
  `database_specific.malicious-packages-origins` section intact. It records the
  unmodified metadata ingested from upstream sources and is required by CI
  validation.
- **Verify Your Environment:** Again, before dismissing an alert as a false
  positive, verify in your lockfiles and build logs that your environment never
  pulled the malicious version from the public registry.