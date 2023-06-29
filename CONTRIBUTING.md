# How to contribute

We'd love to accept your patches and contributions to this project.

## Before you begin

### Review our community guidelines

This project follows
[OpenSSF's Contributor Code of Conduct](CODE_OF_CONDUCT.md).

### Reviews

All submissions, including submissions by project members, require review. We
use GitHub pull requests for this purpose. Consult
[GitHub Help](https://help.github.com/articles/about-pull-requests/) for more
information on using pull requests.

### Setup

Required steps:

1. Create [a GitHub account](https://github.com/join).
1. [Install git](https://help.github.com/articles/set-up-git/) for source control.
1. Clone the repository, e.g:

  ```shell
  git clone git@github.com:ossf/malicious-packages.git
  cd malicious-packages
  ```

Contributing changes will require forking the repository and pushing
your changes to the fork.

Optional:

- [Install Go](https://go.dev/dl/) for code development.
- Install `make` for running development commands.


## Contributing OSV Reports

We accept new reports of malicious packages that are within [scope](README.md#scope),
and updates to any existing report in the database.

**Note:** This process is new and untested, it will change and evolve
over time. We welcome [suggestions](https://github.com/ossf/malicious-packages/issues/new)
on how the process can be improved.

### Via Pull Request

#### New Individual Report

1. If needed, create the directory under `./malicious/` for the report
   to live in.
    - Directories are formatted `[ecosystem]/[package_name]`, with no
      escaping of slashes.
      (e.g. `./malicious/go/github.com/ossf/package-analysis/` or
      `./malicious/npm/@example/package/`).
    - If you're unsure, once the PR is created this will be checked by a
      GitHub action.
1. Create the JSON file with the name `MAL-0000-[name].json`. Where
   `[name]` can be replaced with any arbitrary text.
1. Populate the JSON file conforming to the [OSV Schema](https://ossf.github.io/osv-schema/)
   format and the [notes below](#osv-schema-notes).
1. Commit and push the change to a fork and submit a Pull Request.
    - Please fix any validation errors.

#### Bulk Import

1. [Create an issue](https://github.com/ossf/malicious-packages/issues/new),
   which should include the following:
    - A proposed unique "source id" if you do not already have one.
    - Some details on the reports (i.e. quantity, ecosystems), etc.
1. Use the `ingest` command to copy the reports from a local folder to the
   appropriate locations, and to ensure the origin data is correctly populated.
    - Ensure your OSV reports are in a local directory.
    - From the repo run (requires [Go](https://go.dev/doc/install)):

    ```shell
    go run ./cmd/ingest \
       -config config/config.yaml \
       -dir /path/to/osv \
       -source [source id]
    ```

    - Fix any issues. You will need to revert the repo before running
      ingest again.
1. Commit and push the changes to a form and submit a Pull Request.
    - Reference the issue from step #1 in the PR.
    - Please fix any validation errors, although the `ingest` command
      should avoid these.

### Via Automated Ingestion

#### Requirements

- OSV Reports are available in cloud storage.
  - Currently only AWS S3 and Google Cloud Storage are supported.
  - It must be possible to grant access to the data.
- New reports are frequently added. If not, consider a
  [bulk import PR](#bulk-import).
- Reports have a low false positive rate.
- OSV reports:
  - Are in JSON.
  - Conform to the [notes below](#osv-schema-notes).
- A valid email contact for communication.

#### Process

1. [Create an issue](https://github.com/ossf/malicious-packages/issues/new),
   which should include the following:
    - A proposed unique "source id" if you do not already have one.
    - Some information about the organization/group producticing the
      reports.
    - Some details on the reports (i.e. quantity, ecosystems), etc and
      the frequency of updates.
1. Access to the storage will need to be granted to a service/worker
   account (TBC).
1. The source is added to `config.yaml`.
1. The `ingest` command will be executed regularly to ingest new OSV
   reports (TBC).

### OSV Schema Notes

- `id` - assigned automatically, do not set.
- `summary` - overridden with a standard summary.
- `details` - aggregated together during merge, with one entry per
   source (longest). Only a single user contributed detail is allowed
   before the source based details.
- `affected` - must have one entry, and only one.
- `affected[0].package.ecosystem` and `affected[0].package.name` - required.
- `affected[0].ranges` - appended, no effort is made to consolidate
  `SEMVER` ranges.
- `database_specific` and `affected[0].database_specific` objects:
  - scalar values are stripped
  - during merge, duplicate keys with object values will be merged
  - during merge, duplicate keys with array values will be appended together
- `affected[0].ecosystem_specific` and `*.severity` data is dropped.
- `credits` are merged, with entries deduplicated based on the credit
  name and type.
- Other fields are merged by append lists together and removing duplicates.

## Contributing Code

Code contributions are welcome!

For larger features or changes, please
[create an issue](https://github.com/ossf/malicious-packages/issues/new) first.

When creating a Pull Request, please ensure:

- there are unit tests, and they are passing (run: `make test`)
- all lint errors have been fixed
