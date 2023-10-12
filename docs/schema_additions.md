# Purpose

This document describes the database specific additions to the
[OSV Schema](https://github.com/ossf/osv-schema) specific to the Malicious
Packages repository.

The [OSV Schema](https://github.com/ossf/osv-schema) is a format specification
for reporting vulnerabilities in Open Source projects. This format has been
chosen to work with existing OSV tooling.

The Malicious Packages repository uses the OSV format to store reports of
malicious packages published on open source repositories.

The additions described in this document have two primary functions:

1. Annotating reports
1. Managing the database

To understand how the standard OSV fields are used, see the
[Contributing Guide](https://github.com/ossf/malicious-packages/blob/main/CONTRIBUTING.md)
for documentation.

# Database Specific Format Overview

The underlying OSV format is a JSON-based encoding format. Additions are
expressed in the following informal schema. The exact details of each field are
elaborated in the next section. All strings contain UTF-8 text.

```json
{
	/* ... other OSV fields ... */
	"database_specific": {
		"iocs": {
			"domains": [ string ],
			"urls": [ string ],
			"ip_addresses": [ string ],
		},
		"malicious-packages-origins" : [ {
			"source": string,
			"sha256": string,
			"import_time": string,
			"modified_time": string,
			"ranges": [ /* OSV range object */ ],
			"versions": [ string ]
		} ],
		/* ... other database specific entries ... */
	}
}
```

# Field Details

# iocs fields (under development)

The `iocs` field is a JSON object that stores indicators of compromise about
a given malicious package.

This area of the database specific schema is under active development and
subject to change.

## malicious-packages-origins fields

The `malicious-packages-origins` field is a JSON array containing objects that
is used internally to manage the malicious packages database. This data has
little value to consumers of OSV malware.

Each entry in the `malicious-packages-origins` array describes one origin OSV
report that was ingested and merged together to produce this individual OSV
report.

The field is used to help attribute each source and allow for the automated
ingestion command ([./cmd/ingest](https://github.com/ossf/malicious-packages/tree/main/cmd/ingest))
to detect reports that have already been imported. When an origin OSV is
ingested an entry will be added to this array. When OSV for the same package are
merged together the `malicious-packages-origins` in each source OSV will be
appended together in the merged OSV.

Within each object in the `malicious-packages-origins` array, the `source` field
contains a key identifying the specific source where an origin OSV was found.
This key should be specified in the [`./config/config.yaml`](https://github.com/ossf/malicious-packages/blob/main/config/config.yaml) file.

The `sha256` field contains a hash of the origin OSV file using the SHA256
algorithm. The `source` and `sha256` fields tuple should be a universally unique
identifier of an origin OSV file.

For origins that have an OSV `id` set, the `modified_time` and `id` are stored
as well to allow for updates to the be detected in the OSV.

The `import_time` indicates when the original OSV report was imported into the
malicious packages repository.

Finally, the `ranges` and `versions` fields are copies of the
`affected[0].ranges` and `affected[0].versions` from the origin OSV.

# malicious-packages-origins[].source field

The `source` field contains a string identifying the specific source that
contributed the origin OSV. Can only contain numbers, lowercase characters a-z,
and dashes (regexp: `^[a-z0-9-]+$`). The `source` field must be present.

# malicious-packages-origins[].sha256 field

The `sha256` field is a string containing a SHA256 hash of the origin OSV
serialized as a hexadecimal string. Valid characters are 0-9, a-f. The `sha256`
field must be present.

# malicious-packages-origins[].import_time field

The `import_time` field gives the time the origin OSV should be considered to
have been ingested, as an RFC3339-formatted timestamp in UTC (ending in "Z").
The `import_time` field should be present.

# malicious-packages-origins[].id field

The `id` field is optional. It stores a copy of the ID field in the origin OSV
as a string, if it was present. When used in conjunction with `modified_time` it
can be used to identify updates to the origin OSV that need to be consumed.

# malicious-packages-origins[].modified_time field

The `modified_time` field stores a copy of the modified time from the origin
OSV, as an RFC3339-formatted timestamp in UTC (ending in "Z"). The
`modified_time` field should be present.

# malicious-packages-origins[].ranges field

The ranges field is optional. It is a copy of the ranges field from the
`affected[].ranges` field in the origin OSV.

See https://ossf.github.io/osv-schema/#affectedranges-field.

# malicious-packages-origins[].versions field

The `versions` field is optional. It is a copy of the versions field from the
`affected[].versions` field in the origin OSV.

See https://ossf.github.io/osv-schema/#affectedversions-field.
