#!/bin/bash -e

## Version of protoc and protoc-gen-go needed to generate the protos.
PROTOC="35.1"
PROTOC_GEN_GO="v1.36.11"

## Go dependency for osv-schema to use to determine the current git commit ID.
OSV_SCHEMA_REPO="https://github.com/ossf/osv-schema"
OSV_SCHEMA_MODULE="github.com/ossf/osv-schema/bindings/go"

DIR="$(dirname $0)"
cd "$DIR"/..

## Ensure the current versions of protoc-* are correct.
CURRENT_PROTOC="$(protoc --version 2>/dev/null | cut -d' ' -f2)"
if [ "$PROTOC" != "$CURRENT_PROTOC" ]; then
    echo "Error: want protoc '$PROTOC', but found '$CURRENT_PROTOC'" >&2
    exit 1
fi
go install google.golang.org/protobuf/cmd/protoc-gen-go@$PROTOC_GEN_GO

## Download the dependent OSV Schema vulnerability.proto as a dependency.
OSV_SCHEMA_VERSION="$(go list -m -f '{{.Version}}' $OSV_SCHEMA_MODULE)"
OSV_SCHEMA_COMMIT="${OSV_SCHEMA_VERSION##*-}"
mkdir -p proto_deps/osv
cd proto_deps/osv
git init -q
git remote add origin "$OSV_SCHEMA_REPO" 2>/dev/null || echo "remote origin already exists"
git fetch -q origin main 
git checkout -q --detach "$OSV_SCHEMA_COMMIT"
cd ../..

## Generate our protos.
protoc -I=./proto_deps --go_out=paths=source_relative:./proto --proto_path=./proto malicious_packages.proto
