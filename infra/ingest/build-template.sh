#!/bin/bash
# Build only a new never-booted scanner fixture. No production configuration changes.
set -euo pipefail
umask 077
[[ $EUID == 0 && ${M07_INGEST_TEMPLATE:-} == YES-I-AUTHORIZE-INGEST-TEMPLATE ]]
[[ $# == 2 && -d $1 && -d $2 ]]
TOOLS=$1
OUTPUT=$2
REPO=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO"
CGO_ENABLED=0 /usr/local/go/bin/go build -o "$OUTPUT/ingest-runner" ./cmd/ingest-runner
CGO_ENABLED=0 /usr/local/go/bin/go test -c -fuzz '^FuzzGuestOCI$' -o "$OUTPUT/ingest-tests" ./internal/ingest
M04_IMAGE_BUILD=YES-I-AUTHORIZE-LOOP-IMAGE M07_TOOLS="$TOOLS" \
 M07_INGEST_RUNNER="$OUTPUT/ingest-runner" M07_INGEST_TESTS="$OUTPUT/ingest-tests" \
 bash infra/builder/build-lab-fixture.sh ingest
