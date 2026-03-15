#!/usr/bin/env bash
set -euo pipefail

DIR="${COVERAGE_DIR:-coverage}"
mkdir -p "$DIR"

VERBOSE="${VERBOSE:-}"
SKIP_INTEGRATION="${SKIP_INTEGRATION:-}"
SERVE="${SERVE:-}"

log() {
    echo "==> $*"
}

vlog() {
    if [ -n "$VERBOSE" ]; then
        echo "    $*"
    fi
}

# Build filter pattern from .coverignore
filter_profile() {
    local input="$1" output="$2"
    if [ -f .coverignore ]; then
        local pattern
        pattern=$(grep -v '^#' .coverignore | grep -v '^$' | paste -sd'|' -)
        if [ -n "$pattern" ]; then
            grep -v -E "$pattern" "$input" > "$output"
            return
        fi
    fi
    cp "$input" "$output"
}

# --- Unit tests ---
log "Running unit tests..."
go test -coverprofile="$DIR/unit.raw" -covermode=atomic -race ./... "$@" || true
filter_profile "$DIR/unit.raw" "$DIR/unit.out"
vlog "Unit coverage profile: $DIR/unit.out"

# --- Integration tests ---
if [ -z "$SKIP_INTEGRATION" ]; then
    log "Running integration tests..."
    go test -tags integration -run 'TestIntegration' -coverprofile="$DIR/integration.raw" -covermode=atomic -race ./... "$@" || true
    filter_profile "$DIR/integration.raw" "$DIR/integration.out"
    vlog "Integration coverage profile: $DIR/integration.out"
fi

# --- Merge profiles ---
log "Merging coverage profiles..."
{
    head -1 "$DIR/unit.out"
    tail -n +2 "$DIR/unit.out"
    if [ -z "$SKIP_INTEGRATION" ] && [ -f "$DIR/integration.out" ]; then
        tail -n +2 "$DIR/integration.out"
    fi
} > "$DIR/total.out"

# --- Text summaries ---
echo ""
log "Unit test coverage:"
go tool cover -func="$DIR/unit.out" | tail -1

if [ -z "$SKIP_INTEGRATION" ] && [ -f "$DIR/integration.out" ]; then
    echo ""
    log "Integration test coverage:"
    go tool cover -func="$DIR/integration.out" | tail -1
fi

echo ""
log "Total coverage:"
go tool cover -func="$DIR/total.out" | tail -1

# --- HTML report ---
log "Generating HTML coverage report..."
REPORT_ARGS=("unit=$DIR/unit.out")
if [ -z "$SKIP_INTEGRATION" ] && [ -f "$DIR/integration.out" ]; then
    REPORT_ARGS+=("integration=$DIR/integration.out")
fi

if [ -n "$SERVE" ]; then
    echo ""
    go run ./cmd/covreport -serve "$SERVE" -open "${REPORT_ARGS[@]}"
else
    go run ./cmd/covreport -o "$DIR/report.html" "${REPORT_ARGS[@]}"
    echo ""
    log "Done. Coverage report: $DIR/report.html"
fi
