#!/usr/bin/env bash
#
# HALIXOR headless runner.
#
# Usage:
#   GHIDRA_HOME=/path/to/ghidra_11.2.1_PUBLIC ./run-headless.sh <firmware.bin>
#
# Environment:
#   GHIDRA_HOME   Ghidra distribution root (default: ../ghidra_11.2.1_PUBLIC)
#   OUTPUT_DIR    results directory       (default: ./output)
#   JAVA_HOME     JDK 21 home             (default: ghida's bundled java or PATH)
#   CONFIG        analysis config file    (default: ./config/analysis.config.json)
#   RAM_BASE      RAM base address        (default: 0x20000000)
#   RAM_SIZE      RAM size in bytes       (default: 0x20000 = 128 KB)
#
set -euo pipefail

DIST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${1:?usage: run-headless.sh <firmware.bin>}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"

GHIDRA_HOME="${GHIDRA_HOME:-$DIST_DIR/../ghidra_11.2.1_PUBLIC}"
OUTPUT_DIR="${OUTPUT_DIR:-$DIST_DIR/output}"
CONFIG="${CONFIG:-$DIST_DIR/config/analysis.config.json}"
PROCESSOR="ARM:LE:32:Cortex"
BASE_ADDR="0x08000000"
RAM_BASE="${RAM_BASE:-0x20000000}"
RAM_SIZE="${RAM_SIZE:-0x20000}"

# 1. assemble a Ghidra script directory: the script plus the library sources.
#    Ghidra 11 compiles every .java under the script directory together
#    (OSGi source bundle), so no external classpath is needed.
SCRIPT_DIR="$(mktemp -d)"
cp "$DIST_DIR/halixor.java" "$SCRIPT_DIR/"
cp "$DIST_DIR/InitRam.java" "$SCRIPT_DIR/"
cp "$DIST_DIR/ParamId.java" "$SCRIPT_DIR/"
cp -R "$DIST_DIR/src/." "$SCRIPT_DIR/"

# 2. run the analysis (from a scratch cwd so the script's relative
#    "output" dir lands there and can be collected afterwards)
RUN_DIR="$(mktemp -d)"
PROJECT_DIR="$(mktemp -d)"
mkdir -p "$PROJECT_DIR" "$RUN_DIR"
USER_HOME="${USER_HOME:-$DIST_DIR/.user-home}"
mkdir -p "$USER_HOME"

# keep Ghidra's per-user state (JDK choice, settings) in a writable location
export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:-} -Duser.home=$USER_HOME -Djava.awt.headless=true"
(
    cd "$RUN_DIR"
    "$GHIDRA_HOME/support/analyzeHeadless" \
        "$PROJECT_DIR" HALIXOR \
        -import "$BIN" \
        -loader BinaryLoader \
        -loader-baseAddr "$BASE_ADDR" \
        -processor "$PROCESSOR" \
        -scriptPath "$SCRIPT_DIR" \
        -preScript InitRam.java "$RAM_BASE" "$RAM_SIZE" \
        -postScript ParamId.java \
        -postScript halixor.java "$CONFIG"
) || true

# 3. move results next to the package
mkdir -p "$OUTPUT_DIR"
cp "$RUN_DIR"/output/* "$OUTPUT_DIR/" 2>/dev/null || true

# keep the full run log even if the script crashed mid-way
cp "$RUN_DIR"/output/*.vlog "$OUTPUT_DIR/" 2>/dev/null || true

echo "======================================================"
echo "HALIXOR run finished. Results in: $OUTPUT_DIR"
ls -la "$OUTPUT_DIR"
