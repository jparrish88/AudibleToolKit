#!/bin/bash
set -euo pipefail

# ---
# PREPARE: Configuration required before main container process starts
# ---

echo "Using entrypoint"

# container config scripts go in entrypoint.d
for file in /_run/entrypoint/*.sh ; do
    if [[ -x "$file" ]]; then
        echo "Running file $file"
        "$file"
    fi
done

# ---
# MAIN: exec the primary container process
# ---
echo "Starting container, CMD: $@"
exec "$@"
