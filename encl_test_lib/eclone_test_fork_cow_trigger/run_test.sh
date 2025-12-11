#!/bin/bash
# run_test.sh
OUTPUT="test_result.txt"
: > "$OUTPUT"

exec >> "$OUTPUT" 2>&1

echo "Test run started at: $(date)"
echo "Note: this file contains both program output and shell diagnostics (e.g. 'Segmentation fault' lines)."
echo "------------------------------------------------------------------"

for emodt in 0 1; do
    for parent in $(seq 1 7); do
        for child in $(seq 1 7); do
            echo ""
            echo "==== emodt: $emodt    parent: $parent    child: $child ===="
            echo "Command: ./main $emodt $parent $child"
            start_ts=$(date +%s%3N)
            ./main "$emodt" "$parent" "$child"
            ret=$?
            end_ts=$(date +%s%3N)

            echo "Exit code: $ret"
            if [ $ret -ge 128 ]; then
                signum=$((ret-128))
                echo "Terminated by signal: $signum"
            fi
            echo "Elapsed ms: $((end_ts - start_ts))"
            echo "------------------------------------------------------------------"
        done
    done
done

echo "Test run finished at: $(date)"
