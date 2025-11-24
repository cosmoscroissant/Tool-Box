#!/bin/bash

INTERVAL=360  # 6 minutes in seconds
RUN_COUNT=0

echo "=========================================="
echo "VirusTotal Malware Extractor - Local"
echo "=========================================="
echo ""

trap 'echo ""; echo "Stopped."; exit 0' SIGINT

deduplicate_file() {
    local filename=$1
    if [ ! -f "$filename" ]; then
        return
    fi
    
    local local_content=$(cat "$filename")
    local remote_content=$(git show origin/main:"$filename" 2>/dev/null || echo "")
    
    if [ -z "$remote_content" ]; then
        echo "$filename: First time, keeping all."
        return
    fi
    
    local existing_file="/tmp/existing_$(basename $filename)"
    echo "$remote_content" > "$existing_file"
    
    local filtered_file="/tmp/filtered_$(basename $filename)"
    grep -v -F -f "$existing_file" "$filename" > "$filtered_file" 2>/dev/null || true
    
    if [ -s "$filtered_file" ]; then
        cat "$filtered_file" >> "$filename"
        echo "$filename: Added $(wc -l < $filtered_file) new unique entries."
    else
        echo "$filename: No new unique entries."
    fi
    
    rm -f "$existing_file" "$filtered_file"
}


RUN_COUNT=$((RUN_COUNT + 1))
echo "[$(date -u +'%Y-%m-%d %H:%M:%S')] =========================================="
echo "[$(date -u +'%Y-%m-%d %H:%M:%S')] Run #$RUN_COUNT - Starting Extraction"
echo "[$(date -u +'%Y-%m-%d %H:%M:%S')] =========================================="
    
API_KEY=$(python3 -c "import sys; sys.path.insert(0, '/IOC'); from IOC.constants import MALWAREBAZAAR_API_KEY; print(MALWAREBAZAAR_API_KEY)")
python3 Extractor/IOC_extractor_MalwareBazaar_VT.py --api "$API_KEY"
    
echo "[$(date -u +'%Y-%m-%d %H:%M:%S')] Extraction complete"
echo ""
    
echo ""
echo "[$(date -u +'%Y-%m-%d %H:%M:%S')] waiting 6 minutes before next cycle"
echo ""
    
sleep $INTERVAL