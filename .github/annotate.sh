#!/usr/bin/env bash
# CI helper: turn the interesting part of a log into ONE GitHub error
# annotation (readable via the checks API even when raw logs are not).
# Usage: annotate.sh <title> <logfile>
title=$1; log=$2
body=$( { grep -nE 'error|Error|FAIL|panic|fatal' "$log" | grep -vE 'TreatWarningsAsErrors|ErrorReport|0 Error' | sort -u | head -60; echo '---- tail'; tail -80 "$log"; } \
  | cut -c1-300 | sed -e 's/%/%25/g' -e 's/\r//g' | awk 'BEGIN{ORS="%0A"} {print}' | head -c 60000)
echo "::error title=$title::$body"
