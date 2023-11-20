#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Invalid parameters. Usage: $0 <tag_version> <release_note>"
    exit 1
fi

tag_version="sashi_$1"
release_note="$2"

gh release create "$tag_version" ./installer/* -t "$tag_version" -n "$release_note" -p