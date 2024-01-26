#!/bin/bash

if [ "$#" -ne 3 ]; then
    echo "Invalid parameters. Usage: $0 <tag_version> <target_branch> <release_note>"
    exit 1
fi

tag_version="sashi_$1"
target_branch="$2"
release_note="$3"

./copy_files.sh
git add .
git commit -m "$tag_version $release_note"
git push origin main
gh release create "$tag_version" ./installer/* -t "$tag_version" --target "$target_branch" -n "$release_note"