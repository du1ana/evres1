#!/bin/bash

if [ "$#" -ne 3 ]; then
    echo "Invalid parameters. Usage: $0 <tag_version> <target_branch> <release_note>"
    exit 1
fi

tag_version="sashi_$1"
target_branch="$2"
release_note="$3"

echo "Starting release process for $tag_version..."

# Run copy_files.sh and check if it succeeds
echo "Copying files..."
./copy_files.sh
if [ $? -ne 0 ]; then
    echo "Error: File copying failed. Aborting release."
    exit 1
fi

echo "Files copied successfully. Committing changes..."
git add .
git commit -m "$tag_version $release_note"

echo "Pushing to repository..."
git push origin main
if [ $? -ne 0 ]; then
    echo "Error: Failed to push to repository. Aborting release."
    exit 1
fi

# Check if release already exists and delete it if needed
echo "Checking if release $tag_version already exists..."
if gh release view "$tag_version" >/dev/null 2>&1; then
    echo "Release $tag_version already exists. Deleting it..."
    gh release delete "$tag_version" --yes
    if [ $? -ne 0 ]; then
        echo "Warning: Failed to delete existing release. Continuing anyway..."
    fi
    
    # Also delete the tag if it exists
    echo "Deleting existing tag $tag_version..."
    git tag -d "$tag_version" 2>/dev/null
    git push --delete origin "$tag_version" 2>/dev/null
fi

echo "Creating new release $tag_version..."
gh release create "$tag_version" ./installer/* -t "$tag_version" --target "$target_branch" -n "$release_note"
if [ $? -eq 0 ]; then
    echo "Release $tag_version created successfully!"
else
    echo "Error: Failed to create release $tag_version"
    exit 1
fi