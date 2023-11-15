#!/bin/bash

function online_version_timestamp() {
    latest_version_data=$(curl -s "$cloud_storage/latest")
    latest_version_timestamp=$(echo "$latest_version_data" | jq -r '.published_at')
    echo "$latest_version_timestamp"
}

cloud_storage="https://api.github.com/repos/du1ana/ev-res-test/releases"

# to be sused in sashimono to check latest ver
latest_version_data=$(curl -s "$cloud_storage/latest")

latest_version=$(echo "$latest_version_data" | jq -r '.name')
latest_version_timestamp=$(echo "$latest_version_data" | jq -r '.published_at')

echo "Latest Version: $latest_version"
echo "Timestamp: $latest_version_timestamp"


installer_version_timestamp=$(online_version_timestamp)

echo "Local timestamp: $installer_version_timestamp"

