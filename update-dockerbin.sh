#!/bin/bash

url="https://raw.githubusercontent.com/moby/moby/master/contrib/download-frozen-image-v2.sh"
filename="/usr/bin/sashimono/dockerbin/download-frozen-image-v2.sh"
backup_dir="/usr/bin/sashimono/dockerbin/backups"
images_dir="/usr/bin/sashimono/dockerbin/images/evernodedev"
max_retries=2
backup_file=""

mkdir -p "$backup_dir"

restore_backup() {
    if [ -n "$backup_file" ] && [ -f "$backup_file" ]; then
        echo "Restoring backup from $backup_file"
        mv "$backup_file" "$filename"
        echo "Backup restored successfully."
    fi
}

download_and_update() {
    local attempt=$1
    echo "Attempt $attempt: Downloading new file..."
    
    if curl -L -o "$filename" "$url"; then
        echo "Download successful."
        
        if chmod 755 "$filename"; then
            echo "Permissions set successfully."
            return 0
        else
            echo "Failed to set permissions."
            return 1
        fi
    else
        echo "Download failed."
        return 1
    fi
}

if [ -f "$filename" ]; then
    timestamp=$(date +%Y%m%d_%H%M%S)
    backup_file="$backup_dir/download-frozen-image-v2.sh.bak_$timestamp"
    mv "$filename" "$backup_file"
    echo "Existing file backed up to $backup_file"
fi

success=false
for ((attempt=1; attempt<=max_retries; attempt++)); do
    if download_and_update $attempt; then
        success=true
        break
    else
        echo "Attempt $attempt failed."
        if [ $attempt -lt $max_retries ]; then
            echo "Retrying..."
            sleep 2
        fi
    fi
done

if [ "$success" = true ]; then
    echo "Successfully downloaded and replaced $filename"
    
    if [ -d "$images_dir" ]; then
        echo "Clearing $images_dir directory..."
        rm -rf "$images_dir"/*
        echo "Cleared $images_dir directory."
    fi
    
    echo "Update completed successfully."
else
    echo "All retry attempts failed. Restoring backup..."
    restore_backup
    echo "Update failed after $max_retries attempts."
    exit 1
fi

