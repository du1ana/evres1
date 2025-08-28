#curl -fsSL https://github.com/du1ana/evres1/releases/download/sashi_v3.5.13/setup.sh | cat | sudo SKIP_SYSREQ=1 NO_DOMAIN=1 NETWORK=devnet bash -s install
#!/bin/bash

# Get the current script directory to use relative paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Define an array of source and destination file paths (using current directory)
file_paths=(
    "/home/dulana/EvernodeXRPL/sashimono/build/installer.tar.gz $SCRIPT_DIR/installer/installer.tar.gz"
    "/home/dulana/EvernodeXRPL/sashimono/build/setup-jshelper.tar.gz $SCRIPT_DIR/installer/setup-jshelper.tar.gz"
    "/home/dulana/EvernodeXRPL/sashimono/installer/setup.sh $SCRIPT_DIR/installer/setup.sh"
    "/home/dulana/EvernodeXRPL/sashimono/build/reputation-contract.tar.gz $SCRIPT_DIR/installer/reputation-contract.tar.gz"
)

cd "/home/dulana/EvernodeXRPL/sashimono" &&  make -j8 && make installer -j8

# Ensure the installer directory exists
mkdir -p "$SCRIPT_DIR/installer"

# Loop through each pair and perform the copy and replace operation
for path_pair in "${file_paths[@]}"; do
    # Split the pair into source and destination paths
    IFS=' ' read -r source_filepath destination_filepath <<< "$path_pair"

    # Check if the source file exists
    if [ -e "$source_filepath" ]; then
        # Copy and replace the file
        cp -f "$source_filepath" "$destination_filepath"

        # Check if the copy was successful
        if [ $? -eq 0 ]; then
            echo "File copied successfully from $source_filepath to $destination_filepath"
        else
            echo "Error: Failed to copy the file from $source_filepath to $destination_filepath"
            exit 1
        fi
    else
        echo "Warning: Source file $source_filepath does not exist - skipping"
    fi
done
