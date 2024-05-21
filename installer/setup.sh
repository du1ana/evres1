#!/bin/bash
# Evernode host setup tool to manage Sashimono installation and host registration.
# This script is also used as the 'evernode' cli alias after the installation.
# usage: ./setup.sh install

# surrounding braces  are needed make the whole script to be buffered on client before execution.
{

    # set the LANG environment variable to a universal encoding
    export LANG=C.UTF-8

    evernode="Evernode"
    maxmind_creds="687058:FtcQjM0emHFMEfgI"
    cgrulesengd_default="cgrulesengd"
    alloc_ratio=80
    ramKB_per_instance=524288
    instances_per_core=3
    max_non_ipv6_instances=5
    max_ipv6_prefix_len=112
    min_ipv6_prefix_len=64
    min_lease_amt=0.000001
    min_disk_mb=1000
    min_ram_mb=500
    min_swap_mb=0
    evernode_alias=/usr/bin/evernode
    log_dir=/tmp/evernode
    reputationd_script_dir=$(dirname "$(realpath "$0")")
    root_user="root"

    repo_owner="du1ana"
    repo_name="evres"
    desired_branch="main"

    latest_version_endpoint="https://api.github.com/repos/$repo_owner/$repo_name/releases/latest"
    latest_version_data=$(curl -s "$latest_version_endpoint")
    latest_version=$(echo "$latest_version_data" | jq -r '.tag_name')
    if [ -z "$latest_version" ] || [ "$latest_version" = "null" ]; then
        echo "Failed to retrieve latest version data."
        exit 1
    fi

    # Prepare resources URLs
    issues_repo="evernode-host"
    report_url="https://github.com/$repo_owner/$issues_repo/issues"

    resource_storage="https://github.com/$repo_owner/$repo_name/releases/download/$latest_version"
    licence_url="https://raw.githubusercontent.com/$repo_owner/$repo_name/$desired_branch/license/evernode-license.pdf"
    config_url="https://raw.githubusercontent.com/$repo_owner/$repo_name/$desired_branch/definitions/definitions.json"
    reputation_contract_url="https://raw.githubusercontent.com/$repo_owner/$repo_name/$desired_branch/sashimono/installer/reputation-contract.tar.gz"
    setup_script_url="$resource_storage/setup.sh"
    installer_url="$resource_storage/installer.tar.gz"
    jshelper_url="$resource_storage/setup-jshelper.tar.gz"

    installer_version_timestamp_file="installer.version.timestamp"
    setup_helper_dir="/tmp/evernode-setup-helpers"
    nodejs_util_bin="/usr/bin/node"
    jshelper_bin="$setup_helper_dir/jshelper/index.js"
    config_json_path="$setup_helper_dir/configuration.json"

    spinner=('|' '/' '-' '\')

    xrpl_address="-"
    xrpl_secret="-"
    reputationd_xrpl_secret="-"
    reputationd_xrpl_address="-"
    countrycode="-"
    email_address="-"
    tls_key_file="self"
    tls_cert_file="self"
    tls_cabundle_file="self"
    description="-"
    fallback_rippled_servers="-"

    # export vars used by Sashimono installer.
    export USER_BIN=/usr/bin
    export SASHIMONO_BIN=/usr/bin/sashimono
    export MB_XRPL_BIN=$SASHIMONO_BIN/mb-xrpl
    export REPUTATIOND_BIN=$SASHIMONO_BIN/reputationd
    export DOCKER_BIN=$SASHIMONO_BIN/dockerbin
    export SASHIMONO_DATA=/etc/sashimono
    export SASHIMONO_CONFIG="$SASHIMONO_DATA/sa.cfg"
    export MB_XRPL_DATA=$SASHIMONO_DATA/mb-xrpl
    export REPUTATIOND_DATA=$SASHIMONO_DATA/reputationd
    export MB_XRPL_CONFIG="$MB_XRPL_DATA/mb-xrpl.cfg"
    export REPUTATIOND_CONFIG="$REPUTATIOND_DATA/reputationd.cfg"
    export SASHIMONO_SERVICE="sashimono-agent"
    export CGCREATE_SERVICE="sashimono-cgcreate"
    export MB_XRPL_SERVICE="sashimono-mb-xrpl"
    export REPUTATIOND_SERVICE="sashimono-reputationd"
    export SASHIADMIN_GROUP="sashiadmin"
    export SASHIUSER_GROUP="sashiuser"
    export SASHIUSER_PREFIX="sashi"
    export MB_XRPL_USER="sashimbxrpl"
    export REPUTATIOND_USER="sashireputationd"
    export CG_SUFFIX="-cg"
    export EVERNODE_AUTO_UPDATE_SERVICE="evernode-auto-update"
    export MIN_OPERATIONAL_COST_PER_MONTH=5
    # 3 Month minimum operational duration is considered.
    export MIN_OPERATIONAL_DURATION=3
    export MIN_REPUTATION_COST_PER_MONTH=10

    export NETWORK="${NETWORK:-devnet}"

    # Private docker registry (not used for now)
    export DOCKER_REGISTRY_USER="sashidockerreg"
    export DOCKER_REGISTRY_PORT=0

    # We execute some commands as unprivileged user for better security.
    # (we execute as the user who launched this script as sudo)
    noroot_user=${SUDO_USER:-$(whoami)}

    # Default key path is set to a path in MB_XRPL_USER home
    default_key_filepath="/home/$MB_XRPL_USER/.evernode-host/.host-account-secret.key"

    # Default reputationd key path is set to a path in REPUTATIOND_USER home
    default_reputationd_key_filepath="/home/$REPUTATIOND_USER/.evernode-host/.host-reputationd-secret.key"

    # Helper to print multi line text.
    # (When passed as a parameter, bash auto strips spaces and indentation which is what we want)
    function echomult() {
        echo -e $1
    }

    function confirm() {
        local prompt=$1
        local defaultChoice=${2:-y} #Default choice is set to 'y' if $2 parameter is not provided.

        local choiceDisplay="[Y/n]"
        if [ "$defaultChoice" == "n" ]; then
            choiceDisplay="[y/N]"
        fi

        echo -en $prompt "$choiceDisplay "
        local yn=""
        read yn </dev/tty

        # Default choice is 'y'
        [ -z $yn ] && yn="$defaultChoice"
        while ! [[ $yn =~ ^[Yy|Nn]$ ]]; do
            read -ep "'y' or 'n' expected: " yn </dev/tty
        done

        echo ""                                     # Insert new line after answering.
        [[ $yn =~ ^[Yy]$ ]] && return 0 || return 1 # 0 means success.
    }

    function spin() {
        while [ 1 ]; do
            for i in ${spinner[@]}; do
                echo -ne "\r$i"
                sleep 0.2
            done
        done
    }

    function wait_call() {
        local command_to_execute="$1"
        local output_template="$2"

        echomult "\nWaiting for the process to complete..."
        spin &
        local spin_pid=$!

        command_output=$($command_to_execute)
        return_code=$?

        kill $spin_pid
        wait $spin_pid
        echo -ne "\r"

        [ $return_code -eq 0 ] && echo -e ${output_template/\[OUTPUT\]/$command_output} || echo -e "\r$command_output"
        return $return_code
    }

    # Configuring the sashimono service is the last stage of the installation.
    # Removing the sashimono service is the first stage of un-installation.
    # So if the service exists, Previous sashimono installation has been complete.
    # Creating bin dir is the first stage of installation.
    # Removing bin dir is the last stage of un-installation.
    # So if the service does not exists but the bin dir exists, Previous installation or un-installation is failed partially.
    installed=false
    command -v evernode &>/dev/null && installed=true

    if $installed; then
        [ "$1" == "install" ] &&
            echo "$evernode is already installed on your host. Use the 'evernode' command to manage your host." &&
            exit 1

        [ "$1" == "deregister" ] &&
            echo "$evernode is already installed on your host. You cannot deregister without uninstalling. Use the 'evernode' command to manage your host." &&
            exit 1

        [ "$1" != "uninstall" ] && [ "$1" != "status" ] && [ "$1" != "list" ] && [ "$1" != "update" ] && [ "$1" != "log" ] && [ "$1" != "applyssl" ] && [ "$1" != "transfer" ] && [ "$1" != "config" ] && [ "$1" != "delete" ] && [ "$1" != "governance" ] && [ "$1" != "regkey" ] && [ "$1" != "offerlease" ] && [ "$1" != "reputationd" ] &&
            echomult "$evernode host management tool
                \nYour have $evernode installed on your machine.
                \nSupported commands:
                \nstatus - View $evernode registration info.
                \nlist - View contract instances running on this system.
                \nlog - Generate evernode log file.
                \napplyssl - Apply new SSL certificates for contracts.
                \nconfig - View and update host configuration.
                \nupdate - Check and install $evernode software updates.
                \ntransfer - Initiate an $evernode transfer for your machine.
                \ndelete - Remove an instance from the system and recreate the lease.
                \nuninstall - Uninstall and deregister from $evernode.
                \ngovernance - Governance candidate management.
                \nregkey - Regular key management.
                \nofferlease - Create Lease offers for the instances.
                \nreputationd - opt-in / opt-out for the Evernode reputation for reward distribution." &&
            exit 1
    else
        [ "$1" != "install" ] && [ "$1" != "transfer" ] && [ "$1" != "deregister" ] &&
            echomult "$evernode host management tool
                \nYour have not installed $evernode on your machine.
                \nSupported commands:
                \ninstall - Install Sashimono and register on $evernode.
                \ntransfer - Initiate an $evernode transfer for your machine.
                \nderegister - Deregister your account from $evernode." &&
            exit 1
    fi
    mode=$1

    if [ "$mode" == "install" ] || [ "$mode" == "uninstall" ] || [ "$mode" == "update" ] || [ "$mode" == "log" ] || [ "$mode" == "transfer" ] || [ "$mode" == "deregister" ]; then
        [ -n "$2" ] && [ "$2" != "-q" ] && [ "$2" != "-i" ] && echo "Second arg must be -q (Quiet) or -i (Interactive)" && exit 1
        [ "$2" == "-q" ] && interactive=false || interactive=true
        [ "$mode" == "transfer" ] && transfer=true || transfer=false
        [ "$mode" == "regkey" ] && regkey=true || regkey=false
        (! $transfer || $installed || $regkey) && [ "$EUID" -ne 0 ] && echo "Please run with root privileges (sudo)." && exit 1
    fi

    # Format the given KB number into GB units.
    function GB() {
        echo "$(bc <<<"scale=2; $1 / 1000000") GB"
    }

    function install_nodejs_utility() {
        apt-get update
        apt-get install -y ca-certificates curl gnupg
        mkdir -p /etc/apt/keyrings
        curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg

        NODE_MAJOR=20
        echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_MAJOR.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list
        apt-get update
        apt-get -y install nodejs
    }

    function check_common_prereq() {
        # Check jq command is installed.
        if ! command -v jq &>/dev/null; then
            echo "jq command not found. Installing.."
            apt-get install -y jq >/dev/null
        fi

        if ! command -v node &>/dev/null; then
            echo "Installing nodejs..."
            ! install_nodejs_utility >/dev/null && exit 1
        else
            version=$(node -v | cut -d '.' -f1)
            version=${version:1}
            if [[ $version -lt 20 ]]; then
                echo "$evernode requires NodeJs 20.x or later. You system has NodeJs $version installed. Either remove the NodeJs installation or upgrade to NodeJs 20.x."
                exit 1
            fi
        fi
    }

    function check_prereq() {
        echomult "\nChecking initial level prerequisites..."

        check_common_prereq

        # Check bc command is installed.
        if ! command -v bc &>/dev/null; then
            echo "bc command not found. Installing.."
            apt-get -y install bc >/dev/null
        fi

        # Check host command is installed.
        if ! command -v host &>/dev/null; then
            echo "host command not found. Installing.."
            apt-get -y install bind9-host >/dev/null
        fi

        # Check qrencode command is installed.
        if ! command -v qrencode &>/dev/null; then
            echo "qrencode command not found. Installing.."
            apt-get install -y qrencode >/dev/null
        fi
    }

    function check_sys_req() {

        # Assign sys resource info to global vars since these will also be used for instance allocation later.
        ramKB=$(free | grep Mem | awk '{print $2}')
        swapKB=$(free | grep -i Swap | awk '{print $2}')
        diskKB=$(df | grep -w /home | head -1 | awk '{print $4}')
        [ -z "$diskKB" ] && diskKB=$(df | grep -w / | head -1 | awk '{print $4}')

        # Skip system requirement check in non-production environments if SKIP_SYSREQ=1.
        ([ "$NETWORK" != "mainnet" ] && [ "$SKIP_SYSREQ" == "1" ]) && echo "System requirements check skipped." && return 0

        local proc1=$(ps --no-headers -o comm 1)
        if [ "$proc1" != "systemd" ]; then
            echo "$evernode host installation requires systemd. Your system does not have systemd running. Aborting."
            exit 1
        fi

        local os=$(grep -ioP '^ID=\K.+' /etc/os-release)
        local osversion=$(grep -ioP '^VERSION_ID=\K.+' /etc/os-release)

        local errors=""
        ([ "$os" != "ubuntu" ] || [ "$osversion" != '"20.04"' ]) && errors=" OS: $os $osversion (required: Ubuntu 20.04)\n"
        [ $ramKB -lt 2000000 ] && errors="$errors RAM: $(GB $ramKB) (required: 2 GB RAM)\n"
        [ $swapKB -lt 2000000 ] && errors="$errors Swap: $(GB $swapKB) (required: 2 GB Swap)\n"
        [ $diskKB -lt 4000000 ] && errors="$errors Disk space (/home): $(GB $diskKB) (required: 4 GB)\n"

        if [ -z "$errors" ]; then
            echo "System check complete. Your system is capable of becoming an $evernode host."
        else
            echomult "Your system does not meet following $evernode system requirements:\n $errors"
            echomult "$evernode host registration requires Ubuntu 20.04 with minimum 2 GB RAM,
            2 GB Swap and 4 GB free disk space for /home. Aborting setup."
            exit 1
        fi
    }

    function download_public_config() {
        [ ! -z $1 ] && config_path="$1"
        echomult "\nDownloading Environment configuration...\n"
        sudo -u $noroot_user curl $config_url --output $config_json_path

        # Network config selection.

        echomult "\nChecking Evernode $NETWORK environment details..."

        if ! jq -e ".${NETWORK}" "$config_json_path" >/dev/null 2>&1; then
            echomult "Sorry the specified environment has not been configured yet..\n" && exit 1
        fi
    }

    function set_environment_configs() {
        export EVERNODE_GOVERNOR_ADDRESS=${OVERRIDE_EVERNODE_GOVERNOR_ADDRESS:-$(jq -r ".$NETWORK.governorAddress" $config_json_path)}
        rippled_server=$(jq -r ".$NETWORK.rippledServer" $config_json_path)
        local config_fb_rippled_servers=$(jq -r ".$NETWORK.fallbackRippledServers | select( . != null and . != [] )" $config_json_path)
        if [ ! -z "$config_fb_rippled_servers" ]; then
            fallback_rippled_servers=$(echo "$config_fb_rippled_servers" | jq -r '. | join(",")')
        fi
    }

    function init_setup_helpers() {

        echo "Downloading setup support files..."

        local jshelper_dir=$(dirname $jshelper_bin)
        rm -r $jshelper_dir >/dev/null 2>&1
        sudo -u $noroot_user mkdir -p $jshelper_dir
        chmod -R 777 $(dirname $jshelper_dir)

        if [ ! -f "$jshelper_bin" ]; then
            pushd $jshelper_dir >/dev/null 2>&1
            sudo -u $noroot_user curl -L $jshelper_url --output jshelper.tar.gz
            sudo -u $noroot_user tar zxf jshelper.tar.gz --strip-components=1
            rm jshelper.tar.gz
            popd >/dev/null 2>&1
        fi
        [ ! -f "$jshelper_bin" ] && echo "Could not download helper tool for setup checks." && exit 1
        echo -e "Done.\n"
    }

    function exec_jshelper() {

        # Create fifo file to read response data from the helper script.
        local resp_file=$setup_helper_dir/helper_fifo
        [ -p $resp_file ] || sudo -u $noroot_user mkfifo $resp_file

        # Execute js helper asynchronously while collecting response to fifo file.
        [ "$fallback_rippled_servers" != "-" ] && local fb_server_param="fallback-servers:$fallback_rippled_servers"
        sudo -u $noroot_user RESPFILE=$resp_file $nodejs_util_bin $jshelper_bin "$@" "network:$NETWORK" "$fb_server_param" >/dev/null 2>&1 &
        local pid=$!
        local result=$(cat $resp_file) && [ "$result" != "-" ] && echo $result

        # Wait for js helper to exit and reflect the error exit code in this function return.
        wait $pid && [ $? -eq 0 ] && rm $resp_file && return 0
        rm -rf $resp_file && return 1
    }

    function exec_jshelper_root() {

        # Create fifo file to read response data from the helper script.
        local resp_file=$setup_helper_dir/helper_fifo
        [ -p $resp_file ] || mkfifo $resp_file

        # Execute js helper asynchronously while collecting response to fifo file.
        [ "$fallback_rippled_servers" != "-" ] && local fb_server_param="fallback-servers:$fallback_rippled_servers"
        RESPFILE=$resp_file $nodejs_util_bin $jshelper_bin "$@" "network:$NETWORK" "$fb_server_param" >/dev/null 2>&1 &
        local pid=$!
        local result=$(cat $resp_file) && [ "$result" != "-" ] && echo $result

        # Wait for js helper to exit and reflect the error exit code in this function return.
        wait $pid && [ $? -eq 0 ] && rm $resp_file && return 0
        rm -rf $resp_file && return 1
    }

    function resolve_filepath() {
        # name reference the variable name provided as first argument.
        local -n filepath=$1
        local option=$2
        local prompt="${*:3} "

        while [ -z "$filepath" ]; do
            read -p "$prompt" filepath </dev/tty

            # if optional accept empty path as "-"
            [ "$option" == "o" ] && [ -z "$filepath" ] && filepath="-"

            # Check for valid path.
            ([ "$option" == "r" ] || ([ "$option" == "o" ] && [ "$filepath" != "-" ])) &&
                [ ! -f "$filepath" ] && echo "Invalid file path" && filepath=""
        done
    }

    function set_domain_certs() {
        if confirm "\n$evernode can automatically setup free SSL certificates and renewals for '$inetaddr'
            using Let's Encrypt (https://letsencrypt.org/).
            \nDo you want to setup Let's Encrypt automatic SSL (recommended)?" &&
            confirm "Do you agree to have Let's Encrypt send SSL certificate notifications to your email '$email_address' (required)?" &&
            confirm "Do you agree with Let's Encrypt Terms of Service at https://letsencrypt.org/documents/LE-SA-v1.3-September-21-2022.pdf ?"; then

            tls_key_file="letsencrypt"
            tls_cert_file="letsencrypt"
            tls_cabundle_file="letsencrypt"
        else

            # Unset variables before aks for user input.
            tls_key_file=""
            tls_cert_file=""
            tls_cabundle_file=""

            echomult "You have opted out of automatic SSL setup. You need to have obtained SSL certificate files for '$inetaddr'
            from a trusted authority. Please specify the certificate files you have obtained below.\n"

            resolve_filepath tls_key_file r "Please specify location of the private key (usually ends with .key):"
            resolve_filepath tls_cert_file r "Please specify location of the certificate (usually ends with .crt):"
            resolve_filepath tls_cabundle_file o "Please specify location of ca bundle (usually ends with .ca-bundle [Optional]):"
        fi
        return 0
    }

    function validate_inet_addr_domain() {
        if host $inetaddr >/dev/null 2>&1; then
            local port="80"
            echo "Verifying domain $inetaddr on port $port..."
            local domain_result=$(exec_jshelper_root validate-domain $inetaddr $port)
            [[ "$domain_result" == "ok" ]] && echo "Domain verification successful." && return 0

            if [ "$domain_result" == "listen_error" ]; then
                echomult "Could not initiate domain verification. It's likely that port $port is already in use by another application.\n
                It's recommended that you abandon the setup and correct this. You should consider continuing only if you are an advanced user
                who knows what they are doing, and is going to provide your own SSL certificates."
                confirm "Do you want to abandon the setup (recommended)?" && echo "Setup abandoned." && exit 1
                echo "Continuing with unverified domain $inetaddr" && return 0
            fi

            [[ "$domain_result" == "domain_error" ]] &&
                echo "Domain verification for $inetaddr failed. Please make sure that this host is reachable via $inetaddr"
        fi

        # Reaching this point means some error has occured. So we clear the inetaddress to allow to try again.
        inetaddr="" && return 1
    }

    function validate_inet_addr() {
        # inert address cannot be empty and cannot contain spaces.
        [ -z "$inetaddr" ] || [[ $inetaddr = *" "* ]] && inetaddr="" && return 1

        # Attempt to resolve ip (in case inetaddr is a DNS address)
        # This will resolve correctly if inetaddr is a valid ip or dns address.

        local resolved_ips=$(getent hosts $inetaddr | wc -l)

        # Check if there is more than one IP address
        if [ $resolved_ips -eq 1 ]; then
            return 0
        elif [ $resolved_ips -gt 1 ]; then
            echo "Your domain ($inetaddr) must point to a single IP address."
        fi

        # If invalid, reset inetaddr and return with non-zero code.
        inetaddr="" && return 1

    }

    function validate_positive_integer() {
        ! [[ $1 =~ ^[1-9][0-9]*$ ]] && return 1
        return 0
    }

    function validate_positive_decimal() {
        ! [[ $1 =~ ^(0*[1-9][0-9]*(\.[0-9]+)?|0+\.[0-9]*[1-9][0-9]*)$ ]] && return 1
        return 0
    }

    function validate_rippled_url() {
        ! [[ $1 =~ ^(wss?:\/\/)([^\/|^ ]{3,})(:([0-9]{1,5}))?$ ]] && echo "Rippled URL must be a valid URL that starts with 'wss://' or 'ws://'" && return 1

        ! exec_jshelper validate-server $1 && echo "Could not communicate with the xahaud server $1." && return 1
        return 0
    }

    function validate_email_address() {
        local emailAddress=$1
        email_address_length=${#emailAddress}
        ( (! [[ "$email_address_length" -le 40 ]] && echo "Email address length should not exceed 40 characters.") ||
            (! [[ $emailAddress =~ .+@.+ ]] && echo "Email address is invalid.")) || return 0
        return 1
    }

    function validate_lease_amount() {
        local invalid=$(echo "$amount < $min_lease_amt" | bc -l)
        [[ "$invalid" -eq 1 ]] && return 1
        return 0
    }

    function set_inet_addr() {
        # Skip system requirement check in non-production environments if $NO_DOMAIN=1.
        if [ "$NETWORK" == "mainnet" ] || [[ "$NETWORK" != "mainnet" && "$NO_DOMAIN" == "" ]]; then
            while [ -z "$inetaddr" ]; do
                read -ep "Please specify the domain name that this host is reachable at: " inetaddr </dev/tty
                validate_inet_addr && validate_inet_addr_domain && break
                echo "Invalid or unreachable domain name."
            done
            set_domain_certs && return 0
        elif [ -z "$inetaddr" ]; then
            tls_key_file="self"
            tls_cert_file="self"
            tls_cabundle_file="self"

            # Attempt auto-detection.

            inetaddr=$(hostname -I | awk '{print $1}')
            validate_inet_addr && $interactive && confirm "Detected ip address '$inetaddr'. This needs to be publicly reachable over
                                internet.\n\nIs this the ip address you want others to use to reach your host?" && return 0
            inetaddr=""

            while [ -z "$inetaddr" ]; do
                read -ep "Please specify the public ip/domain address your server is reachable at: " inetaddr </dev/tty
                validate_inet_addr && return 0
                echo "Invalid ip/domain address."
            done

            ! validate_inet_addr && echo "Invalid ip/domain address" && exit 1
        fi

    }

    function check_port_validity() {
        # Port should be a number and between 1 through 65535.
        # 1 through 1023 are used by system-supplied TCP/IP applications.
        [[ $1 =~ ^[0-9]+$ ]] && [ $1 -ge 1024 ] && [ $1 -le 65535 ] && return 0
        return 1
    }

    function set_init_ports() {

        # Take default ports in interactive mode or if 'default' is specified.
        # Picked default ports according to https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
        # (22223 - 23073) and (26000 - 26822) range is uncommon.

        # Default starting ports.
        init_peer_port=22861
        init_user_port=26201

        if [ -n "$init_peer_port" ] && [ -n "$init_user_port" ] && confirm "Selected default port ranges (Peer: $init_peer_port-$((init_peer_port + alloc_instcount)), User: $init_user_port-$((init_user_port + alloc_instcount))).
                                        This needs to be publicly reachable over internet. \n\nAre these the ports you want to use?"; then
            return 0
        fi

        init_peer_port=""
        init_user_port=""
        while [ -z "$init_peer_port" ]; do
            read -ep "Please specify the starting port of the public 'Peer port range' your server is reachable at: " init_peer_port </dev/tty
            ! check_port_validity $init_peer_port && init_peer_port="" && echo "Invalid port."
        done
        while [ -z "$init_user_port" ]; do
            read -ep "Please specify the starting port of the public 'User port range' your server is reachable at: " init_user_port </dev/tty
            ! check_port_validity $init_user_port && init_user_port="" && echo "Invalid port."
        done
    }

    # Validate country code and convert to uppercase if valid.
    function resolve_countrycode() {
        # If invalid, reset countrycode and return with non-zero code.
        if ! [[ $countrycode =~ ^[A-Za-z][A-Za-z]$ ]]; then
            countrycode=""
            return 1
        else
            countrycode=$(echo $countrycode | tr 'a-z' 'A-Z')
            return 0
        fi
    }

    function set_country_code() {

        # Attempt to auto-detect in interactive mode or if 'auto' is specified.
        echo "Checking country code..."
        echo "Using GeoLite2 data created by MaxMind, available from https://www.maxmind.com"

        # MaxMind needs a ip address to detect country code. DNS is not supported by it.
        # Use getent to resolve ip address in case inetaddr is a DNS name.
        local mxm_ip=$(getent hosts $inetaddr | head -1 | awk '{ print $1 }')
        # If getent fails (mxm_ip empty) for some reason, keep using inetaddr for MaxMind api call.
        [ -z "$mxm_ip" ] && mxm_ip="$inetaddr"

        local detected=$(curl -s -u "$maxmind_creds" "https://geolite.info/geoip/v2.1/country/$mxm_ip?pretty" | grep "iso_code" | head -1 | awk '{print $2}')
        countrycode=${detected:1:2}
        resolve_countrycode || echo "Could not detect country code."

        # Uncomment this if we want the user to manually change the auto-detected country code.
        # if [ -n "$countrycode" ] && ! confirm "Based on the internet address '$inetaddr' we have detected that your country
        #                                         code is '$countrycode'. Do you want to specify a different country code" ; then
        #     return 0
        # fi
        # countrycode=""

        while [ -z "$countrycode" ]; do
            # This will be asked if auto-detection fails or if user wants to specify manually.
            read -ep "Please specify the two-letter country code where your server is located in (eg. AU): " countrycode </dev/tty
            resolve_countrycode || echo "Invalid country code."
        done
    }

    function set_ipv6_subnet() {

        ipv6_subnet="-"
        ipv6_net_interface="-"

        echomult "If your host has IPv6 support, Evernode can assign individual outbound IPv6 addresses to each
        contract instance. This will prevent your host's primary IP address from getting blocked by external
        services in case many contracts on your host attempt to contact the same external service."

        ! confirm "\nDoes your host have an IPv6 subnet assigned to it? The CIDR notation for this usually looks like \"xxxx:xxxx:xxxx:xxxx::/64\"" && return 0

        while true; do
            local subnet_input
            read -ep "Please specify the IPv6 subnet CIDR assigned to this host: " subnet_input </dev/tty
            [ -z "$subnet_input" ] && echo "Invalid ipv6 subnet specified. It must be a valid ipv6 subnet in the CIDR format of \"xxxx:xxxx:xxxx:xxxx::/NN\"." && continue

            # If the given IP is valid, this will return the normalized ipv6 subnet like "x:x:x:x::/NN"
            local primary_subnet=$(exec_jshelper ip6-getsubnet $subnet_input)
            [ -z "$primary_subnet" ] && echo "Invalid ipv6 subnet specified. It must be a valid ipv6 subnet in the CIDR format of \"xxxx:xxxx:xxxx:xxxx::/NN\"." && continue

            # For further validation, we check whether the subnet prefix is actually assigned to any network interfaces of the host.
            local subnet_prefix="$(cut -d'/' -f1 <<<$primary_subnet | sed 's/::*$//g')"
            local prefix_len="$(cut -d'/' -f2 <<<$primary_subnet)"
            local net_interfaces=$(ip -6 -br addr show scope global | grep "$subnet_prefix")
            local interface_count=$(echo "$net_interfaces" | wc -l)

            [ "$prefix_len" -lt $min_ipv6_prefix_len ] && echo "Minimum allowed prefix length for $evernode is $min_ipv6_prefix_len." && continue
            [ "$prefix_len" -gt $max_ipv6_prefix_len ] && echo "Maximum allowed prefix length for $evernode is $max_ipv6_prefix_len." && continue
            [ -z "$net_interfaces" ] && echo "Could not find a network interface with the specified ipv6 subnet." && continue
            [ "$interface_count" -gt 1 ] && echo "Found more than 1 network interface with the specified ipv6 subnet." && echo "$net_interfaces" && continue

            primary_subnet=$(echo "$net_interfaces" | awk '{ print $3 }')
            ipv6_subnet=$primary_subnet
            ipv6_net_interface=$(echo "$net_interfaces" | awk '{ print $1 }')

            echomult "\nSubnet CIDR identified: $primary_subnet"
            if ! confirm "Do you want to allocate the entire address range of the subnet $primary_subnet to $evernode?"; then

                while true; do
                    read -ep "Please specify the nested IPv6 subnet you want to allocate for $evernode (this must be a nested subnet within $primary_subnet subnet): " subnet_input </dev/tty
                    [ -z "$subnet_input" ] && echo "Invalid ipv6 subnet specified. It must be a valid ipv6 nested subnet in the CIDR format of \"xxxx:xxxx:xxxx:xxxx::/NN\"." && continue

                    # If the given nested subnet is valid, this will return the normalized ipv6 subnet like "x:x:x:x::/NN"
                    local nested_subnet=$(exec_jshelper ip6-nested-subnet $primary_subnet $subnet_input)
                    [ -z "$nested_subnet" ] && echo "Invalid nested IPv6 subnet specified." && continue

                    local prefix_len="$(cut -d'/' -f2 <<<$nested_subnet)"
                    [ "$prefix_len" -gt $max_ipv6_prefix_len ] && echo "Maximum allowed prefix length for $evernode is $max_ipv6_prefix_len." && continue

                    ipv6_subnet=$nested_subnet
                    break
                done
            fi

            break
        done
    }

    function set_cgrules_svc() {
        local filepath=$(grep "ExecStart.*=.*/cgrulesengd$" /etc/systemd/system/*.service | head -1 | awk -F : ' { print $1 } ')
        if [ -n "$filepath" ]; then
            local filename=$(basename $filepath)
            cgrulesengd_service="${filename%.*}"
        fi
        # If service not detected, use the default name.
        [ -z "$cgrulesengd_service" ] && cgrulesengd_service=$cgrulesengd_default || echo "cgroups rules engine service found: '$cgrulesengd_service'"
    }

    function set_instance_alloc() {
        [ -z $alloc_ramKB ] && alloc_ramKB=$(((ramKB / 100) * alloc_ratio))
        [ -z $alloc_swapKB ] && alloc_swapKB=$(((swapKB / 100) * alloc_ratio))
        [ -z $alloc_diskKB ] && alloc_diskKB=$(((diskKB / 100) * alloc_ratio))
        [ -z $alloc_cpu ] && alloc_cpu=$(((1000000 / 100) * alloc_ratio))

        # If instance count is not specified, decide it based on some rules.
        if [ -z $alloc_instcount ]; then

            # Instance count based on total RAM
            local ram_c=$((alloc_ramKB / ramKB_per_instance))
            # Instance count based on no. of CPU cores.
            local cores=$(grep -c ^processor /proc/cpuinfo)
            local cpu_c=$((cores * instances_per_core))
            # Hardware spec-based maximum instance count will be the lower of the two.
            alloc_instcount=$((ram_c < cpu_c ? ram_c : cpu_c))

            # If the host does not have a ipv6 subnet, limit the max instance count further.
            if [ -z "$ipv6_subnet" ] && [ $alloc_instcount -gt $max_non_ipv6_instances ]; then
                $alloc_instcount=$max_non_ipv6_instances
            fi
        fi

        echomult "Based on your system resources, we have chosen the following allocation:\n
            $(GB $alloc_ramKB) memory\n
            $(GB $alloc_swapKB) Swap\n
            $(GB $alloc_diskKB) disk space\n
            Distributed among $alloc_instcount contract instances"
        confirm "\nIs this the allocation you want to use?" && return 0

        local ramMB=0 swapMB=0 diskMB=0

        while true; do
            read -ep "Specify the number of contract instances that you wish to host: " alloc_instcount </dev/tty
            ! [[ $alloc_instcount -gt 0 ]] && echo "Invalid instance count." || break
        done

        local max_ram_mb=$((ramKB / 1000))
        while true; do
            read -ep "Specify the total memory in megabytes to distribute among all contract instances: " ramMB </dev/tty
            ! [[ $ramMB -gt 0 ]] && echo "Invalid memory size." && continue
            [[ $ramMB -lt $min_ram_mb ]] && echo "Minimum memory size should be "$min_ram_mb" MB." && continue
            [[ $ramMB -gt $max_ram_mb ]] && echo "Insufficient memory on your host. Maximum available memory is "$max_ram_mb" MB." && continue
            break
        done

        local max_swap_mb=$((swapKB / 1000))
        while true; do
            read -ep "Specify the total Swap in megabytes to distribute among all contract instances: " swapMB </dev/tty
            ! [[ $swapMB -gt 0 ]] && echo "Invalid swap size." && continue
            [[ $swapMB -lt $min_swap_mb ]] && echo "Minimum swap size should be "$min_swap_mb" MB." && continue
            [[ $swapMB -gt $max_swap_mb ]] && echo "Insufficient swap on your host. Maximum available swap is "$max_swap_mb" MB." && continue
            break
        done

        local max_disk_mb=$((diskKB / 1000))
        while true; do
            read -ep "Specify the total disk space in megabytes to distribute among all contract instances: " diskMB </dev/tty
            ! [[ $diskMB -gt 0 ]] && echo "Invalid disk size." && continue
            [[ $diskMB -lt $min_disk_mb ]] && echo "Minimum disk size should be "$min_disk_mb" MB." && continue
            [[ $diskMB -gt $max_disk_mb ]] && echo "Insufficient disk on your host. Maximum available disk is "$max_disk_mb" MB." && continue
            break
        done

        alloc_ramKB=$((ramMB * 1000))
        alloc_swapKB=$((swapMB * 1000))
        alloc_diskKB=$((diskMB * 1000))

        if ! [[ $alloc_ramKB -gt 0 ]] || ! [[ $alloc_swapKB -gt 0 ]] || ! [[ $alloc_diskKB -gt 0 ]] ||
            ! [[ $alloc_cpu -gt 0 ]] || ! [[ $alloc_instcount -gt 0 ]]; then
            echo "Invalid allocation." && exit 1
        fi
    }

    function set_lease_amount() {

        # Lease amount is mandatory field set by the user
        local amount=0
        while true; do
            read -ep "Specify the lease amount in EVRs for your contract instances (per moment charge per contract): " amount </dev/tty
            ! validate_positive_decimal $amount && echo "Lease amount should be a numerical value greater than zero." && continue
            ! validate_lease_amount $amount && echo "Lease amount should be greater than or equal "$min_lease_amt" EVRs" && continue
            break
        done

        lease_amount=$amount
    }

    function set_extra_fee() {
        local fee=0
        if confirm "Do you want to set an extra transaction fee to consider in case of network congestion?" "n"; then
            while true; do
                read -ep "Specify the affordable extra transaction fee (in XAH Drops): " fee </dev/tty
                ! ([[ $fee =~ ^[0-9]+$ ]] && [[ $fee -ge 0 ]]) && echo "Extra fee amount should be an integer value greater than or equal zero." || break
            done

            echo -e "Affordable extra transaction fee is set as $fee XAH Drops.\n"
        fi

        extra_txn_fee=$fee
    }

    function set_email_address() {

        local emailAddress=""
        while true; do
            read -ep "Specify the contact email address for your host (this will be published on the host registry and is publicly visible to anyone): " emailAddress </dev/tty
            ! validate_email_address $emailAddress || break
        done

        email_address=$emailAddress
    }

    function set_rippled_server() {
        if confirm "Do you want to connect to the default xahaud server ($rippled_server)?"; then
            ! validate_rippled_url $rippled_server && exit 1
        else
            local new_url=""
            while true; do
                read -ep "Specify the Xahaud server URL: " new_url </dev/tty
                ! validate_rippled_url $new_url || break
            done
            rippled_server=$new_url
        fi
    }

    function validate_and_set_fallback_rippled_servers() {
        IFS=',' read -ra fallback_servers <<<"$1"
        unset IFS
        for server in "${fallback_servers[@]}"; do
            server=$(echo "$server" | sed -e 's/^[[:space:][:punct:]]*//' -e 's/[[:space:][:punct:]]*$//')
            if ! validate_rippled_url "$server"; then
                return 1
            fi
        done

        fallback_rippled_servers="$1"
    }

    function set_fallback_rippled_servers() {
        if ([[ "$fallback_rippled_servers" != "-" ]] && ! confirm "Do you want to set ("$fallback_rippled_servers") the default fallback rippled servers ?") || confirm "Do you want to specify fallback rippled servers?" "n"; then
            local new_urls=""
            while true; do
                read -p "Specify the comma-separated list of fallback server URLs: " new_urls </dev/tty
                ! validate_and_set_fallback_rippled_servers "$new_urls" || break
            done
        fi
    }

    function set_regular_key() {
        [ "$EUID" -ne 0 ] && echo "Please run with root privileges (sudo)." && exit 1

        ! sudo -u $MB_XRPL_USER MB_DATA_DIR=$MB_XRPL_DATA node $MB_XRPL_BIN regkey $1 &&
            echo "There was an error in changing the regular key." && return 1
    }

    function set_transferee_address() {
        # Here we set the default transferee address as 'CURRENT_HOST_ADDRESS', but we set it to the exact current host address in host client side.
        [ -z $transferee_address ] && transferee_address=''

        if $interactive; then
            confirm "\nDo you want to set the current host account as the transferee's account?" && return 0

            local address=''
            while true; do
                read -ep "Specify the Xahau account address of the transferee: " address </dev/tty
                ! [[ $address =~ ^r[a-zA-Z0-9]{24,34}$ ]] && echo "Invalid Xahau account address." || break

            done

            transferee_address=$address
        fi

        ! [[ $transferee_address =~ ^r[a-zA-Z0-9]{24,34}$ ]] && echo "Invalid Xahau account address." && exit 1
    }

    # Function to generate QR code in the terminal
    function generate_qrcode() {
        if [ -z "$1" ]; then
            echo "Argument error > Usage: generate_qrcode <string>"
            return 1
        fi
        local input_string="$1"
        qrencode -s 1 -l L -t UTF8 "$input_string"
    }

    function generate_keys() {
        local is_reputationd=false
        if [[ "$1" == "reputationd" ]]; then
            is_reputationd=true
        fi
        while true; do
            account_json=$(exec_jshelper generate-account) && break
            echo "Error occurred in account setting up."
            confirm "\nDo you want to retry?\nPressing 'n' would terminate the installation." || exit 1
        done
        if $is_reputationd; then
            reputationd_xrpl_address=$(jq -r '.address' <<<"$account_json")
            reputationd_xrpl_secret=$(jq -r '.secret' <<<"$account_json")
        else
            xrpl_address=$(jq -r '.address' <<<"$account_json")
            xrpl_secret=$(jq -r '.secret' <<<"$account_json")
        fi
    }

    read_fallback_rippled_servers_res="-"
    function read_fallback_rippled_servers_from_config() {
        local override_fallback_rippled_servers=$(jq -r ".xrpl.fallbackRippledServers | select( . != null and . != [] )" "$MB_XRPL_CONFIG")
        if [ ! -z "$override_fallback_rippled_servers" ]; then
            read_fallback_rippled_servers_res=$(echo "$override_fallback_rippled_servers" | jq -r '. | join(",")')
        fi
    }

    function read_configs() {
        if [ -f "$MB_XRPL_CONFIG" ]; then
            echomult "\nReading configuration from existing Message Board configuration file..."

            local owner=$(stat -c "%U" "$MB_XRPL_CONFIG")
            local group=$(stat -c "%G" "$MB_XRPL_CONFIG")
            local access=$(stat -c "%a" "$MB_XRPL_CONFIG")

            ([ "$owner" != "$MB_XRPL_USER" ] || [ "$group" != "$MB_XRPL_USER" ] || [ "$access" != "644" ]) &&
                echomult "\nConfiguration file permissions have been altered." &&
                exit 1

            local override_network=$(jq -r ".xrpl.network | select( . != null )" "$MB_XRPL_CONFIG")
            if [ ! -z $override_network ]; then
                NETWORK="$override_network"
                set_environment_configs || exit 1
            fi

            local override_rippled_server=$(jq -r ".xrpl.rippledServer | select( . != null )" "$MB_XRPL_CONFIG")
            [ ! -z $override_rippled_server ] && rippled_server="$override_rippled_server"
            ! read_fallback_rippled_servers_from_config && exit 1
            fallback_rippled_servers="$read_fallback_rippled_servers_res"

            xrpl_address=$(jq -r ".xrpl.address | select( . != null )" "$MB_XRPL_CONFIG")
            key_file_path=$(jq -r ".xrpl.secretPath | select( . != null )" "$MB_XRPL_CONFIG")
            lease_amount=$(jq ".xrpl.leaseAmount | select( . != null )" "$MB_XRPL_CONFIG")
            # Format lease amount since jq gives it in exponential format.
            lease_amount=$(awk -v lease_amount="$lease_amount" 'BEGIN { printf("%f\n", lease_amount) }' </dev/null)
            extra_txn_fee=$(jq ".xrpl.affordableExtraFee | select( . != null )" "$MB_XRPL_CONFIG")
            [ -z $extra_txn_fee ] && extra_txn_fee=0
            email_address=$(jq -r ".host.emailAddress | select( . != null )" "$MB_XRPL_CONFIG")

            # Validating important configurations.
            ([ -z $xrpl_address ] || [ -z $key_file_path ] || [ -z $lease_amount ] || [ -z $extra_txn_fee ] || [ -z $email_address ]) && echo "Configuration file format has been altered." && exit 1
            if [ -n "$key_file_path" ] && [ -e "$key_file_path" ]; then
                # Change the ownership in case user is removed.
                chown "$MB_XRPL_USER": $key_file_path

                xrpl_secret=$(jq -r ".xrpl.secret | select( . != null )" "$key_file_path")

                ! validate_rippled_url "$rippled_server" && exit 1

                xrpl_secret=$(cat $key_file_path | jq -r '.xrpl.secret')

                ! [[ $xrpl_secret =~ ^s[1-9A-HJ-NP-Za-km-z]{25,35}$ ]] && echo "Invalid account secret." && exit 1

                echo "Checking configured account keys..."
                ! exec_jshelper validate-keys $rippled_server $xrpl_address $xrpl_secret && echo "Invalid account secret." && exit 1
            else
                echo "Cannot resume the installation due to secret path issue." && exit 1
            fi

            ! validate_positive_decimal $lease_amount && echo "Lease amount should be a numerical value greater than zero." && exit 1

            ! ([[ $extra_txn_fee =~ ^[0-9]+$ ]] && [[ $extra_txn_fee -ge 0 ]]) && echo "Extra fee amount should be an integer value greater than or equal zero." && exit 1

            ! validate_email_address $email_address && exit 1

            ipv6_subnet=$(jq -r ".networking.ipv6.subnet | select( . != null )" "$MB_XRPL_CONFIG")
            [ -z "$ipv6_subnet" ] && ipv6_subnet="-"
            ipv6_net_interface=$(jq -r ".networking.ipv6.interface | select( . != null )" "$MB_XRPL_CONFIG")
            [ -z "$ipv6_net_interface" ] && ipv6_net_interface="-"
        fi

        if [ -f "$SASHIMONO_CONFIG" ]; then
            echomult "\nReading configuration from existing Sashimono Agent configuration file..."

            # Get the owner and group of the sa config file.
            local owner=$(stat -c "%U" "$SASHIMONO_CONFIG")
            local group=$(stat -c "%G" "$SASHIMONO_CONFIG")
            local access=$(stat -c "%a" "$SASHIMONO_CONFIG")

            ([ "$owner" != "$root_user" ] || [ "$group" != "$root_user" ] || [ "$access" != "644" ]) &&
                echomult "\nConfiguration file permissions have been altered." &&
                exit 1

            inetaddr=$(jq -r ".hp.host_address | select( . != null )" "$SASHIMONO_CONFIG")
            init_peer_port=$(jq ".hp.init_peer_port | select( . != null )" "$SASHIMONO_CONFIG")
            init_user_port=$(jq ".hp.init_user_port | select( . != null )" "$SASHIMONO_CONFIG")
            alloc_cpu=$(jq -r ".system.max_cpu_us | select( . != null )" "$SASHIMONO_CONFIG")
            alloc_ramKB=$(jq -r ".system.max_mem_kbytes | select( . != null )" "$SASHIMONO_CONFIG")
            alloc_swapKB=$(jq -r ".system.max_swap_kbytes | select( . != null )" "$SASHIMONO_CONFIG")
            alloc_diskKB=$(jq -r ".system.max_storage_kbytes | select( . != null )" "$SASHIMONO_CONFIG")
            alloc_instcount=$(jq -r ".system.max_instance_count | select( . != null )" "$SASHIMONO_CONFIG")

            # Validating important configurations.
            ([ -z $inetaddr ] || [ -z $init_peer_port ] || [ -z $init_user_port ] || [ -z $alloc_cpu ] || [ -z $alloc_ramKB ] || [ -z $alloc_swapKB ] || [ -z $alloc_diskKB ] || [ -z $alloc_instcount ]) && echo "Configuration file format has been altered." && exit 1
        fi
    }

    function collect_host_xrpl_account_inputs() {
        while true; do
            read -ep "Specify the Xahau account address: " xrpl_address </dev/tty
            ! [[ $xrpl_address =~ ^r[0-9a-zA-Z]{24,34}$ ]] && echo "Invalid Xahau account address." && continue

            read -ep "Specify the Xahau account secret: " xrpl_secret </dev/tty
            ! [[ $xrpl_secret =~ ^s[1-9A-HJ-NP-Za-km-z]{25,35}$ ]] && echo "Invalid account secret." && continue

            echo "Checking account keys..."
            ! exec_jshelper validate-keys $rippled_server $xrpl_address $xrpl_secret && xrpl_secret="" && continue

            break
        done
    }

    function set_host_xrpl_account() {

        [ ! -z $1 ] && operation=$1 || operation="register"

        # Take only user input if this is for transfer or deregister
        if [[ "$xrpl_secret" == "-" ]] && ([[ "$operation" == "transfer" ]] || [[ "$operation" == "deregister" ]]); then
            collect_host_xrpl_account_inputs

            return 0
        fi

        if [ "$xrpl_secret" == "-" ]; then
            confirm "\nDo you want to use the default key file path ${default_key_filepath} to save the new account key?" && key_file_path=$default_key_filepath

            if [ "$key_file_path" != "$default_key_filepath" ]; then
                while true; do
                    read -ep "Specify the preferred key file path: " key_file_path </dev/tty
                    parent_directory=$(dirname "$key_file_path")

                    canonicalized_directory=$(realpath "$parent_directory")
                    root_directory="/root"
                    canonicalized_root=$(realpath "$root_directory")

                    if [[ "$canonicalized_directory" == "$canonicalized_root"* ]]; then
                        echo "Key should not be located in /root directory." && continue
                    fi

                    ! [ -e "$parent_directory" ] && echo "Invalid directory path." || break
                done
            fi

            key_dir=$(dirname "$key_file_path")
            if [ ! -d "$key_dir" ]; then
                mkdir -p "$key_dir"
            fi

            if [ "$key_file_path" == "$default_key_filepath" ]; then
                parent_directory=$(dirname "$key_file_path")
                chmod -R 550 "$parent_directory" &&
                    chown -R $MB_XRPL_USER: "$parent_directory" || {
                    echomult "Error occurred in permission and ownership assignment of key file directory."
                    exit 1
                }
            fi

            if [ -e "$key_file_path" ]; then
                if confirm "The file '$key_file_path' already exists. Do you want to continue using that key file?\nPressing 'n' would terminate the installation."; then
                    echomult "Continuing with the existing key file."
                    existing_secret=$(jq -r '.xrpl.secret' "$key_file_path" 2>/dev/null)
                    if [ "$existing_secret" != "null" ] && [ "$existing_secret" != "-" ]; then
                        while true; do
                            account_json=$(exec_jshelper generate-account $existing_secret) && break
                            echo "Error occurred when existing account retrieval."
                            confirm "\nDo you want to retry?\nPressing 'n' would terminate the installation." || exit 1
                        done

                        xrpl_address=$(jq -r '.address' <<<"$account_json")
                        xrpl_secret=$(jq -r '.secret' <<<"$account_json")

                        chmod 440 "$key_file_path" &&
                            chown $MB_XRPL_USER: $key_file_path || {
                            echomult "Error occurred in permission and ownership assignment of key file."
                            exit 1
                        }

                        echomult "Retrived account details via secret.\n"
                        return 0
                    else
                        echomult "Error: Existing secret file does not have the expected format."
                        exit 1
                    fi
                else
                    exit 1
                fi
            else
                ! confirm "\nAre you performing a fresh Evernode installation?
                 \nNOTE: Pressing 'n' implies that you are in the process of transferring from a previous installation in $NETWORK." && operation="re-register"

                if [ "$operation" == "register" ]; then
                    generate_keys
                else
                    collect_host_xrpl_account_inputs
                fi

                echo "{ \"xrpl\": { \"secret\": \"$xrpl_secret\" } }" >"$key_file_path" &&
                    chmod 440 "$key_file_path" &&
                    chown $MB_XRPL_USER: $key_file_path &&
                    echomult "Key file saved successfully at $key_file_path" || {
                    echomult "Error occurred in permission and ownership assignment of key file."
                    exit 1
                }
            fi
        fi
    }

    function set_host_reputationd_account() {

        confirm "\nDo you want to use the default key file path ${default_reputationd_key_filepath} to save the new account key?" && reputationd_key_file_path=$default_reputationd_key_filepath

        if [ "$reputationd_key_file_path" != "$default_reputationd_key_filepath" ]; then
            while true; do
                read -ep "Specify the preferred key file path: " key_file_path </dev/tty
                parent_directory=$(dirname "$reputationd_key_file_path")

                canonicalized_directory=$(realpath "$parent_directory")
                root_directory="/root"
                canonicalized_root=$(realpath "$root_directory")

                if [[ "$canonicalized_directory" == "$canonicalized_root"* ]]; then
                    echo "Key should not be located in /root directory." && continue
                fi

                ! [ -e "$parent_directory" ] && echo "Invalid directory path." || break
            done
        fi

        reputationd_key_dir=$(dirname "$reputationd_key_file_path")
        if [ ! -d "$reputationd_key_dir" ]; then
            mkdir -p "$reputationd_key_dir"
        fi

        if [ "$reputationd_key_file_path" == "$default_reputationd_key_filepath" ]; then
            parent_directory=$(dirname "$reputationd_key_file_path")
            chmod -R 550 "$parent_directory" &&
                chown -R $REPUTATIOND_USER: "$parent_directory" || {
                echomult "Error occurred in permission and ownership assignment of key file directory."
                return 1
            }
        fi

        if [ -e "$reputationd_key_file_path" ]; then
            if confirm "The file '$reputationd_key_file_path' already exists. Do you want to continue using that key file?\nPressing 'n' would terminate the installation."; then
                echomult "Continuing with the existing key file."
                reputationd_existing_secret=$(jq -r '.xrpl.secret' "$reputationd_key_file_path" 2>/dev/null)
                if [ "$reputationd_existing_secret" != "null" ] && [ "$reputationd_existing_secret" != "-" ]; then
                    while true; do
                        account_json=$(exec_jshelper generate-account $reputationd_existing_secret) && break
                        echo "Error occurred when existing account retrieval."
                        confirm "\nDo you want to retry?\nPressing 'n' would terminate the installation." || return 1
                    done

                    reputationd_xrpl_address=$(jq -r '.address' <<<"$account_json")
                    reputationd_xrpl_secret=$(jq -r '.secret' <<<"$account_json")

                    chmod 440 "$reputationd_key_file_path" &&
                        chown $REPUTATIOND_USER: $reputationd_key_file_path || {
                        echomult "Error occurred in permission and ownership assignment of key file."
                        exit 1
                    }

                    echomult "Retrived account details via secret.\n"
                    return 0
                else
                    echomult "Error: Existing secret file does not have the expected format."
                    exit 1
                fi
            else
                exit 1
            fi
        else
            generate_keys "reputationd"

            echo "{ \"xrpl\": { \"secret\": \"$reputationd_xrpl_secret\" } }" >"$reputationd_key_file_path" &&
                chmod 440 "$reputationd_key_file_path" &&
                chown $REPUTATIOND_USER: $reputationd_key_file_path &&
                echomult "Key file saved successfully at $reputationd_key_file_path" || {
                echomult "Error occurred in permission and ownership assignment of key file."
                exit 1
            }
        fi
    }

    function prepare_host() {
        ([ -z $rippled_server ] || [ -z $xrpl_address ] || [ -z $key_file_path ] || [ -z $xrpl_secret ] || [ -z $inetaddr ]) && echo "No params specified." && return 1

        local inc_reserves_count=$((1 + 1 + $alloc_instcount))
        while true; do
            local min_reserve_requirement=$(exec_jshelper compute-xah-requirement $rippled_server $inc_reserves_count) && break
            echo "Error occurred in min XAH calculation."
            confirm "\nDo you want to retry?\nPressing 'n' would terminate the installation." || exit 1
        done

        local min_xah_requirement=$(echo "$MIN_OPERATIONAL_COST_PER_MONTH*$MIN_OPERATIONAL_DURATION + $min_reserve_requirement" | bc)

        while true; do
            local min_evr_requirement=$(exec_jshelper compute-evr-requirement $rippled_server $EVERNODE_GOVERNOR_ADDRESS $xrpl_address) && break
            echo "Error occurred in min EVR calculation."
            confirm "\nDo you want to retry?\nPressing 'n' would terminate the installation." || exit 1
        done

        local need_xah=$(echo "$min_xah_requirement > 0" | bc -l)
        local need_evr=$(echo "$min_evr_requirement > 0" | bc -l)

        local message="Your host account with the address $xrpl_address will be on Xahau $NETWORK.
        \nThe secret key of the account is located at $key_file_path.
        \nNOTE: It is your responsibility to safeguard/backup this file in a secure manner.
        \nIf you lose it, you will not be able to access any funds in your Host account. NO ONE else can recover it.
        \n\nThis is the account that will represent this host on the Evernode host registry. You need to load up the account with following funds in order to continue with the installation."

        [[ "$need_xah" -eq 1 ]] && message="$message\n(*) At least $min_xah_requirement XAH to cover regular transaction fees for the first three months."
        [[ "$need_evr" -eq 1 ]] && message="$message\n(*) At least $min_evr_requirement EVR to cover Evernode registration."

        message="$message\n\nYou can scan the following QR code in your wallet app to send funds based on the account condition:\n"

        echomult "$message"

        generate_qrcode "$xrpl_address"

        if [[ "$need_xah" -eq 1 ]]; then
            echomult "\nChecking the account condition..."
            echomult "To set up your host account, ensure a deposit of $min_xah_requirement XAH to cover the regular transaction fees for the first three months."

            while true; do
                wait_call "exec_jshelper check-balance $rippled_server $EVERNODE_GOVERNOR_ADDRESS $xrpl_address NATIVE $min_xah_requirement" "[OUTPUT] XAH balance is there in your host account." &&
                    break
                confirm "\nDo you want to re-check the balance?\nPressing 'n' would terminate the installation." || exit 1
            done

            # Adding 2 second sleep to avoid account not found.
            sleep 2
        fi

        echomult "\nPreparing host account..."
        while true; do
            wait_call "exec_jshelper prepare-host $rippled_server $EVERNODE_GOVERNOR_ADDRESS $xrpl_address $xrpl_secret $inetaddr $extra_txn_fee" "Account preparation is successfull." && break
            confirm "\nDo you want to re-try account preparation?\nPressing 'n' would terminate the installation." || exit 1
        done

        if [[ "$need_evr" -eq 1 ]]; then
            echomult "\n\nIn order to register in Evernode you need to have $min_evr_requirement EVR balance in your host account. Please deposit the required registration fee in EVRs.
        \nYou can scan the provided QR code in your wallet app to send funds:"

            while true; do
                wait_call "exec_jshelper check-balance $rippled_server $EVERNODE_GOVERNOR_ADDRESS $xrpl_address ISSUED $min_evr_requirement" "[OUTPUT] EVR balance is there in your host account." &&
                    break
                confirm "\nDo you want to re-check the balance?\nPressing 'n' would terminate the installation." || exit 1
            done
        fi
    }

    function install_failure() {
        echomult "There was an error during installation.
            \nPlease provide the file $logfile to the Evernode team by visiting this link: $report_url.
            \nThank you."
        exit 1
    }

    function uninstall_failure() {
        echo "There was an error during uninstallation."
        exit 1
    }

    function online_version_timestamp() {
        latest_version_data=$(curl -s "$latest_version_endpoint")
        latest_version_timestamp=$(echo "$latest_version_data" | jq -r '.published_at')
        echo "$latest_version_timestamp"
    }

    function enable_evernode_auto_updater() {
        [ "$EUID" -ne 0 ] && echo "Please run with root privileges (sudo)." && exit 1

        # Create the service.
        echo "[Unit]
Description=Service for the Evernode auto-update.
After=network.target
[Service]
User=root
Group=root
Type=oneshot
ExecStart=/usr/bin/evernode update -q
[Install]
WantedBy=multi-user.target" >/etc/systemd/system/$EVERNODE_AUTO_UPDATE_SERVICE.service

        # Create a timer for the service (every two hours).
        echo "[Unit]
Description=Timer for the Evernode auto-update.
# Allow manual starts
RefuseManualStart=no
# Allow manual stops
RefuseManualStop=no
[Timer]
Unit=$EVERNODE_AUTO_UPDATE_SERVICE.service
OnCalendar=0/12:00:00
# Execute job if it missed a run due to machine being off
Persistent=true
# To prevent rush time, adding 2 hours delay
RandomizedDelaySec=7200
[Install]
WantedBy=timers.target" >/etc/systemd/system/$EVERNODE_AUTO_UPDATE_SERVICE.timer

        # Reload the systemd daemon.
        systemctl daemon-reload

        echo "Enabling Evernode auto update service..."
        systemctl enable $EVERNODE_AUTO_UPDATE_SERVICE.service

        echo "Enabling Evernode auto update timer..."
        systemctl enable $EVERNODE_AUTO_UPDATE_SERVICE.timer
        echo "Starting Evernode auto update timer..."
        systemctl start $EVERNODE_AUTO_UPDATE_SERVICE.timer
    }

    function remove_evernode_auto_updater() {
        [ "$EUID" -ne 0 ] && echo "Please run with root privileges (sudo)." && exit 1

        local service_removed=false

        # Remove auto updater service if exists.
        local service_path="/etc/systemd/system/$EVERNODE_AUTO_UPDATE_SERVICE.timer"
        if [ -f $service_path ]; then
            echo "Removing Evernode auto update timer..."
            systemctl stop $EVERNODE_AUTO_UPDATE_SERVICE.timer
            systemctl disable $EVERNODE_AUTO_UPDATE_SERVICE.timer
            rm -f $service_path
            local service_removed=true
        fi

        local service_path="/etc/systemd/system/$EVERNODE_AUTO_UPDATE_SERVICE.service"
        if [ -f $service_path ]; then
            echo "Removing Evernode auto update service..."
            systemctl stop $EVERNODE_AUTO_UPDATE_SERVICE.service
            systemctl disable $EVERNODE_AUTO_UPDATE_SERVICE.service
            rm -f $service_path
            local service_removed=true
        fi

        # Reload the systemd daemon.
        $service_removed && systemctl daemon-reload
    }

    function install_evernode() {
        local upgrade=$1

        # Get installer version (timestamp). We use this later to check for Evernode software updates.
        local installer_version_timestamp=$(online_version_timestamp)
        [ -z "$installer_version_timestamp" ] && echo "Online installer not found." && exit 1

        local tmp=$(mktemp -d)
        cd $tmp
        curl --silent -L $installer_url --output installer.tgz
        tar zxf $tmp/installer.tgz --strip-components=1
        rm installer.tgz

        set -o pipefail # We need installer exit code to detect failures (ignore the tee pipe exit code).
        mkdir -p $log_dir
        logfile="$log_dir/installer-$(date +%s).log"

        if [ "$upgrade" == "0" ]; then
            echo "Installing other prerequisites..."
            ! ./prereq.sh $cgrulesengd_service 2>&1 |
                tee -a >(stdbuf --output=L awk '{ cmd="date -u +\"%Y-%m-%d %H:%M:%S\""; cmd | getline utc_time; close(cmd); print utc_time, $0 }' >>$logfile) | stdbuf --output=L grep -E 'STAGE' |
                while read -r line; do
                    cleaned_line=$(echo "$line" | sed -E 's/STAGE//g' | awk '{sub(/^[ \t]+/, ""); print}')
                    [[ $cleaned_line =~ ^-p(.*)$ ]] && echo -e "\\e[1A\\e[K${cleaned_line}" || echo "${cleaned_line}"
                done && install_failure
        fi

        # Currently the domain address saved only in account_info and an empty value in Hook states.
        # Set description to empty value ('_' will be treated as empty)
        description="_"

        echo "Installing Sashimono..."

        # Read registry address on upgrade mode.
        if [ "$upgrade" == "0" ]; then
            while true; do
                registry_address=$(exec_jshelper access-evernode-cfg $rippled_server $EVERNODE_GOVERNOR_ADDRESS registryAddress) && break
                echo "Error occurred getting registry address."
                confirm "\nDo you want to retry?\nPressing 'n' would terminate the installation." || exit 1
            done
        fi

        # Reputationd
        # Create REPUTATIOND_USER if does not exists..
        if ! grep -q "^$REPUTATIOND_USER:" /etc/passwd; then
            useradd --shell /usr/sbin/nologin -m $REPUTATIOND_USER 2>/dev/null

            # Setting the ownership of the REPUTATIOND_USER's home to REPUTATIOND_USER expilcity.
            # NOTE : There can be user id mismatch, as we do not delete REPUTATIOND_USER's home in the uninstallation even though the user is removed.
            chown -R "$REPUTATIOND_USER":"$SASHIADMIN_GROUP" /home/$REPUTATIOND_USER

        fi

        # Assign reputationd user priviledges.
        if ! id -nG "$REPUTATIOND_USER" | grep -qw "$SASHIADMIN_GROUP"; then
            usermod --lock $REPUTATIOND_USER
            usermod -a -G $SASHIADMIN_GROUP $REPUTATIOND_USER
            loginctl enable-linger $REPUTATIOND_USER # Enable lingering to support service installation.
        fi

        # Filter logs with STAGE prefix and ommit the prefix when echoing.
        # If STAGE log contains -p arg, move the cursor to previous log line and overwrite the log.
        ! UPGRADE=$upgrade EVERNODE_REGISTRY_ADDRESS=$registry_address ./sashimono-install.sh $inetaddr $init_peer_port $init_user_port $countrycode $alloc_instcount \
            $alloc_cpu $alloc_ramKB $alloc_swapKB $alloc_diskKB $lease_amount $rippled_server $xrpl_address $key_file_path $email_address \
            $tls_key_file $tls_cert_file $tls_cabundle_file $description $ipv6_subnet $ipv6_net_interface $extra_txn_fee $fallback_rippled_servers 2>&1 |
            tee -a >(stdbuf --output=L grep -v "\[INFO\]" | awk '{ cmd="date -u +\"%Y-%m-%d %H:%M:%S\""; cmd | getline utc_time; close(cmd); print utc_time, $0 }' >>$logfile) | stdbuf --output=L grep -E '\[STAGE\]|\[INFO\]' |
            while read -r line; do
                cleaned_line=$(echo "$line" | sed -E 's/\[STAGE\]|\[INFO\]//g' | awk '{sub(/^[ \t]+/, ""); print}')
                [[ $cleaned_line =~ ^-p(.*)$ ]] && echo -e "\\e[1A\\e[K${cleaned_line:3}" || echo "${cleaned_line}"
            done && install_failure

        ! create_evernode_alias && install_failure

        set +o pipefail

        rm -r $tmp

        # Write the verison timestamp to a file for later updated version comparison.
        echo $installer_version_timestamp >$SASHIMONO_DATA/$installer_version_timestamp_file
        if [ "$upgrade" == "0" ]; then
            if confirm "\nWould you like to opt-in to the Evernode reputation and reward system?"; then
                if ! configure_reputationd 0; then
                    echomult "\nError occured configuring ReputationD!!\n You can retry opting-in by executing 'evernode reputationd' after installation.\n"
                else
                    echomult "\nReputationD configuration successfull!!\n"
                fi
            else
                echomult "\nSkipped from opting-in Evernode reputation and reward system.\nYou can opt-in later by using 'evernode reputationd' command.\n"
            fi
        else
            #[ "$upgrade" == "1" ]
            if sudo -u "$REPUTATIOND_USER" [ -f "/home/$REPUTATIOND_USER/.config/systemd/user/$REPUTATIOND_SERVICE.service" ]; then
                #reputationd_enabled=true
                echo "Configuring Evernode reputation and reward system."
                if ! configure_reputationd 1; then
                    echomult "\nError occured configuring ReputationD!!\n You can retry opting-in by executing 'evernode reputationd' after installation.\n"
                else
                    echomult "\nReputationD configuration successfull!!\n"
                fi
            else
                echo "You are not opted-in to Evernode reputation and reward system."
            fi
        fi
    }

    function check_exisiting_contracts() {

        local upgrade=$1

        # Check the condition of existing contract instances.
        local users=$(cut -d: -f1 /etc/passwd | grep "^$SASHIUSER_PREFIX" | sort)
        readarray -t userarr <<<"$users"
        local sashiusers=()
        for user in "${userarr[@]}"; do
            [ ${#user} -lt 24 ] || [ ${#user} -gt 32 ] || [[ ! "$user" =~ ^$SASHIUSER_PREFIX[0-9]+$ ]] && continue
            sashiusers+=("$user")
        done
        local ucount=${#sashiusers[@]}

        if [ "$upgrade" == "0" ]; then
            $interactive && [ $ucount -gt 0 ] && ! confirm "This will delete $ucount contract instances. \n\nDo you still want to continue?" && exit 1
            ! $interactive && echo "$ucount contract instances will be deleted."
        fi
    }

    function uninstall_evernode() {

        local upgrade=$1

        if ! $transfer; then
            [ "$upgrade" == "0" ] && echo "Uninstalling..." || echo "Uninstalling for upgrade..."
            ! UPGRADE=$upgrade TRANSFER=0 $SASHIMONO_BIN/sashimono-uninstall.sh $2 && uninstall_failure

        else
            echo "Intiating Transfer..."
            echo "Uninstalling for transfer..."
            ! UPGRADE=$upgrade TRANSFER=1 $SASHIMONO_BIN/sashimono-uninstall.sh $2 && uninstall_failure
        fi
        # Remove the evernode alias at the end.
        # So, if the uninstallation failed user can try uninstall again with evernode commands.
        remove_evernode_alias
    }

    function update_evernode() {
        echo "Checking for updates..."
        local latest_installer_script_version=$(online_version_timestamp)
        [ -z "$latest_installer_script_version" ] && echo "Could not check for updates. Online installer not found." && exit 1

        local current_installer_script_version=$(cat $SASHIMONO_DATA/$installer_version_timestamp_file)
        [ "$latest_installer_script_version" == "$current_installer_script_version" ] && echo "Your $evernode installation is up to date." && exit 0

        echo "New $evernode update available. Setup will re-install $evernode with updated software. Your account and contract instances will be preserved."
        $interactive && ! confirm "\nDo you want to install the update?" && exit 1

        echo "Starting upgrade..."
        # Alias for setup.sh is created during 'install_evernode' too.
        # If only the setup.sh is updated but not the installer, then the alias should be created again.
        if [ "$latest_installer_script_version" != "$current_installer_script_version" ]; then
            # This is added temporary to remove auto updater. This can later be removed.
            remove_evernode_auto_updater
            install_evernode 1
        fi

        rm -r $setup_helper_dir >/dev/null 2>&1
    }

    function init_evernode_transfer() {

        if ! sudo -u $MB_XRPL_USER MB_DATA_DIR=$MB_XRPL_DATA node $MB_XRPL_BIN transfer $transferee_address &&
            [ "$force" != "-f" ] && [ -f $mb_service_path ]; then
            ! confirm "Evernode transfer initiation was failed. Still do you want to continue the unistallation?" && echo "Aborting unistallation. Try again later." && exit 1
            echo "Continuing uninstallation..."
        fi

    }

    function create_log() {
        if sudo -u "$REPUTATIOND_USER" [ -f "/home/$REPUTATIOND_USER/.config/systemd/user/$REPUTATIOND_SERVICE.service" ]; then
            reputationd_enabled=true
        else
            reputationd_enabled=false
        fi
        tempfile=$(mktemp /tmp/evernode.XXXXXXXXX.log)
        {
            echo "System:"
            uname -r
            lsb_release -a
            echo ""
            echo "sa.cfg:"
            cat "$SASHIMONO_DATA/sa.cfg"
            echo ""
            echo "mb-xrpl.cfg:"
            cat "$MB_XRPL_CONFIG"
            echo ""
            echo "Sashimono log:"
            journalctl -u sashimono-agent.service | tail -n 200
            echo ""
            echo "Message board log:"
            sudo -u sashimbxrpl bash -c journalctl --user -u sashimono-mb-xrpl | tail -n 200
            echo ""
            if [[ "$reputationd_enabled" == "true" ]]; then
                echo "Reputationd log:"
                sudo -u sashireputationd bash -c journalctl --user -u sashimono-reputationd | tail -n 200
            else
                echo "Reputation and reward system is not enabled."
            fi
        } >"$tempfile" 2>&1
        echo "Evernode log saved to $tempfile"
    }

    # Create a copy of this same script as a command.
    function create_evernode_alias() {
        ! curl -fsSL $setup_script_url --output $evernode_alias >>$logfile 2>&1 && echo "Error in creating alias." && return 1
        ! chmod +x $evernode_alias >>$logfile 2>&1 && echo "Error in changing permission for the alias." && return 1
        return 0
    }

    function remove_evernode_alias() {
        rm $evernode_alias
    }

    function check_installer_pending_finish() {
        if [ -f /run/reboot-required.pkgs ] && [ -n "$(grep sashimono /run/reboot-required.pkgs)" ]; then
            echo "Your system needs to be rebooted in order to complete Sashimono installation."
            confirm "Reboot now?" && reboot
            return 0
        else
            # If reboot not required, check whether re-login is required in case the setup was run with sudo.
            # This is because the user account gets added to sashiadmin group and re-login is needed for group permission to apply.
            # without this, user cannot run "sashi" cli commands without sudo.
            if [ "$mode" == "install" ] && [ -n "$SUDO_USER" ]; then
                echo "You need to logout and log back in, to complete Sashimono installation."
                return 0
            else
                return 1
            fi
        fi
    }

    function reputationd_info() {
        if sudo -u "$REPUTATIOND_USER" [ -f "/home/$REPUTATIOND_USER/.config/systemd/user/$REPUTATIOND_SERVICE.service" ]; then
            reputationd_enabled=true
        else
            reputationd_enabled=false
        fi
        local reputationd_user_id=$(id -u "$REPUTATIOND_USER")
        local reputationd_user_runtime_dir="/run/user/$reputationd_user_id"
        local evernode_reputationd_status=$(sudo -u "$REPUTATIOND_USER" XDG_RUNTIME_DIR="$reputationd_user_runtime_dir" systemctl --user is-active $REPUTATIOND_SERVICE)
        echo "Evernode reputationd status: $evernode_reputationd_status"
        if [[ $reputationd_enabled == true ]]; then
            echo -e "\nYour reputationd account details are stored in $REPUTATIOND_DATA/reputationd.cfg"
        fi
    }

    function reg_info() {
        local reg_info=$(MB_DATA_DIR=$MB_XRPL_DATA node $MB_XRPL_BIN reginfo || echo ERROR)
        local error=$(echo "$reg_info" | tail -1)
        [ "$error" == "ERROR" ] && echo "${reg_info/ERROR/""}" && exit 1

        # Get raddress from first line.
        local address_line=$(echo "$reg_info" | head -2 | tail -1)
        local host_address=$(echo "$address_line" | awk -F : ' { print $2 } ')
        echo -e "\n$address_line\n"
        generate_qrcode "$host_address"

        # Remove first line and print.
        echo -e "\n${reg_info/$address_line/""}" | sed '/MB_CLI_SUCCESS/d'

        echo -e "NOTE: If the Host status is shown as inactive it will be marked as active after sending the next heartbeat.\n"

        local sashimono_agent_status=$(systemctl is-active sashimono-agent.service)
        local mb_user_id=$(id -u "$MB_XRPL_USER")
        local mb_user_runtime_dir="/run/user/$mb_user_id"
        local sashimono_mb_xrpl_status=$(sudo -u "$MB_XRPL_USER" XDG_RUNTIME_DIR="$mb_user_runtime_dir" systemctl --user is-active $MB_XRPL_SERVICE)
        echo "Sashimono agent status: $sashimono_agent_status"
        echo "Sashimono message board status: $sashimono_mb_xrpl_status"
        echo -e "\nYour registration account details are stored in $MB_XRPL_DATA/mb-xrpl.cfg"
        echo ""

        reputationd_info
    }

    function get_country_code() {
        local reg_info=$(MB_DATA_DIR=$MB_XRPL_DATA node $MB_XRPL_BIN reginfo || echo ERROR)
        local error=$(echo "$reg_info" | tail -1)
        [ "$error" == "ERROR" ] && echo "${reg_info/ERROR/""}" && exit 1

        local country_code_line=$(echo "$reg_info" | tail -2 | head -1)
        local country_code=$(echo "$country_code_line" | awk -F : ' { print $2 } ')
        echo -e "$country_code"
    }

    function check_sanctioned() {
        if [ -z "$1" ]; then
            echo "Invalid country code received." && exit 1
        fi
        sanctioned_countries=("KP" "RU" "VE" "CU" "IR" "SY")
        local countrycode=$1

        if echo "${sanctioned_countries[*]}" | grep -qiw $countrycode; then
            echo "Sanctioned country code detected. Unable to install or update $evernode." && exit 1
        else
            return 0
        fi
    }

    function apply_ssl() {
        [ "$EUID" -ne 0 ] && echo "Please run with root privileges (sudo)." && exit 1

        local tls_key_file=$1
        local tls_cert_file=$2
        local tls_cabundle_file=$3

        ([ ! -f "$tls_key_file" ] || [ ! -f "$tls_cert_file" ] ||
            ([ "$tls_cabundle_file" != "" ] && [ ! -f "$tls_cabundle_file" ])) &&
            echo -e "One or more invalid files provided.\nusage: applyssl <private key file> <cert file> <ca bundle file (optional)>" && exit 1

        echo "Applying new SSL certificates for $evernode"
        echo "Key: $tls_key_file" && cp $tls_key_file $SASHIMONO_DATA/contract_template/cfg/tlskey.pem || exit 1
        echo "Cert: $tls_cert_file" && cp $tls_cert_file $SASHIMONO_DATA/contract_template/cfg/tlscert.pem || exit 1
        # ca bundle is optional.
        [ "$tls_cabundle_file" != "" ] && echo "CA bundle: $tls_cabundle_file" && (cat $tls_cabundle_file >>$SASHIMONO_DATA/contract_template/cfg/tlscert.pem || exit 1)

        sashi list | jq -rc '.[]' | while read -r inst; do
            local instuser=$(echo $inst | jq -r '.user')
            local instname=$(echo $inst | jq -r '.name')
            echo -e "\nStopping contract instance $instname" && sashi stop -n $instname &&
                echo "Updating SSL certificates" &&
                cp $SASHIMONO_DATA/contract_template/cfg/tlskey.pem $SASHIMONO_DATA/contract_template/cfg/tlscert.pem /home/$instuser/$instname/cfg/ &&
                chmod 644 /home/$instuser/$instname/cfg/tlscert.pem && chmod 600 /home/$instuser/$instname/cfg/tlskey.pem &&
                chown -R $instuser:$instuser /home/$instuser/$instname/cfg/*.pem &&
                echo -e "Starting contract instance $instname" && sashi start -n $instname
        done

        echo "Done."
    }

    function reconfig_sashi() {
        echomult "configuring sashimono...\n"

        ! $SASHIMONO_BIN/sagent reconfig $SASHIMONO_DATA $alloc_instcount $alloc_cpu $alloc_ramKB $alloc_swapKB $alloc_diskKB &&
            echomult "There was an error in updating sashimono configuration." && return 1

        # Update cgroup allocations.
        ([[ $alloc_ramKB -gt 0 ]] || [[ $alloc_swapKB -gt 0 ]] || [[ $alloc_instcount -gt 0 ]]) &&
            echomult "Updating the cgroup configuration..." &&
            ! $SASHIMONO_BIN/user-cgcreate.sh $SASHIMONO_DATA && echomult "Error occured while upgrading cgroup allocations" && return 1

        # Update disk quotas.
        if ([[ $alloc_diskKB -gt 0 ]] || [[ $alloc_instcount -gt 0 ]]); then
            echomult "Updating the disk quotas..."

            users=$(cut -d: -f1 /etc/passwd | grep "^$SASHIUSER_PREFIX" | sort)
            readarray -t userarr <<<"$users"
            sashiusers=()
            for user in "${userarr[@]}"; do
                [ ${#user} -lt 24 ] || [ ${#user} -gt 32 ] || [[ ! "$user" =~ ^$SASHIUSER_PREFIX[0-9]+$ ]] && continue
                sashiusers+=("$user")
            done

            max_storage_kbytes=$(jq '.system.max_storage_kbytes' $saconfig)
            max_instance_count=$(jq '.system.max_instance_count' $saconfig)
            disk=$(expr $max_storage_kbytes / $max_instance_count)
            ucount=${#sashiusers[@]}
            if [ $ucount -gt 0 ]; then
                for user in "${sashiusers[@]}"; do
                    setquota -g -F vfsv0 "$user" "$disk" "$disk" 0 0 /
                done
            fi
        fi

        return 0
    }

    function reconfig_mb() {
        echomult "configuring message board...\n"

        ! sudo -u $MB_XRPL_USER MB_DATA_DIR=$MB_XRPL_DATA node $MB_XRPL_BIN reconfig $lease_amount $alloc_instcount $rippled_server $ipv6_subnet $ipv6_net_interface $extra_txn_fee $fallback_rippled_servers &&
            echo "There was an error in updating message board configuration." && return 1
        return 0
    }

    function config() {
        alloc_instcount=0
        alloc_cpu=0
        alloc_ramKB=0
        alloc_swapKB=0
        alloc_diskKB=0
        lease_amount=0
        rippled_server='-'
        ipv6_subnet='-'
        ipv6_net_interface='-'
        extra_txn_fee='-'
        fallback_rippled_servers='-'

        local saconfig="$SASHIMONO_DATA/sa.cfg"
        local max_instance_count=$(jq '.system.max_instance_count' $saconfig)
        local max_mem_kbytes=$(jq '.system.max_mem_kbytes' $saconfig)
        local max_swap_kbytes=$(jq '.system.max_swap_kbytes' $saconfig)
        local max_storage_kbytes=$(jq '.system.max_storage_kbytes' $saconfig)

        local mbconfig="$MB_XRPL_CONFIG"
        local cfg_lease_amount=$(jq '.xrpl.leaseAmount' $mbconfig)
        local cfg_rippled_server=$(jq -r '.xrpl.rippledServer' $mbconfig)
        local cfg_extra_txn_fee=$(jq '.xrpl.affordableExtraFee' $mbconfig)
        [[ "$cfg_extra_txn_fee" == "null" ]] && cfg_extra_txn_fee=0
        ! read_fallback_rippled_servers_from_config && exit 1
        local cfg_fb_rippled_servers="$read_fallback_rippled_servers_res"

        local cfg_ipv6_subnet=$(jq -r '.networking.ipv6.subnet' $mbconfig)
        local cfg_ipv6_net_interface=$(jq -r '.networking.ipv6.interface' $mbconfig)

        local update_sashi=0
        local update_mb=0

        local sub_mode=${1}
        local occupied_instance_count=$(sashi list | jq length)

        if [ "$sub_mode" == "resources" ]; then

            local ramMB=${2}     # memory to allocate for contract instances.
            local swapMB=${3}    # Swap to allocate for contract instances.
            local diskMB=${4}    # Disk space to allocate for contract instances.
            local instcount=${5} # Total contract instance count.

            [ -z $ramMB ] && [ -z $swapMB ] && [ -z $diskMB ] && [ -z $instcount ] &&
                echomult "Your current resource allocation is:
                \n Memory: $(GB $max_mem_kbytes)
                \n Swap: $(GB $max_swap_kbytes)
                \n Disk space: $(GB $max_storage_kbytes)
                \n Instance count: $max_instance_count\n" && exit 0

            local help_text="Usage: evernode config resources | evernode config resources <memory MB> <swap MB> <disk MB> <max instance count>\n"
            if ([ ! -z $ramMB ] && [[ $ramMB != 0 ]]); then
                local ramKB=$(free | grep Mem | awk '{print $2}')
                local max_ram_mb=$((ramKB / 1000))
                ! validate_positive_decimal $ramMB && echomult "Invalid memory size.\n $help_text" && exit 1
                [[ $ramMB -lt $min_ram_mb ]] &&
                    echomult "Minimum memory size should be "$min_ram_mb" MB.\n" && exit 1
                [[ $ramMB -gt $max_ram_mb ]] && echomult "Insufficient memory on your host. Maximum available memory is "$max_ram_mb" MB.\n" && exit 1
            fi
            if ([ ! -z $swapMB ] && [[ $swapMB != 0 ]]); then
                local swapKB=$(free | grep -i Swap | awk '{print $2}')
                local max_swap_mb=$((swapKB / 1000))
                ! validate_positive_decimal $swapMB && echomult "Invalid swap size.\n $help_text" && exit 1
                [[ $swapMB -lt $min_swap_mb ]] &&
                    echomult "Minimum swap size should be "$min_swap_mb" MB.\n " && exit 1
                [[ $swapMB -gt $max_swap_mb ]] && echomult "Insufficient swap on your host. Maximum available swap is "$max_swap_mb" MB.\n" && exit 1
            fi
            if ([ ! -z $diskMB ] && [[ $diskMB != 0 ]]); then
                local diskKB=$(df | grep -w /home | head -1 | awk '{print $4}')
                [ -z "$diskKB" ] && local diskKB=$(df | grep -w / | head -1 | awk '{print $4}')
                local max_disk_mb=$((diskKB / 1000))
                ! validate_positive_decimal $diskMB && echomult "Invalid disk size.\n $help_text" && exit 1
                [[ $diskMB -lt $min_disk_mb ]] &&
                    echomult "Minimum disk size should be "$min_disk_mb" MB.\n" && exit 1
                [[ $diskMB -gt $max_disk_mb ]] && echomult "Insufficient disk on your host. Maximum available disk is "$max_disk_mb" MB.\n" && exit 1
            fi
            [ ! -z $instcount ] && [[ $instcount != 0 ]] && ! validate_positive_decimal $instcount &&
                echomult "Invalid instance count.\n   $help_text" && exit 1

            [ -z $instcount ] && instcount=0
            alloc_instcount=$instcount
            alloc_ramKB=$((ramMB * 1000))
            alloc_swapKB=$((swapMB * 1000))
            alloc_diskKB=$((diskMB * 1000))

            ( ([[ $alloc_instcount -eq 0 ]] || [[ $max_instance_count == $alloc_instcount ]]) &&
                ([[ $alloc_ramKB -eq 0 ]] || [[ $max_mem_kbytes == $alloc_ramKB ]]) &&
                ([[ $alloc_swapKB -eq 0 ]] || [[ $max_swap_kbytes == $alloc_swapKB ]]) &&
                ([[ $alloc_diskKB -eq 0 ]] || [[ $max_storage_kbytes == $alloc_diskKB ]])) &&
                echomult "Resource configuration values are already configured!\n" && exit 0

            echomult "Using allocation"
            [[ $alloc_ramKB -gt 0 ]] && echomult "$(GB $alloc_ramKB) memory"
            [[ $alloc_swapKB -gt 0 ]] && echomult "$(GB $alloc_swapKB) Swap"
            [[ $alloc_diskKB -gt 0 ]] && echomult "$(GB $alloc_diskKB) disk space"
            [[ $alloc_instcount -gt 0 ]] && echomult "Distributed among $alloc_instcount contract instances"

            update_sashi=1
            [[ $alloc_instcount -gt 0 ]] && update_mb=1

        elif [ "$sub_mode" == "leaseamt" ]; then

            local amount=${2} # Contract instance lease amount in EVRs.
            [ -z $amount ] && echomult "Your current lease amount is: $cfg_lease_amount EVRs.\n" && exit 0

            ! validate_positive_decimal $amount &&
                echomult "Invalid lease amount.\n   Usage: evernode config leaseamt | evernode config leaseamt <lease amount>\n" &&
                exit 1

            ! validate_lease_amount $amount &&
                echomult "Invalid lease amount.\n   Lease amount should be greater than or equal "$min_lease_amt" EVRs\n" &&
                exit 1
            lease_amount=$amount
            [[ $cfg_lease_amount == $lease_amount ]] && echomult "Lease amount is already configured!\n" && exit 0

            echomult "Using lease amount $lease_amount EVRs."

            update_mb=1

        elif [ "$sub_mode" == "xahaud" ]; then

            local server=${2} # Rippled server URL
            [ -z $server ] && echomult "Your current xahaud server is: $cfg_rippled_server\n" && exit 0

            ! validate_rippled_url $server &&
                echomult "\nUsage: evernode config xahaud | evernode config xahaud <xahaud server>\n" &&
                exit 1
            rippled_server=$server
            [[ $cfg_rippled_server == $rippled_server ]] && echomult "Xahaud server is already configured!\n" && exit 0

            echomult "Using the xahaud address '$rippled_server'."

            update_mb=1

        elif [ "$sub_mode" == "xahaud-fallback" ]; then

            local servers=${2} # Rippled server URL
            if [[ -z $servers ]]; then
                [[ ! -z "$cfg_fb_rippled_servers" ]] && echomult "Your current fallback xahaud servers are: $cfg_fb_rippled_servers\n" ||
                    echomult "You have not specified any fallback xahaud servers.\n"
                exit 0
            fi

            ! validate_and_set_fallback_rippled_servers "$servers" &&
                echomult "\nUsage: evernode config xahaud-fallback | evernode config xahaud-fallback <fallback xahaud servers (comma seperated)>\n" &&
                exit 1

            [[ $cfg_fb_rippled_servers == $fallback_rippled_servers ]] && echomult "Xahaud server is already configured!\n" && exit 0

            echomult "Using the fallback xahaud addresses '$fallback_rippled_servers'."

            update_mb=1

        elif [ "$sub_mode" == "email" ]; then

            local email_address=${2} # Email address

            local cfg_host_address=$(jq -r '.xrpl.address' $mbconfig)

            [ ! -z $email_address ] && ! validate_email_address $email_address &&
                echomult "\nUsage: evernode config email | evernode config email <email address>\n" &&
                exit 1

            # Get info of the host.
            local host_info=$(sudo -u $MB_XRPL_USER MB_DATA_DIR=$MB_XRPL_DATA node $MB_XRPL_BIN hostinfo) || exit 1
            local cur_email_address=$(echo $host_info | jq -r '.email')

            [ -z $email_address ] && echomult "Your current email address is: $cur_email_address\n" && exit 0

            [[ $cur_email_address == $email_address ]] && echomult "Email address is already configured!\n" && exit 0

            echomult "Using the email address '$email_address'."

            # If certbot installed, Sashimono might have been setup with letsencrypt certificates.
            if command -v certbot &>/dev/null; then
                local inet_addr=$(jq -r '.hp.host_address' $saconfig)

                local key_file="/etc/letsencrypt/live/$inet_addr/privkey.pem"
                local cert_file="/etc/letsencrypt/live/$inet_addr/fullchain.pem"
                local renewed_key_file="$RENEWED_LINEAGE/privkey.pem"
                local sashimono_key_file="$SASHIMONO_DATA/contract_template/cfg/tlskey.pem"

                # If sashimono containes the letsencrypt certificates, Update them with new email.
                if ([ -f $key_file ] && cmp -s $key_file $sashimono_key_file) || ([ -f $renewed_key_file ] && cmp -s $renewed_key_file $sashimono_key_file); then

                    # Get the current registration email if there's any.
                    local lenc_acc_email=$(certbot show_account 2>/dev/null | grep "Email contact:" | cut -d ':' -f2 | sed 's/ *//g')

                    # If the emails are different, we need to update the letsencrypt email.
                    if [[ $lenc_acc_email != $email_address ]]; then
                        # If there are other certificates from this letsencrypt account,
                        # Complain that sashimono can't update the email since this account is used by other certificates.
                        local count=$(certbot certificates 2>/dev/null | grep "Certificate Name" | grep -v -c "$inet_addr")
                        [ $count -gt 0 ] &&
                            echomult "Existing letsencrypt account with $lenc_acc_email has other certificates which are related to sashimono.\n
                            So letsencrypt email cannot be changed, Please use the same email or update the letsencrypt email with certbot." &&
                            return 1

                        ! certbot -n update_account -m $email_address &&
                            echo "Could not update the letsencrypt email." && return 1
                    fi

                fi
            fi

            # Send update meassage to the registry.
            ! sudo -u $MB_XRPL_USER MB_DATA_DIR=$MB_XRPL_DATA node $MB_XRPL_BIN update $email_address &&
                echo "Could not update host info." && return 1

            # We do not need to restart services for email update.
            echomult "\nSuccessfully changed the email address!\n" && exit 0

        elif [ "$sub_mode" == "instance" ]; then
            local attribute=${2}

            if [ "$attribute" == "ipv6" ]; then
                ([ "$cfg_ipv6_subnet" != null ] && [ "$cfg_ipv6_net_interface" != null ]) &&
                    echomult "You have already enabled IPv6 for instance outbound communication.
            \n Network Interface: $cfg_ipv6_net_interface
            \n Subnet: $cfg_ipv6_subnet" &&
                    ! confirm "\nDo you want to go for a reconfiguration?" && return 0

                if ([[ $occupied_instance_count -gt 0 ]]); then
                    echomult "Could not proceed the reconfiguration as there are occupied instances." && exit 1
                fi

                set_ipv6_subnet
                if [[ "$ipv6_subnet" == "-" || "$ipv6_net_interface" == "-" ]]; then
                    echo -e "Could not proceed with provided details." && exit 1
                fi

                echo -e "Using $ipv6_subnet IPv6 subnet on $ipv6_net_interface for contract instances.\n"
                update_mb=1

            else
                echomult "Invalid arguments.\n  Usage: evernode config instance [ipv6]\n" && exit 1
            fi

        elif [ "$sub_mode" == "extrafee" ]; then

            local fee=${2} # Affordable extra transaction fee to consider in txn failures.
            [ -z $fee ] && echomult "Your affordable extra transaction fee: $cfg_extra_txn_fee XAH Drops.\n" && exit 0

            ! ([[ $fee =~ ^[0-9]+$ ]] && [[ $fee -ge 0 ]]) &&
                echomult "Invalid fee amount.\n   Usage: evernode config extrafee | evernode config extrafee <fee amount in XAH Drops>\n" &&
                exit 1
            extra_txn_fee=$fee
            [[ $cfg_extra_txn_fee == $extra_txn_fee ]] && echomult "Affordable extra transaction fee is already configured!\n" && exit 0

            echomult "Using affordable extra transaction fee $extra_txn_fee XAH Drops."

            update_mb=1

        else
            echomult "Invalid arguments.\n  Usage: evernode config [resources|leaseamt|xahaud|xahaud-fallback|email|instance|extrafee] [arguments]\n" && exit 1
        fi

        local mb_user_id=$(id -u "$MB_XRPL_USER")
        local mb_user_runtime_dir="/run/user/$mb_user_id"
        local has_error=0

        echomult "\nStarting the reconfiguration...\n"

        # Stop the message board service.
        echomult "Stopping the message board..."
        sudo -u "$MB_XRPL_USER" XDG_RUNTIME_DIR="$mb_user_runtime_dir" systemctl --user stop $MB_XRPL_SERVICE

        # Stop the sashimono service.
        if [ $update_sashi == 1 ]; then
            echomult "Stopping the sashimono..."
            systemctl stop $SASHIMONO_SERVICE

            ! reconfig_sashi && has_error=1

            echomult "Starting the sashimono..."
            systemctl start $SASHIMONO_SERVICE
        fi

        if [ $has_error == 0 ] && [ $update_mb == 1 ]; then
            ! reconfig_mb && has_error=1
        fi

        echomult "Starting the message board..."
        sudo -u "$MB_XRPL_USER" XDG_RUNTIME_DIR="$mb_user_runtime_dir" systemctl --user start $MB_XRPL_SERVICE

        [ $has_error == 1 ] && echomult "\nChanging the configuration exited with an error.\n" && exit 1

        echomult "\nSuccessfully changed the configuration!\n"
    }

    function delete_instance() {
        [ "$EUID" -ne 0 ] && echo "Please run with root privileges (sudo)." && exit 1

        # Restart the message board to update the instance count
        local mb_user_id=$(id -u "$MB_XRPL_USER")
        local mb_user_runtime_dir="/run/user/$mb_user_id"

        echomult "Stopping the message board..."
        sudo -u "$MB_XRPL_USER" XDG_RUNTIME_DIR="$mb_user_runtime_dir" systemctl --user stop $MB_XRPL_SERVICE

        local has_error=0
        instance_name=$1
        echo "Deleting instance $instance_name"
        ! sudo -u $MB_XRPL_USER MB_DATA_DIR=$MB_XRPL_DATA node $MB_XRPL_BIN delete $instance_name &&
            echo "There was an error in deleting the instance." && has_error=1

        echomult "Starting the message board..."
        sudo -u "$MB_XRPL_USER" XDG_RUNTIME_DIR="$mb_user_runtime_dir" systemctl --user start $MB_XRPL_SERVICE

        [ $has_error == 0 ] && echo "Instance deletion completed."
    }

    function offerlease() {
        [ "$EUID" -ne 0 ] && echo "Please run with root privileges (sudo)." && exit 1

        local mb_user_id=$(id -u "$MB_XRPL_USER")
        local mb_user_runtime_dir="/run/user/$mb_user_id"

        echomult "Stopping the message board..."
        sudo -u "$MB_XRPL_USER" XDG_RUNTIME_DIR="$mb_user_runtime_dir" systemctl --user stop $MB_XRPL_SERVICE

        local has_error=0
        ! sudo -u $MB_XRPL_USER MB_DATA_DIR=$MB_XRPL_DATA node $MB_XRPL_BIN offer-leases &&
            echo "There was an error in creating lease offers." && has_error=1

        echomult "Starting the message board..."
        sudo -u "$MB_XRPL_USER" XDG_RUNTIME_DIR="$mb_user_runtime_dir" systemctl --user start $MB_XRPL_SERVICE

        [ $has_error == 0 ] && echo "Lease offer creation for minted lease tokens was completed."
    }

    function configure_reputationd() {
        local upgrade=$1
        [ "$EUID" -ne 0 ] && echo "Please run with root privileges (sudo)." && return 1

        # Configure reputationd users and register host.
        echomult "configuring Evernode reputation for reward distribution..."

        if [ -f "$REPUTATIOND_CONFIG" ]; then
            reputationd_secret_path=$(jq -r '.xrpl.secretPath' "$REPUTATIOND_CONFIG")
            chown "$REPUTATIOND_USER": $reputationd_secret_path
        fi
        if [ "$upgrade" == "0" ]; then
            #account generation,
            if ! set_host_reputationd_account; then
                echo "error setting up reputationd account."
                return 1
            fi
        fi

        reputationd_user_dir=/home/"$REPUTATIOND_USER"
        reputationd_user_id=$(id -u "$REPUTATIOND_USER")
        reputationd_user_runtime_dir="/run/user/$reputationd_user_id"

        # Setting the ownership of the REPUTATIOND_USER's home to REPUTATIOND_USER expilcity.
        # NOTE : There can be user id mismatch, as we do not delete REPUTATIOND_USER's home in the uninstallation even though the user is removed.
        chown -R "$REPUTATIOND_USER":"$SASHIADMIN_GROUP" $reputationd_user_dir

        # Setting group ownership for the host secret.
        local host_key_file_path=$(jq -r ".xrpl.secretPath | select( . != null )" "$MB_XRPL_CONFIG")
        local host_key_parent_directory=$(dirname "$host_key_file_path")
        [ $(stat -c "%a" "$host_key_parent_directory") != "550" ] && chmod -R 550 "$host_key_parent_directory"
        [ $(stat -c "%a" "$host_key_file_path") != "440" ] && chmod 440 "$host_key_file_path"

        if [ "$upgrade" == "0" ]; then
            echo -e "\nAccount setup is complete."

            local message="Your host account with the address $reputationd_xrpl_address will be on Xahau $NETWORK.
            \nThe secret key of the account is located at $reputationd_key_file_path.
            \nNOTE: It is your responsibility to safeguard/backup this file in a secure manner.
            \nIf you lose it, you will not be able to access any funds in your Host account. NO ONE else can recover it.
            \n\nThis is the account that will represent this host on the Evernode host registry. You need to load up the account with following funds in order to continue with the installation."

            local min_reputation_xah_requirement=$(echo "$MIN_REPUTATION_COST_PER_MONTH*$MIN_OPERATIONAL_DURATION + 1.2" | bc)
            local lease_amount=$(jq ".xrpl.leaseAmount | select( . != null )" "$MB_XRPL_CONFIG")
            # Format lease amount since jq gives it in exponential format.
            local lease_amount=$(awk -v lease_amount="$lease_amount" 'BEGIN { printf("%f\n", lease_amount) }' </dev/null)
            local min_reputation_evr_requirement=$(echo "$lease_amount*24*30*$MIN_OPERATIONAL_DURATION" | bc)

            local need_xah=$(echo "$min_reputation_xah_requirement > 0" | bc -l)
            local need_evr=$(echo "$min_reputation_evr_requirement > 0" | bc -l)
            [[ "$need_xah" -eq 1 ]] && message="$message\n(*) At least $min_reputation_xah_requirement XAH to cover regular transaction fees for the first three months."
            [[ "$need_evr" -eq 1 ]] && message="$message\n(*) At least $min_reputation_evr_requirement EVR to cover Evernode registration."

            message="$message\n\nYou can scan the following QR code in your wallet app to send funds based on the account condition:\n"

            echomult "$message"

            generate_qrcode "$reputationd_xrpl_address"

            ! sudo -u $REPUTATIOND_USER REPUTATIOND_DATA_DIR=$REPUTATIOND_DATA node $REPUTATIOND_BIN new $reputationd_xrpl_address $reputationd_key_file_path && echo "Error creating configs" && return 1

            echomult "To set up your reputationd host account, ensure a deposit of $min_reputation_xah_requirement XAH to cover the regular transaction fees for the first three months."
            echomult "\nChecking the reputationd account condition."
            while true; do
                wait_call "sudo -u $REPUTATIOND_USER REPUTATIOND_DATA_DIR=$REPUTATIOND_DATA node $REPUTATIOND_BIN wait-for-funds NATIVE $min_reputation_xah_requirement" && break
                confirm "\nDo you want to retry?\nPressing 'n' would terminate the opting-in." || return 1
            done

            sleep 2
        fi
        ! sudo -u $REPUTATIOND_USER REPUTATIOND_DATA_DIR=$REPUTATIOND_DATA node $REPUTATIOND_BIN prepare && echo "Error preparing account" && return 1

        if [ "$upgrade" == "0" ]; then
            echomult "\n\nIn order to register in reputation and reward system you need to have $min_reputation_evr_requirement EVR balance in your host account. Please deposit the required amount in EVRs.
            \nYou can scan the provided QR code in your wallet app to send funds."

            while true; do
                wait_call "sudo -u $REPUTATIOND_USER REPUTATIOND_DATA_DIR=$REPUTATIOND_DATA node $REPUTATIOND_BIN wait-for-funds ISSUED $min_reputation_evr_requirement" && break
                confirm "\nDo you want to retry?\nPressing 'n' would terminate the opting-in." || return 1
            done

        fi

        if [ "$upgrade" == "1" ]; then
            ! sudo -u $REPUTATIOND_USER REPUTATIOND_DATA_DIR=$REPUTATIOND_DATA node $REPUTATIOND_BIN upgrade && echo "Error upgrading reputationd" && return 1
        fi

        ! sudo -u $REPUTATIOND_USER REPUTATIOND_DATA_DIR=$REPUTATIOND_DATA node $REPUTATIOND_BIN update-config $reputation_contract_url && echo "Error configuring reputation contract URL." && return 1

        # Setup env variable for the reputationd user.
        echo "
            export XDG_RUNTIME_DIR=$reputationd_user_runtime_dir" >>"$reputationd_user_dir"/.bashrc
        echo "Updated reputationd user .bashrc."

        reputationd_user_systemd=""
        for ((i = 0; i < 30; i++)); do
            sleep 0.1
            reputationd_user_systemd=$(sudo -u "$REPUTATIOND_USER" XDG_RUNTIME_DIR="$reputationd_user_runtime_dir" systemctl --user is-system-running 2>/dev/null)
            [ "$reputationd_user_systemd" == "running" ] && break
        done
        [ "$reputationd_user_systemd" != "running" ] && echo "NO_REPUTATIOND_USER_SYSTEMD" && abort

        # Configure reputationd service
        echomult "Configuring reputationd service"
        ! (sudo -u $REPUTATIOND_USER mkdir -p "$reputationd_user_dir"/.config/systemd/user/) && echo "ReputationD user systemd folder creation failed" && abort
        # StartLimitIntervalSec=0 to make unlimited retries. RestartSec=5 is to keep 5 second gap between restarts.
        echo "[Unit]
            Description=Running Evernode reputation for reward distribution.
            After=network.target
            StartLimitIntervalSec=0
            [Service]
            Type=simple
            WorkingDirectory=$REPUTATIOND_BIN
            Environment=\"REPUTATIOND_DATA_DIR=$REPUTATIOND_DATA\"
            ExecStart=/usr/bin/node $REPUTATIOND_BIN
            Restart=on-failure
            RestartSec=5
            [Install]
            WantedBy=default.target" | sudo -u $REPUTATIOND_USER tee "$reputationd_user_dir"/.config/systemd/user/$REPUTATIOND_SERVICE.service >/dev/null

        # This service needs to be restarted whenever reputationd.cfg or secret.cfg is changed.
        sudo -u "$REPUTATIOND_USER" XDG_RUNTIME_DIR="$reputationd_user_runtime_dir" systemctl --user enable $REPUTATIOND_SERVICE
        # We only enable this service. It'll be started after pending reboot checks at the bottom of this script.

        # If there's no pending reboot, start the reputationd services now. Otherwise
        # they'll get started at next startup.
        if [ ! -f /run/reboot-required.pkgs ] || [ ! -n "$(grep sashimono /run/reboot-required.pkgs)" ]; then
            echo "Starting the reputationd service."

            sudo -u "$REPUTATIOND_USER" XDG_RUNTIME_DIR="$reputationd_user_runtime_dir" systemctl --user restart $REPUTATIOND_SERVICE
        fi

        echo "Opted-in to the Evernode reputation for reward distribution."
    }

    function remove_reputationd() {
        [ "$EUID" -ne 0 ] && echo "Please run with root privileges (sudo)." && return 1

        reputationd_user_dir=/home/"$REPUTATIOND_USER"
        reputationd_user_id=$(id -u "$REPUTATIOND_USER")
        reputationd_user_runtime_dir="/run/user/$reputationd_user_id"

        # Remove auto updater service if exists.
        local service_path="$reputationd_user_dir"/.config/systemd/user/$REPUTATIOND_SERVICE.service
        if [ -f $service_path ]; then
            echo "Removing Evernode reputation for reward distribution..."
            sudo -u "$REPUTATIOND_USER" XDG_RUNTIME_DIR="$reputationd_user_runtime_dir" systemctl --user stop $REPUTATIOND_SERVICE
            sudo -u "$REPUTATIOND_USER" XDG_RUNTIME_DIR="$reputationd_user_runtime_dir" systemctl --user disable $REPUTATIOND_SERVICE
            rm -f $service_path
            local service_removed=true
        else
            echo "Evernode reputation for reward distribution is not configured."
        fi

        $service_removed && echo "Opted-out from the Evernode reputation for reward distribution."
    }

    # Begin setup execution flow --------------------

    if [ "$mode" == "install" ]; then

        ! confirm "This will install Sashimono, Evernode's contract instance management software,
            and register your system as an $evernode host.
            \nMake sure your system does not currently contain any other workloads important
            to you since we will be making modifications to your system configuration.
            \n\nContinue?" && exit 1

        check_sys_req
        check_prereq

        # Display licence file and ask for concent.
        printf "\n***********************************************************************************************************************\n\n"
        echomult "EVERNODE SOFTWARE LICENCE AGREEMENT"
        echomult "\nBy using this EVERNODE CLI Tool, you agree to be bound by the terms and conditions of the EVERNODE SOFTWARE LICENCE.
    \nFor full details, please refer to the licence document available at:
    \n$licence_url"

        printf "\n\n***********************************************************************************************************************\n"
        ! confirm "\nDo you accept the terms of the licence agreement?" && exit 1

        init_setup_helpers

        download_public_config && set_environment_configs

        # Setting up Sashimono admin group.
        ! grep -q $SASHIADMIN_GROUP /etc/group && ! groupadd $SASHIADMIN_GROUP && echo "$SASHIADMIN_GROUP group creation failed." && abort

        # Create MB_XRPL_USER as we require that user for secret key ownership management.
        if ! grep -q "^$MB_XRPL_USER:" /etc/passwd; then
            echomult "Creating Message-board User..."
            useradd --shell /usr/sbin/nologin -m $MB_XRPL_USER 2>/dev/null

            # Setting the ownership of the MB_XRPL_USER's home to MB_XRPL_USER expilcity.
            # NOTE : There can be user id mismatch, as we do not delete MB_XRPL_USER's home in the uninstallation even though the user is removed.
            chown -R "$MB_XRPL_USER":"$SASHIADMIN_GROUP" /home/$MB_XRPL_USER
        fi

        # Check if message board config and sa.cfg exists.
        # This means installation has passed through configuration.

        read_configs

        [ ! -f "$MB_XRPL_CONFIG" ] && set_rippled_server
        echo -e "Using Xahaud server '$rippled_server'.\n"

        [ ! -f "$MB_XRPL_CONFIG" ] && set_fallback_rippled_servers
        [[ "$fallback_rippled_servers" != "-" ]] && echo -e "Using fallback Xahaud servers '$fallback_rippled_servers'.\n"

        [ ! -f "$MB_XRPL_CONFIG" ] && set_email_address
        echo -e "Using the contact email address '$email_address'.\n"

        # TODO - CHECKPOINT - 01
        # Call set_inet_addr to setup tls certificates even if there's a exiting config.
        set_inet_addr
        echo -e "Using '$inetaddr' as host internet address.\n"

        set_country_code
        check_sanctioned "$countrycode"

        echo -e "Using '$countrycode' as country code.\n"

        [ ! -f "$MB_XRPL_CONFIG" ] && set_ipv6_subnet
        [ "$ipv6_subnet" != "-" ] && [ "$ipv6_net_interface" != "-" ] && echo -e "Using $ipv6_subnet IPv6 subnet on $ipv6_net_interface for contract instances.\n"

        set_cgrules_svc
        echo -e "Using '$cgrulesengd_service' as cgroups rules engine service.\n"

        [ ! -f "$SASHIMONO_CONFIG" ] && set_instance_alloc
        echo -e "Using allocation $(GB $alloc_ramKB) memory, $(GB $alloc_swapKB) Swap, $(GB $alloc_diskKB) disk space, distributed among $alloc_instcount contract instances.\n"

        [ ! -f "$SASHIMONO_CONFIG" ] && set_init_ports
        echo -e "Using peer port range $init_peer_port-$((init_peer_port + alloc_instcount)) and user port range $init_user_port-$((init_user_port + alloc_instcount))).\n"

        [ ! -f "$MB_XRPL_CONFIG" ] && set_lease_amount
        echo -e "Lease amount set as $lease_amount EVRs per Moment.\n"

        [ ! -f "$MB_XRPL_CONFIG" ] && set_extra_fee

        # TODO - CHECKPOINT - 02
        set_host_xrpl_account "register"
        echo -e "\nAccount setup is complete."

        ! prepare_host && echo "Error while preparing the host." && exit 1

        $interactive && ! confirm "\n\nSetup will now begin the installation. Continue?" && exit 1

        # TODO - CHECKPOINT - 03
        echo "Starting installation..."
        install_evernode 0

        rm -r $setup_helper_dir >/dev/null 2>&1

        echomult "Installation successful! Installation log can be found at $logfile
            \n\nYour system is now registered on $evernode. You can check your system status with 'evernode status' command.
            \n\nNOTE: Installation will only mint the lease tokens. Please use 'evernode offerlease' command to create offers for the minted lease tokens.
            \nThe host becomes eligible to send heartbeats after generating offers for minted lease tokens."

        installed=true

    elif [ "$mode" == "uninstall" ]; then

        echomult "\nNOTE: By continuing with this, you will not LOSE the SECRET; it remains within the specified path.
    \nThe secret path can be found inside the configuration stored at '$MB_XRPL_DATA/mb-xrpl.cfg'."

        ! confirm "\nAre you sure you want to uninstall $evernode?" && exit 1

        # Check contract condtion.
        check_exisiting_contracts 0

        # Perform Evernode uninstall
        uninstall_evernode 0
        echo "Uninstallation complete!"

    elif [ "$mode" == "transfer" ]; then
        # If evernode is not installed download setup helpers and call for transfer.
        if $installed; then

            if ! $interactive; then
                transferee_address=${3} # Address of the transferee.
            else

                ! confirm "\nThis will uninstall and deregister this host from $evernode
                while allowing you to transfer the registration to a preferred transferee.
                \n\nAre you sure you want to transfer $evernode registration from this host?" && exit 1

                echomult "\nNOTE: By continuing with this, you will not LOSE the SECRET; it remains within the specified path.
                \nThe secret path can be found inside the configuration stored at '$MB_XRPL_DATA/mb-xrpl.cfg'."

                ! confirm "\nAre you sure you want to continue?" && exit 1

            fi

            # Set transferee based on the user input.
            set_transferee_address

            # Check contract condtion.
            check_exisiting_contracts 0

            # Initiate transferring.
            init_evernode_transfer

            # Execute oftware uninstallation (Force uninstall on quiet mode).
            $interactive && uninstall_evernode 0 || uninstall_evernode 0 -f

        else
            if ! $interactive; then
                xrpl_address=${3}       # XRPL account address.
                xrpl_secret=$(<"${4}")  # XRPL account secret based on the provided path.
                transferee_address=${5} # Address of the transferee.
                rippled_server=${6}     # Rippled server URL
            fi

            check_common_prereq

            init_setup_helpers

            download_public_config && set_environment_configs

            # Set xahaud server based on the user input.
            set_rippled_server
            echo -e "Using Xahaud server '$rippled_server'.\n"

            # Set host account based on the user input.
            set_host_xrpl_account "transfer"

            # Set transferee based on the user input.
            set_transferee_address

            $interactive && ! confirm "\nThis will deregister $xrpl_address from $evernode
            while allowing you to transfer the registration to $([ -z $transferee_address ] && echo "same account" || echo "$transferee_address").
            \n  Note: If there are partial registrations, This process will first complete the registration and then it will be deregistered.
            \n\nAre you sure you want to transfer $evernode registration?" && exit 1

            # Execute transfer from js helper.
            has_error=false
            ! exec_jshelper transfer $rippled_server $EVERNODE_GOVERNOR_ADDRESS $xrpl_address $xrpl_secret $transferee_address && has_error=true

            rm -r $setup_helper_dir >/dev/null 2>&1

            $has_error && echo "Error occured in transfer process. Check the error and try again." && exit 1
        fi

        echo "Transfer process was successfully initiated. You can now install and register $evernode using the account $([ -z $transferee_address ] && echo "same account" || echo "$transferee_address")."

    elif [ "$mode" == "deregister" ]; then
        if ! $interactive; then
            xrpl_address=${3}      # XRPL account address.
            xrpl_secret=$(<"${4}") # XRPL account secret based on the provided path.
            rippled_server=${5}    # Rippled server URL
        fi

        check_common_prereq

        init_setup_helpers

        download_public_config && set_environment_configs

        # Set rippled server based on the user input.
        set_rippled_server
        echo -e "Using Rippled server '$rippled_server'.\n"

        # Set host account based on the user input.
        set_host_xrpl_account "deregister"

        $interactive && ! confirm "\nThis will deregister $xrpl_address from $evernode.
            \n  Note: If there are partial registrations, This process will first complete the registration and then it will be deregistered.
            \n\nAre you sure you want to deregister from $evernode?" && exit 1

        # Execute deregister from js helper.
        has_error=false
        ! exec_jshelper deregister $rippled_server $EVERNODE_GOVERNOR_ADDRESS $xrpl_address $xrpl_secret && has_error=true

        rm -r $setup_helper_dir >/dev/null 2>&1

        $has_error && echo "Error occured in deregister process. Check the error and try again." && exit 1

        echo "Deregister process was sucessfull."

    elif [ "$mode" == "status" ]; then
        reg_info

    elif [ "$mode" == "list" ]; then
        sashi list

    elif [ "$mode" == "update" ]; then
        country_code=$(get_country_code)
        check_sanctioned "$country_code"

        update_evernode

        echomult "Upgrade complete!
            \n\nNOTE: This update includes following commands for you to configure reputation for reward distribution.
            \n evernode reputationd <opt-in|opt-out> - Opt-in or opt-out for Evernode reputation for reward distribution.
            \n evernode reputationd status - Check the status of Evernode reputation for reward distribution."

    elif [ "$mode" == "log" ]; then
        create_log

    elif [ "$mode" == "applyssl" ]; then
        apply_ssl $2 $3 $4

    elif [ "$mode" == "config" ]; then
        [ "$EUID" -ne 0 ] && echo "Please run with root privileges (sudo)." && exit 1

        init_setup_helpers
        config $2 $3 $4 $5 $6

    elif [ "$mode" == "delete" ]; then
        [ -z "$2" ] && echomult "A contract instance name must be specified (see 'evernode list').\n  Usage: evernode delete <instance name>" && exit 1

        delete_instance "$2"

    elif [ "$mode" == "governance" ]; then
        [[ "$2" == "" || "$2" == "help" ]] && echomult "Governance management tool
            \nSupported commands:
            \npropose [hashFile] [shortName] - Propose new governance candidate.
            \nwithdraw [candidateId] - Withdraw proposed governance candidate.
            \nvote [candidateId] - Vote for a governance candidate.
            \nunvote [candidateId] - Remove vote from voted governance candidate.
            \nstatus - Get governance info of this host.
            \nreport [dudHostAddress] - Report a dud host.
            \nhelp - Print help." && exit 0
        ! MB_DATA_DIR=$MB_XRPL_DATA node $MB_XRPL_BIN ${*:1} && exit 1

    elif [ "$mode" == "regkey" ]; then
        if [ "$2" == "set" ]; then
            if [ -z "$3" ]; then
                echo "Regular key to be set must be provided." && exit 1
            elif [[ ! "$3" =~ ^[[:alnum:]]{24,34}$ ]]; then
                echo "Regular key is invalid." && exit 1
            fi
            set_regular_key $3
        elif [ "$2" == "delete" ]; then
            set_regular_key
        else
            echomult "Regular key management tool
            \nSupported commands:
            \nset [regularKey] - Assign or update the regular key.
            \ndelete - Delete the regular key" && exit 1
        fi

    elif [ "$mode" == "offerlease" ]; then
        offerlease

    elif [ "$mode" == "reputationd" ]; then
        if [ "$2" == "opt-in" ]; then
            init_setup_helpers
            if ! configure_reputationd 0; then
                echomult "\nError occured configuring ReputationD. Retry with the same command again."
                exit 1
            fi
        elif [ "$2" == "opt-out" ]; then
            ! confirm "Are you sure you want to opt out from Evernode reputation for reward distribution?" "n" && exit 1
            if ! remove_reputationd; then
                echomult "\nError occured removing ReputationD. Retry with the same command again."
                exit 1
            fi
        elif [ "$2" == "status" ]; then
            echo ""
            reputationd_info
            echo ""
            ! sudo -u $REPUTATIOND_USER REPUTATIOND_DATA_DIR=$REPUTATIOND_DATA node $REPUTATIOND_BIN repinfo && echo "Error getting reputation status" && exit 1
        else
            echomult "ReputationD management tool
            \nSupported commands:
            \nopt-in - Opt in to the Evernode reputation for reward distribution.
            \nopt-out - Opt out from the Evernode reputation for reward distribution.
            \nstatus - Check the status of Evernode reputation for reward distribution." && exit 1
        fi
    fi

    $installed && check_installer_pending_finish

    exit 0

    # surrounding braces  are needed make the whole script to be buffered on client before execution.
}
