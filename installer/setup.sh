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
evernode_alias=/usr/bin/evernode
log_dir=/tmp/evernode-beta
cloud_storage="https://stevernode.blob.core.windows.net/evernode-dev-v3-a86733dc-c0fc-4b1f-97cf-2071ae9c5bee"
setup_script_url="$cloud_storage/setup.sh"
installer_url="$cloud_storage/installer.tar.gz"
licence_url="$cloud_storage/licence.txt"
nodejs_url="$cloud_storage/node"
jshelper_url="$cloud_storage/setup-jshelper.tar.gz"
installer_version_timestamp_file="installer.version.timestamp"
setup_version_timestamp_file="setup.version.timestamp"
default_rippled_server="wss://hooks-testnet-v3.xrpl-labs.com"
setup_helper_dir="/tmp/evernode-setup-helpers"
nodejs_util_bin="$setup_helper_dir/node"
jshelper_bin="$setup_helper_dir/jshelper/index.js"

# export vars used by Sashimono installer.
export USER_BIN=/usr/bin
export SASHIMONO_BIN=/usr/bin/sashimono
export MB_XRPL_BIN=$SASHIMONO_BIN/mb-xrpl
export DOCKER_BIN=$SASHIMONO_BIN/dockerbin
export SASHIMONO_DATA=/etc/sashimono
export MB_XRPL_DATA=$SASHIMONO_DATA/mb-xrpl
export SASHIMONO_SERVICE="sashimono-agent"
export CGCREATE_SERVICE="sashimono-cgcreate"
export MB_XRPL_SERVICE="sashimono-mb-xrpl"
export SASHIADMIN_GROUP="sashiadmin"
export SASHIUSER_GROUP="sashiuser"
export SASHIUSER_PREFIX="sashi"
export MB_XRPL_USER="sashimbxrpl"
export CG_SUFFIX="-cg"
export EVERNODE_AUTO_UPDATE_SERVICE="evernode-auto-update"

# TODO: Verify if the correct Governor address is present in the DEV/BETA envs.
export EVERNODE_GOVERNOR_ADDRESS="raVhw4Q8FQr296jdaDLDfZ4JDhh7tFG7SF"
export MIN_EVR_BALANCE=5120

# Private docker registry (not used for now)
export DOCKER_REGISTRY_USER="sashidockerreg"
export DOCKER_REGISTRY_PORT=0

# We execute some commands as unprivileged user for better security.
# (we execute as the user who launched this script as sudo)
noroot_user=${SUDO_USER:-$(whoami)}

# Helper to print multi line text.
# (When passed as a parameter, bash auto strips spaces and indentation which is what we want)
function echomult() {
    echo -e $1
}

function confirm() {
    echo -en $1" [Y/n] "
    local yn=""
    read yn </dev/tty

    # Default choice is 'y'
    [ -z $yn ] && yn="y"
    while ! [[ $yn =~ ^[Yy|Nn]$ ]]; do
        read -p "'y' or 'n' expected: " yn </dev/tty
    done

    echo "" # Insert new line after answering.
    [[ $yn =~ ^[Yy]$ ]] && return 0 || return 1  # 0 means success.
}

# Configuring the sashimono service is the last stage of the installation.
# Removing the sashimono service is the first stage of ununstallation.
# So if the service exists, Previous sashimono installation has been complete.
# Creating bin dir is the first stage of installation.
# Removing bin dir is the last stage of uninstalltion.
# So if the service does not exists but the bin dir exists, Previous installation or uninstalltion is failed partially.
installed=false
[ -f /etc/systemd/system/$SASHIMONO_SERVICE.service ] && [ -d $SASHIMONO_BIN ] && installed=true

if $installed ; then
    [ "$1" == "install" ] \
        && echo "$evernode is already installed on your host. Use the 'evernode' command to manage your host." \
        && exit 1

    [ "$1" != "uninstall" ] && [ "$1" != "status" ] && [ "$1" != "list" ] && [ "$1" != "update" ] && [ "$1" != "log" ] && [ "$1" != "applyssl" ] && [ "$1" != "transfer" ] && [ "$1" != "config" ] &&  [ "$1" != "delete" ] &&  [ "$1" != "governance" ] \
        && echomult "$evernode host management tool
                \nYour host is registered on $evernode.
                \nSupported commands:
                \nstatus - View $evernode registration info
                \nlist - View contract instances running on this system
                \nlog - Generate evernode log file.
                \napplyssl - Apply new SSL certificates for contracts.
                \nconfig - View and update host configuration.
                \nupdate - Check and install $evernode software updates
                \ntransfer - Initiate an $evernode transfer for your machine
                \ndelete - Remove an instance from the system and recreate the lease
                \nuninstall - Uninstall and deregister from $evernode
                \ngovernance - Governance candidate management" \
        && exit 1
elif [ -d $SASHIMONO_BIN ] ; then
    [ "$1" != "install" ] && [ "$1" != "uninstall" ] \
        && echomult "$evernode host management tool
                \nYour system has a previous failed partial $evernode installation.
                \nYou can repair previous $evernode installation by installing again.
                \nSupported commands:
                \nuninstall - Uninstall previous $evernode installation" \
        && exit 1

    # If partially installed and interactive mode, Allow user to repair.
    [ "$2" != "-q" ]  && [ "$1" == "install" ] \
        && ! confirm "$evernode host management tool
                \nYour system has a previous failed partial $evernode installation.
                \nYou can run:
                \nuninstall - Uninstall previous $evernode installation.
                \n\nDo you want to repair previous $evernode installation?" \
        && exit 1
else
    [ "$1" != "install" ] && [ "$1" != "transfer" ] \
        && echomult "$evernode host management tool
                \nYour system is not registered on $evernode.
                \nSupported commands:
                \ninstall - Install Sashimono and register on $evernode
                \ntransfer - Initiate an $evernode transfer for your machine"\
        && exit 1
fi
mode=$1

if [ "$mode" == "install" ] || [ "$mode" == "uninstall" ] || [ "$mode" == "update" ] || [ "$mode" == "log" ] || [ "$mode" == "transfer" ] ; then
    [ -n "$2" ] && [ "$2" != "-q" ] && [ "$2" != "-i" ] && echo "Second arg must be -q (Quiet) or -i (Interactive)" && exit 1
    [ "$2" == "-q" ] && interactive=false || interactive=true
    [ "$mode" == "transfer" ] && transfer=true || transfer=false
    (! $transfer || $installed) && [ "$EUID" -ne 0 ] && echo "Please run with root privileges (sudo)." && exit 1
fi

# Change the relevant setup helper path based on Evernode installation condition and the command mode.
if $installed && [ "$mode" != "update" ] ; then
    setup_helper_dir="$SASHIMONO_BIN/evernode-setup-helpers"
    nodejs_util_bin="$setup_helper_dir/node"
    jshelper_bin="$setup_helper_dir/jshelper/index.js"
fi

# Format the given KB number into GB units.
function GB() {
    echo "$(bc <<<"scale=2; $1 / 1000000") GB"
}

function check_prereq() {
    # Check if node js installed.
    if command -v node &>/dev/null; then
        version=$(node -v | cut -d '.' -f1)
        version=${version:1}
        if [[ $version -lt 16 ]]; then
            echo "$evernode requires NodeJs 16.x or later. You system has NodeJs $version installed. Either remove the NodeJs installation or upgrade to NodeJs 16.x."
            exit 1
        fi
    fi

    # Check bc command is installed.
    if ! command -v bc &>/dev/null; then
        echo "bc command not found. Installing.."
        apt-get -y install bc >/dev/null
    fi

    # Check host command is installed.
    if ! command -v host &> /dev/null; then
        echo "host command not found. Installing.."
        apt-get -y install bind9-host >/dev/null
    fi
}

function check_sys_req() {

    # Assign sys resource info to global vars since these will also be used for instance allocation later.
    ramKB=$(free | grep Mem | awk '{print $2}')
    swapKB=$(free | grep -i Swap | awk '{print $2}')
    diskKB=$(df | grep -w /home | head -1 | awk '{print $4}')
    [ -z "$diskKB" ] && diskKB=$(df | grep -w / | head -1 | awk '{print $4}')

    [ "$SKIP_SYSREQ" == "1" ] && echo "System requirements check skipped." && return 0

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

function init_setup_helpers() {

    echo "Downloading setup support files..."

    local jshelper_dir=$(dirname $jshelper_bin)
    rm -r $jshelper_dir >/dev/null 2>&1
    sudo -u $noroot_user mkdir -p $jshelper_dir

    [ ! -f "$nodejs_util_bin" ] && sudo -u $noroot_user curl $nodejs_url --output $nodejs_util_bin
    [ ! -f "$nodejs_util_bin" ] && echo "Could not download nodejs for setup checks." && exit 1
    chmod +x $nodejs_util_bin

    if [ ! -f "$jshelper_bin" ]; then
        pushd $jshelper_dir >/dev/null 2>&1
        sudo -u $noroot_user curl $jshelper_url --output jshelper.tar.gz
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
    sudo -u $noroot_user RESPFILE=$resp_file $nodejs_util_bin $jshelper_bin "$@" >/dev/null 2>&1 &
    local pid=$!
    local result=$(cat $resp_file) && [ "$result" != "-" ] && echo $result
    
    # Wait for js helper to exit and reflect the error exit code in this function return.
    wait $pid && [ $? -eq 0 ] && rm $resp_file && return 0
    rm $resp_file && return 1
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
        ([ "$option" == "r" ] || ([ "$option" == "o" ] && [ "$filepath" != "-" ])) \
            && [ ! -f "$filepath" ] && echo "Invalid file path" && filepath=""
    done
}

function set_domain_certs() {
    if confirm "\n$evernode can automatically setup free SSL certificates and renewals for '$inetaddr'
            using Let's Encrypt (https://letsencrypt.org/).
            \nDo you want to setup Let's Encrypt automatic SSL (recommended)?" && \
        confirm "Do you agree to have Let's Encrypt send SSL certificate notifications to your email '$email_address' (required)?" && \
        confirm "Do you agree with Let's Encrypt Terms of Service at https://letsencrypt.org/documents/LE-SA-v1.3-September-21-2022.pdf ?" ; then
            
        tls_key_file="letsencrypt"
        tls_cert_file="letsencrypt"
        tls_cabundle_file="letsencrypt"
    else

        echomult "You have opted out of automatic SSL setup. You need to have obtained SSL certificate files for '$inetaddr'
            from a trusted authority. Please specify the certificate files you have obtained below.\n"

        resolve_filepath tls_key_file r "Please specify location of the private key (usually ends with .key):"
        resolve_filepath tls_cert_file r "Please specify location of the certificate (usually ends with .crt):"
        resolve_filepath tls_cabundle_file o "Please specify location of ca bundle (usually ends with .ca-bundle [Optional]):"
    fi
    return 0
}

function validate_inet_addr_domain() {
    host $inetaddr >/dev/null 2>&1 && return 0
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

function validate_positive_decimal() {
    ! [[ $1 =~ ^(0*[1-9][0-9]*(\.[0-9]+)?|0+\.[0-9]*[1-9][0-9]*)$ ]] && return 1
    return 0
}

function validate_rippled_url() {
    ! [[ $1 =~ ^(wss?:\/\/)([^\/|^:|^ ]{3,})(:([0-9]{1,5}))?$ ]] && echo "Rippled URL must be a valid URL that starts with 'wss://'" && return 1

    echo "Checking server $1..."
    ! exec_jshelper validate-server $1 && echo "Could not communicate with the rippled server." && return 1
    return 0
}

function validate_email_address() {
    local emailAddress=$1
    email_address_length=${#emailAddress}
    ( ( ! [[ "$email_address_length" -le 40 ]] && echo "Email address length should not exceed 40 characters." ) ||    
        ( ! [[ $emailAddress =~ .+@.+ ]] && echo "Email address is invalid." ) ) || return 0
    return 1
}

function set_inet_addr() {

    if $interactive && [ "$NO_DOMAIN" == "" ] ; then
        echo ""
        while [ -z "$inetaddr" ]; do
            read -p "Please specify the domain name that this host is reachable at: " inetaddr </dev/tty
            validate_inet_addr && validate_inet_addr_domain && set_domain_certs && return 0
            echo "Invalid or unreachable domain name."
        done
    fi

    # Rest of this function flow will be used for debugging and internal testing puposes only.

    tls_key_file="self"
    tls_cert_file="self"
    tls_cabundle_file="self"

    # Attempt auto-detection.
    if [ "$inetaddr" == "auto" ] || $interactive ; then
        inetaddr=$(hostname -I | awk '{print $1}')
        validate_inet_addr && $interactive && confirm "Detected ip address '$inetaddr'. This needs to be publicly reachable over
                                internet.\n\nIs this the ip address you want others to use to reach your host?" && return 0
        $interactive && inetaddr=""
    fi

    if $interactive ; then
        while [ -z "$inetaddr" ]; do
            read -p "Please specify the public ip/domain address your server is reachable at: " inetaddr </dev/tty
            validate_inet_addr && return 0
            echo "Invalid ip/domain address."
        done
    fi

    ! validate_inet_addr && echo "Invalid ip/domain address" && exit 1
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
    ([ "$init_peer_port" == "default" ] || $interactive) && init_peer_port=22861
    ([ "$init_user_port" == "default" ] || $interactive) && init_user_port=26201

    if $interactive ; then

        if [ -n "$init_peer_port" ] && [ -n "$init_user_port" ] && confirm "Selected default port ranges (Peer: $init_peer_port-$((init_peer_port + alloc_instcount)), User: $init_user_port-$((init_user_port + alloc_instcount))).
                                            This needs to be publicly reachable over internet. \n\nAre these the ports you want to use?" ; then
            return 0
        fi

        init_peer_port=""
        init_user_port=""
        while [ -z "$init_peer_port" ]; do
            read -p "Please specify the starting port of the public 'Peer port range' your server is reachable at: " init_peer_port </dev/tty
            ! check_port_validity $init_peer_port && init_peer_port="" && echo "Invalid port."
        done
        while [ -z "$init_user_port" ]; do
            read -p "Please specify the starting port of the public 'User port range' your server is reachable at: " init_user_port </dev/tty
            ! check_port_validity $init_user_port && init_user_port="" && echo "Invalid port."
        done

    else
        [ -z "$init_peer_port" ] && echo "Invalid starting peer port '$init_peer_port'" && exit 1
        [ -z "$init_user_port" ] && echo "Invalid starting user port '$init_user_port'" && exit 1
    fi
}

# Validate country code and convert to uppercase if valid.
function resolve_countrycode() {
    # If invalid, reset countrycode and return with non-zero code.
    if ! [[ $countrycode =~ ^[A-Za-z][A-Za-z]$ ]] ; then
        countrycode=""
        return 1
    else
        countrycode=$(echo $countrycode | tr 'a-z' 'A-Z')
        return 0
    fi
}

function set_country_code() {

    # Attempt to auto-detect in interactive mode or if 'auto' is specified.
    if [ "$countrycode" == "auto" ] || $interactive ; then
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
    fi

    if $interactive ; then

        # Uncomment this if we want the user to manually change the auto-detected country code.
        # if [ -n "$countrycode" ] && ! confirm "Based on the internet address '$inetaddr' we have detected that your country
        #                                         code is '$countrycode'. Do you want to specify a different country code" ; then
        #     return 0
        # fi
        # countrycode=""

        while [ -z "$countrycode" ]; do
            # This will be asked if auto-detection fails or if user wants to specify manually.
            read -p "Please specify the two-letter country code where your server is located in (eg. AU): " countrycode </dev/tty
            resolve_countrycode || echo "Invalid country code."
        done

    else
        resolve_countrycode || (echo "Invalid country code '$countrycode'" && exit 1)
    fi
}

function set_ipv6_subnet() {

    if $interactive ; then

        ipv6_subnet="-"
        ipv6_net_interface="-"

        echomult "If your host has IPv6 support, Evernode can assign individual outbound IPv6 addresses to each
            contract instance. This will prevent your host's primary IP address from getting blocked by external
            services in case many contracts on your host attempt to contact the same external service."

        ! confirm "\nDoes your host have an IPv6 subnet assigned to it? The CIDR notation for this usually looks like \"xxxx:xxxx:xxxx:xxxx::/64\"" && return 0
    
        while true; do
            local subnet_input
            read -p "Please specify the IPv6 subnet CIDR assigned to this host: " subnet_input </dev/tty
            
            # If the given IP is valid, this will return the normalized ipv6 subnet like "x:x:x:x::/NN"
            local primary_subnet=$(exec_jshelper ip6-getsubnet $subnet_input)
            [ -z "$primary_subnet" ] && echo "Invalid ipv6 subnet specified. It must be a valid ipv6 subnet in the CIDR format of \"xxxx:xxxx:xxxx:xxxx::/NN\"." && continue
            
            # For further validation, we check whether the subnet prefix is actually assigned to any network interfaces of the host.
            local subnet_prefix="$(cut -d'/' -f1 <<<$primary_subnet | sed 's/::*$//g')"
            local prefix_len="$(cut -d'/' -f2 <<<$primary_subnet)"
            local net_interfaces=$(ip -6 -br addr | grep $subnet_prefix)
            local interface_count=$(echo "$net_interfaces" | wc -l)

            [ "$prefix_len" -gt $max_ipv6_prefix_len ] && echo "Maximum allowed prefix length for $evernode is $max_ipv6_prefix_len." && continue
            [ -z "$net_interfaces" ] && echo "Could not find a network interface with the specified ipv6 subnet." && continue
            [ "$interface_count" -gt 1 ] && echo "Found more than 1 network interface with the specified ipv6 subnet." && echo "$net_interfaces" && continue

            ipv6_subnet=$primary_subnet
            ipv6_net_interface=$(echo "$net_interfaces" | awk '{ print $1 }')

            if ! confirm "\nDo you want to allocate the entire address range of the subnet $primary_subnet to $evernode?" ; then

                while true; do
                    read -p "Please specify the nested IPv6 subnet you want to allocate for $evernode (this must be a nested subnet within $primary_subnet subnet): " subnet_input </dev/tty
                    
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
    fi

}

function set_cgrules_svc() {
    local filepath=$(grep "ExecStart.*=.*/cgrulesengd$" /etc/systemd/system/*.service | head -1 | awk -F : ' { print $1 } ')
    if [ -n "$filepath" ] ; then
        local filename=$(basename $filepath)
        cgrulesengd_service="${filename%.*}"
    fi
    # If service not detected, use the default name.
    [ -z "$cgrulesengd_service" ] && cgrulesengd_service=$cgrulesengd_default || echo "cgroups rules engine service found: '$cgrulesengd_service'"
}

function set_instance_alloc() {
    [ -z $alloc_ramKB ] && alloc_ramKB=$(( (ramKB / 100) * alloc_ratio ))
    [ -z $alloc_swapKB ] && alloc_swapKB=$(( (swapKB / 100) * alloc_ratio ))
    [ -z $alloc_diskKB ] && alloc_diskKB=$(( (diskKB / 100) * alloc_ratio ))
    [ -z $alloc_cpu ] && alloc_cpu=$(( (1000000 / 100) * alloc_ratio ))

    # If instance count is not specified, decide it based on some rules.
    if [ -z $alloc_instcount ]; then

        # Instance count based on total RAM
        local ram_c=$(( alloc_ramKB / ramKB_per_instance ))
        # Instance count based on no. of CPU cores.
        local cores=$(grep -c ^processor /proc/cpuinfo)
        local cpu_c=$(( cores * instances_per_core ))
        # Hardware spec-based maximum instance count will be the lower of the two.
        alloc_instcount=$(( ram_c < cpu_c ? ram_c : cpu_c ))

        # If the host does not have a ipv6 subnet, limit the max instance count further.
        if [ -z "$ipv6_subnet" ] && [ $alloc_instcount -gt $max_non_ipv6_instances ] ; then
            $alloc_instcount=$max_non_ipv6_instances
        fi
    fi


    if $interactive; then
        echomult "Based on your system resources, we have chosen the following allocation:\n
                $(GB $alloc_ramKB) memory\n
                $(GB $alloc_swapKB) Swap\n
                $(GB $alloc_diskKB) disk space\n
                Distributed among $alloc_instcount contract instances"
        confirm "\nIs this the allocation you want to use?" && return 0

        local ramMB=0 swapMB=0 diskMB=0

        while true ; do
            read -p "Specify the number of contract instances that you wish to host: " alloc_instcount </dev/tty
            ! [[ $alloc_instcount -gt 0 ]] && echo "Invalid instance count." || break
        done

        while true ; do
            read -p "Specify the total memory in megabytes to distribute among all contract instances: " ramMB </dev/tty
            ! [[ $ramMB -gt 0 ]] && echo "Invalid memory size." || break
        done

        while true ; do
            read -p "Specify the total Swap in megabytes to distribute among all contract instances: " swapMB </dev/tty
            ! [[ $swapMB -gt 0 ]] && echo "Invalid swap size." || break
        done

        while true ; do
            read -p "Specify the total disk space in megabytes to distribute among all contract instances: " diskMB </dev/tty
            ! [[ $diskMB -gt 0 ]] && echo "Invalid disk size." || break
        done

        alloc_ramKB=$(( ramMB * 1000 ))
        alloc_swapKB=$(( swapMB * 1000 ))
        alloc_diskKB=$(( diskMB * 1000 ))
    fi

    if ! [[ $alloc_ramKB -gt 0 ]] || ! [[ $alloc_swapKB -gt 0 ]] || ! [[ $alloc_diskKB -gt 0 ]] ||
       ! [[ $alloc_cpu -gt 0 ]] || ! [[ $alloc_instcount -gt 0 ]]; then
        echo "Invalid allocation." && exit 1
    fi
}

function set_lease_amount() {

    # Lease amount is mandatory field set by the user
    if $interactive; then
        local amount=0
        while true ; do
            read -p "Specify the lease amount in EVRs for your contract instances (per moment charge per contract): " amount </dev/tty
            ! validate_positive_decimal $amount && echo "Lease amount should be a numerical value greater than zero." || break
        done

        lease_amount=$amount
    fi
}

function set_email_address() {
    if $interactive; then
        local emailAddress=""
        while true ; do
            read -p "Specify the contact email address for your host (this will be published on the host registry and is publicly visible to anyone): " emailAddress </dev/tty
            ! validate_email_address $emailAddress || break
        done

        email_address=$emailAddress
    fi

    validate_email_address $email_address || exit 1
}

function set_rippled_server() {
    ([ -z $rippled_server ] || [ "$rippled_server" == "default" ]) && rippled_server=$default_rippled_server

    if $interactive; then
        if confirm "Do you want to connect to the default rippled server ($default_rippled_server)?" ; then
            ! validate_rippled_url $rippled_server && exit 1
        else
            local new_url=""
            while true ; do
                read -p "Specify the Rippled server URL: " new_url </dev/tty
                ! validate_rippled_url $new_url || break
            done
            rippled_server=$new_url
        fi
    fi
}

function set_transferee_address() {
    # Here we set the default transferee address as 'CURRENT_HOST_ADDRESS', but we set it to the exact current host address in host client side.
    [ -z $transferee_address ] && transferee_address=''

    if $interactive; then
        confirm "\nDo you want to set the current host account as the transferee's account?" && return 0

        local address=''
        while true ; do
            read -p "Specify the XRPL account address of the transferee: " address </dev/tty
            ! [[ $address =~ ^r[a-zA-Z0-9]{24,34}$ ]] && echo "Invalid XRPL account address." || break

        done

        transferee_address=$address
    fi

    ! [[ $transferee_address =~ ^r[a-zA-Z0-9]{24,34}$ ]] && echo "Invalid XRPL account address." && exit 1
}


function set_host_xrpl_account() {
    local account_validate_criteria="register"
    [ ! -z $1 ] && account_validate_criteria=$1

    if $interactive; then
        [ "$account_validate_criteria" == "register" ] &&
            echomult "In order to register in Evernode you need to have an XRPL account with sufficient Ever (EVR) balance.\n"
        local xrpl_address=""
        local xrpl_secret=""
        while true ; do

            read -p "Specify the XRPL account address: " xrpl_address </dev/tty
            ! [[ $xrpl_address =~ ^r[0-9a-zA-Z]{24,34}$ ]] && echo "Invalid XRPL account address." && continue

            echo "Checking account $xrpl_address..."
            ! exec_jshelper validate-account $rippled_server $EVERNODE_GOVERNOR_ADDRESS $xrpl_address $account_validate_criteria && xrpl_address="" && continue

            # Take hidden input and print empty echo (new line) at the end.
            read -s -p "Specify the XRPL account secret (your input will be hidden on screen): " xrpl_secret </dev/tty && echo ""
            ! [[ $xrpl_secret =~ ^s[1-9A-HJ-NP-Za-km-z]{25,35}$ ]] && echo "Invalid XRPL account secret." && continue

            echo "Checking account keys..."
            ! exec_jshelper validate-keys $rippled_server $xrpl_address $xrpl_secret && xrpl_secret="" && continue

            break

        done

        xrpl_account_address=$xrpl_address
        xrpl_account_secret=$xrpl_secret
    fi
}

function install_failure() {
    echo "There was an error during installation. Please provide the file $logfile to Evernode team. Thank you."
    exit 1
}

function uninstall_failure() {
    echo "There was an error during uninstallation."
    exit 1
}

function online_version_timestamp() {
    # Send HTTP HEAD request and get last modified timestamp of the installer package or setup.sh.
    curl --silent --head $1 | grep 'Last-Modified:' | sed 's/[^ ]* //'
}

function install_evernode() {
    local upgrade=$1

    # Get installer version (timestamp). We use this later to check for Evernode software updates.
    local installer_version_timestamp=$(online_version_timestamp $installer_url)
    [ -z "$installer_version_timestamp" ] && echo "Online installer not found." && exit 1
    # Get setup version (timestamp).
    local setup_version_timestamp=$(online_version_timestamp $setup_script_url)

    local tmp=$(mktemp -d)
    cd $tmp
    curl --silent $installer_url --output installer.tgz
    tar zxf $tmp/installer.tgz --strip-components=1
    rm installer.tgz

    set -o pipefail # We need installer exit code to detect failures (ignore the tee pipe exit code).
    mkdir -p $log_dir
    logfile="$log_dir/installer-$(date +%s).log"

    if [ "$upgrade" == "0" ] ; then
        echo "Installing prerequisites..."
        ! ./prereq.sh $cgrulesengd_service 2>&1 \
                                | tee -a $logfile | stdbuf --output=L grep "STAGE" | cut -d ' ' -f 2- && install_failure
    fi

    # Create evernode cli alias at the begining.
    # So, if the installation attempt failed user can uninstall the failed installation using evernode commands.
    ! create_evernode_alias && install_failure

    # Currently the domain address saved only in account_info and an empty value in Hook states.
    # Set description to empty value ('_' will be treated as empty)
    description="_"

    echo "Installing Sashimono..."

    init_setup_helpers
    registry_address=$(exec_jshelper access-evernode-cfg $rippled_server $EVERNODE_GOVERNOR_ADDRESS $xrpl_account_address registryAddress)

    # Filter logs with STAGE prefix and ommit the prefix when echoing.
    # If STAGE log contains -p arg, move the cursor to previous log line and overwrite the log.
    ! UPGRADE=$upgrade EVERNODE_REGISTRY_ADDRESS=$registry_address ./sashimono-install.sh $inetaddr $init_peer_port $init_user_port $countrycode $alloc_instcount \
                            $alloc_cpu $alloc_ramKB $alloc_swapKB $alloc_diskKB $lease_amount $rippled_server $xrpl_account_address $xrpl_account_secret $email_address \
                            $tls_key_file $tls_cert_file $tls_cabundle_file $description $ipv6_subnet $ipv6_net_interface 2>&1 \
                            | tee -a $logfile | stdbuf --output=L grep "STAGE\|ERROR" \
                            | while read line ; do [[ $line =~ ^STAGE[[:space:]]-p(.*)$ ]] && echo -e \\e[1A\\e[K"${line:9}" || echo ${line:6} ; done \
                            && remove_evernode_alias && install_failure
    set +o pipefail

    rm -r $tmp

    # Write the verison timestamp to a file for later updated version comparison.
    echo $installer_version_timestamp > $SASHIMONO_DATA/$installer_version_timestamp_file
    echo $setup_version_timestamp > $SASHIMONO_DATA/$setup_version_timestamp_file
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

    if [ "$upgrade" == "0" ] ; then
        $interactive && [ $ucount -gt 0 ] && ! confirm "This will delete $ucount contract instances. \n\nDo you still want to continue?" && exit 1
        ! $interactive && echo "$ucount contract instances will be deleted."
    fi
}

function uninstall_evernode() {

    local upgrade=$1

    if ! $transfer ; then
        [ "$upgrade" == "0" ] && echo "Uninstalling..." ||  echo "Uninstalling for upgrade..."
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
    local latest_installer_script_version=$(online_version_timestamp $installer_url)
    local latest_setup_script_version=$(online_version_timestamp $setup_script_url)
    [ -z "$latest_installer_script_version" ] && echo "Could not check for updates. Online installer not found." && exit 1

    local current_installer_script_version=$(cat $SASHIMONO_DATA/$installer_version_timestamp_file)
    local current_setup_script_version=$(cat $SASHIMONO_DATA/$setup_version_timestamp_file)
    [ "$latest_installer_script_version" == "$current_installer_script_version" ] && [ "$latest_setup_script_version" == "$current_setup_script_version" ] && echo "Your $evernode installation is up to date." && exit 0

    echo "New $evernode update available. Setup will re-install $evernode with updated software. Your account and contract instances will be preserved."
    $interactive && ! confirm "\nDo you want to install the update?" && exit 1

    echo "Starting upgrade..."
    # Alias for setup.sh is created during 'install_evernode' too. 
    # If only the setup.sh is updated but not the installer, then the alias should be created again.
    if [ "$latest_installer_script_version" != "$current_installer_script_version" ] ; then
        uninstall_evernode 1
        install_evernode 1
    elif [ "$latest_setup_script_version" != "$current_setup_script_version" ] ; then
        [ -d $log_dir ] || mkdir -p $log_dir
        logfile="$log_dir/installer-$(date +%s).log"
        remove_evernode_alias
        ! create_evernode_alias && echo "Alias creation failed."
        echo $latest_setup_script_version > $SASHIMONO_DATA/$setup_version_timestamp_file
    fi

    rm -r $setup_helper_dir >/dev/null 2>&1

    echo "Upgrade complete."
}

function init_evernode_transfer() {

    if ! sudo -u $MB_XRPL_USER MB_DATA_DIR=$MB_XRPL_DATA node $MB_XRPL_BIN transfer $transferee_address &&
        [ "$force" != "-f" ] && [ -f $mb_service_path ]; then
        ! confirm "Evernode transfer initiation was failed. Still do you want to continue the unistallation?" && echo "Aborting unistallation. Try again later." && exit 1
        echo "Continuing uninstallation..."
    fi

}

function create_log() {
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
        cat "$MB_XRPL_DATA/mb-xrpl.cfg"
        echo ""
        echo "Sashimono log:"
        journalctl -u sashimono-agent.service | tail -n 200
        echo ""
        echo "Message board log:"
        sudo -u sashimbxrpl bash -c  journalctl --user -u sashimono-mb-xrpl | tail -n 200
        echo ""
        echo "Auto updater service log:"
        journalctl -u evernode-auto-update | tail -n 200
    } > "$tempfile" 2>&1
    echo "Evernode log saved to $tempfile"
}

# Create a copy of this same script as a command.
function create_evernode_alias() {
    ! curl -fsSL $setup_script_url --output $evernode_alias >> $logfile 2>&1 && echo "Error in creating alias." && return 1
    ! chmod +x $evernode_alias >> $logfile 2>&1 && echo "Error in changing permission for the alias." && return 1
    return 0
}

function remove_evernode_alias() {
    rm $evernode_alias
}

function check_installer_pending_finish() {
    if [ -f /run/reboot-required.pkgs ] && [ -n "$(grep sashimono /run/reboot-required.pkgs)" ]; then
        echo "Your system needs to be rebooted in order to complete Sashimono installation."
        $interactive && confirm "Reboot now?" && reboot
        ! $interactive && echo "Rebooting..." && reboot
        return 0
    else
        # If reboot not required, check whether re-login is required in case the setup was run with sudo.
        # This is because the user account gets added to sashiadmin group and re-login is needed for group permission to apply.
        # without this, user cannot run "sashi" cli commands without sudo.
        if [ "$mode" == "install" ] && [ -n "$SUDO_USER" ] ; then
            echo "You need to logout and log back in, to complete Sashimono installation."
            return 0
        else
            return 1
        fi
    fi
}

function reg_info() {
    echo ""
    if MB_DATA_DIR=$MB_XRPL_DATA node $MB_XRPL_BIN reginfo ; then
        local sashimono_agent_status=$(systemctl is-active sashimono-agent.service)
        local mb_user_id=$(id -u "$MB_XRPL_USER")
        local mb_user_runtime_dir="/run/user/$mb_user_id"
        local sashimono_mb_xrpl_status=$(sudo -u "$MB_XRPL_USER" XDG_RUNTIME_DIR="$mb_user_runtime_dir" systemctl --user is-active $MB_XRPL_SERVICE)
        echo "Sashimono agent status: $sashimono_agent_status"
        echo "Sashimono mb xrpl status: $sashimono_mb_xrpl_status"
        echo -e "\nYour account details are stored in $MB_XRPL_DATA/mb-xrpl.cfg and $MB_XRPL_DATA/secret.cfg."
    fi
}

function apply_ssl() {
    [ "$EUID" -ne 0 ] && echo "Please run with root privileges (sudo)." && exit 1
    
    local tls_key_file=$1
    local tls_cert_file=$2
    local tls_cabundle_file=$3

    ([ ! -f "$tls_key_file" ] || [ ! -f "$tls_cert_file" ] || \
        ([ "$tls_cabundle_file" != "" ] && [ ! -f "$tls_cabundle_file" ])) &&
            echo -e "One or more invalid files provided.\nusage: applyssl <private key file> <cert file> <ca bundle file (optional)>" && exit 1

    echo "Applying new SSL certificates for $evernode"
    echo "Key: $tls_key_file" && cp $tls_key_file $SASHIMONO_DATA/contract_template/cfg/tlskey.pem || exit 1
    echo "Cert: $tls_cert_file" && cp $tls_cert_file $SASHIMONO_DATA/contract_template/cfg/tlscert.pem || exit 1
    # ca bundle is optional.
    [ "$tls_cabundle_file" != "" ] && echo "CA bundle: $tls_cabundle_file" && (cat $tls_cabundle_file >> $SASHIMONO_DATA/contract_template/cfg/tlscert.pem || exit 1)

    sashi list | jq -rc '.[]' | while read -r inst; do \
        local instuser=$(echo $inst | jq -r '.user'); \
        local instname=$(echo $inst | jq -r '.name'); \
        echo -e "\nStopping contract instance $instname" && sashi stop -n $instname && \
            echo "Updating SSL certificates" && \
            cp $SASHIMONO_DATA/contract_template/cfg/tlskey.pem $SASHIMONO_DATA/contract_template/cfg/tlscert.pem /home/$instuser/$instname/cfg/ && \
            chmod 644 /home/$instuser/$instname/cfg/tlscert.pem && chmod 600 /home/$instuser/$instname/cfg/tlskey.pem && \
            chown -R $instuser:$instuser /home/$instuser/$instname/cfg/*.pem && \
            echo -e "Starting contract instance $instname" && sashi start -n $instname; \
    done

    echo "Done."
}

function reconfig_sashi() {
    echomult "Configuaring sashimono...\n"

    ! $SASHIMONO_BIN/sagent reconfig $SASHIMONO_DATA $alloc_instcount $alloc_cpu $alloc_ramKB $alloc_swapKB $alloc_diskKB &&
        echomult "There was an error in updating sashimono configuration." && return 1

    # Update cgroup allocations.
    ( [[ $alloc_ramKB -gt 0 ]] || [[ $alloc_swapKB -gt 0 ]] || [[ $alloc_instcount -gt 0 ]] ) &&
        echomult "Updating the cgroup configuration..." &&
        ! $SASHIMONO_BIN/user-cgcreate.sh $SASHIMONO_DATA && echomult "Error occured while upgrading cgroup allocations" && return 1

    # Update disk quotas.
    if ( [[ $alloc_diskKB -gt 0 ]] || [[ $alloc_instcount -gt 0 ]] ) ; then
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
    echomult "Configuaring message board...\n"

    ! sudo -u $MB_XRPL_USER MB_DATA_DIR=$MB_XRPL_DATA node $MB_XRPL_BIN reconfig $lease_amount $alloc_instcount $rippled_server $ipv6_subnet $ipv6_net_interface &&
        echo "There was an error in updating message board configuration." && return 1
    return 0
}

function config() {
    [ "$EUID" -ne 0 ] && echo "Please run with root privileges (sudo)." && exit 1

    alloc_instcount=0
    alloc_cpu=0
    alloc_ramKB=0
    alloc_swapKB=0
    alloc_diskKB=0
    lease_amount=0
    rippled_server='-'
    ipv6_subnet='-'
    ipv6_net_interface='-'

    local saconfig="$SASHIMONO_DATA/sa.cfg"
    local max_instance_count=$(jq '.system.max_instance_count' $saconfig)
    local max_mem_kbytes=$(jq '.system.max_mem_kbytes' $saconfig)
    local max_swap_kbytes=$(jq '.system.max_swap_kbytes' $saconfig)
    local max_storage_kbytes=$(jq '.system.max_storage_kbytes' $saconfig)

    local mbconfig="$MB_XRPL_DATA/mb-xrpl.cfg"
    local cfg_lease_amount=$(jq '.xrpl.leaseAmount' $mbconfig)
    local cfg_rippled_server=$(jq -r '.xrpl.rippledServer' $mbconfig)

    local cfg_ipv6_subnet=$(jq -r '.networking.ipv6.subnet' $mbconfig)
    local cfg_ipv6_net_interface=$(jq -r '.networking.ipv6.interface' $mbconfig)

    local update_sashi=0
    local update_mb=0

    local sub_mode=${1}
    local occupied_instance_count=$(sashi list | jq length)

    if [ "$sub_mode" == "resources" ] ; then

        local ramMB=${2}       # memory to allocate for contract instances.
        local swapMB=${3}      # Swap to allocate for contract instances.
        local diskMB=${4}      # Disk space to allocate for contract instances.
        local instcount=${5}   # Total contract instance count.

        [ -z $ramMB ] && [ -z $swapMB ] && [ -z $diskMB ] && [ -z $instcount ] &&
            echomult "Your current resource allocation is:
            \n Memory: $(GB $max_mem_kbytes)
            \n Swap: $(GB $max_swap_kbytes)
            \n Disk space: $(GB $max_storage_kbytes)
            \n Instance count: $max_instance_count\n" && exit 0


        local help_text="Usage: evernode config resources | evernode config resources <memory MB> <swap MB> <disk MB> <max instance count>\n"
        [ ! -z $ramMB ] && [[ $ramMB != 0 ]] && ! validate_positive_decimal $ramMB &&
            echomult "Invalid memory size.\n   $help_text" && exit 1
        [ ! -z $swapMB ] && [[ $swapMB != 0 ]] && ! validate_positive_decimal $swapMB &&
            echomult "Invalid swap size.\n   $help_text" && exit 1
        [ ! -z $diskMB ] && [[ $diskMB != 0 ]] && ! validate_positive_decimal $diskMB &&
            echomult "Invalid disk size.\n   $help_text" && exit 1
        [ ! -z $instcount ] && [[ $instcount != 0 ]] && ! validate_positive_decimal $instcount &&
            echomult "Invalid instance count.\n   $help_text" && exit 1

        [ -z $instcount ] && instcount=0
        alloc_instcount=$instcount
        alloc_ramKB=$(( ramMB * 1000 ))
        alloc_swapKB=$(( swapMB * 1000 ))
        alloc_diskKB=$(( diskMB * 1000 ))

        ( ( [[ $alloc_instcount -eq 0 ]] || [[ $max_instance_count == $alloc_instcount ]] ) &&
            ( [[ $alloc_ramKB -eq 0 ]] || [[ $max_mem_kbytes == $alloc_ramKB ]] ) &&
            ( [[ $alloc_swapKB -eq 0 ]] || [[ $max_swap_kbytes == $alloc_swapKB ]] ) &&
            ( [[ $alloc_diskKB -eq 0 ]] || [[ $max_storage_kbytes == $alloc_diskKB ]] ) ) &&
            echomult "Resource configuration values are already configured!\n" && exit 0

        echomult "Using allocation"
        [[ $alloc_ramKB -gt 0 ]] && echomult "$(GB $alloc_ramKB) memory"
        [[ $alloc_swapKB -gt 0 ]] && echomult "$(GB $alloc_swapKB) Swap"
        [[ $alloc_diskKB -gt 0 ]] && echomult "$(GB $alloc_diskKB) disk space"
        [[ $alloc_instcount -gt 0 ]] && echomult "Distributed among $alloc_instcount contract instances"

        update_sashi=1
        [[ $alloc_instcount -gt 0 ]] && update_mb=1

    elif [ "$sub_mode" == "leaseamt" ] ; then

        local amount=${2}      # Contract instance lease amount in EVRs.
        [ -z $amount ] && echomult "Your current lease amount is: $cfg_lease_amount EVRs.\n" && exit 0


        ! validate_positive_decimal $amount &&
            echomult "Invalid lease amount.\n   Usage: evernode config leaseamt | evernode config leaseamt <lease amount>\n" &&
            exit 1
        lease_amount=$amount
        [[ $cfg_lease_amount == $lease_amount ]] && echomult "Lease amount is already configured!\n" && exit 0

        echomult "Using lease amount $lease_amount EVRs."

        update_mb=1

    elif [ "$sub_mode" == "rippled" ] ; then
    
        local server=${2}    # Rippled server URL
        [ -z $server ] && echomult "Your current rippled server is: $cfg_rippled_server\n" && exit 0

        ! validate_rippled_url $server &&
            echomult "\nUsage: evernode config rippled | evernode config rippled <rippled server>\n" &&
            exit 1
        rippled_server=$server
        [[ $cfg_rippled_server == $rippled_server ]] && echomult "Rippled server is already configured!\n" && exit 0

        echomult "Using the rippled address '$rippled_server'."

        update_mb=1

    elif [ "$sub_mode" == "email" ] ; then
    
        local email_address=${2}    # Email address

        local cfg_host_address=$(jq -r '.xrpl.address' $mbconfig)

        local mbsecretconfig="$MB_XRPL_DATA/secret.cfg"
        local cfg_host_secret=$(jq -r '.xrpl.secret' $mbsecretconfig)

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
        if command -v certbot &>/dev/null ; then
            local inet_addr=$(jq -r '.hp.host_address' $saconfig)

            local key_file="/etc/letsencrypt/live/$inet_addr/privkey.pem"
            local cert_file="/etc/letsencrypt/live/$inet_addr/fullchain.pem"
            local renewed_key_file="$RENEWED_LINEAGE/privkey.pem"
            local sashimono_key_file="$SASHIMONO_DATA/contract_template/cfg/tlskey.pem"

            # If sashimono containes the letsencrypt certificates, Update them with new email.
            if ( [ -f $key_file ] && cmp -s $key_file $sashimono_key_file ) || ( [ -f $renewed_key_file ] && cmp -s $renewed_key_file $sashimono_key_file ) ; then

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

    elif [ "$sub_mode" == "instance" ] ; then
        local attribute=${2}

        if [ "$attribute" == "ipv6" ] ; then
            ([ "$cfg_ipv6_subnet" != null ] && [ "$cfg_ipv6_net_interface" != null ]) &&
            echomult "You have already enabled IPv6 for instance outbound communication.
            \n Network Interface: $cfg_ipv6_net_interface
            \n Subnet: $cfg_ipv6_subnet" &&
            ! confirm "\nDo you want to go for a reconfiguration?" && return 0

            if ( [[ $occupied_instance_count -gt 0 ]] ); then
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

    else
        echomult "Invalid arguments.\n  Usage: evernode config [resources|leaseamt|rippled|email|instance] [arguments]\n" && exit 1
    fi

    local mb_user_id=$(id -u "$MB_XRPL_USER")
    local mb_user_runtime_dir="/run/user/$mb_user_id"
    local has_error=0

    echomult "\nStarting the reconfiguration...\n"

    # Stop the message board service.
    echomult "Stopping the message board..."
    sudo -u "$MB_XRPL_USER" XDG_RUNTIME_DIR="$mb_user_runtime_dir" systemctl --user stop $MB_XRPL_SERVICE

    # Stop the sashimono service.
    if [ $update_sashi == 1 ] ; then
        echomult "Stopping the sashimono..."
        systemctl stop $SASHIMONO_SERVICE

        ! reconfig_sashi && has_error=1

        echomult "Starting the sashimono..."
        systemctl start $SASHIMONO_SERVICE
    fi

    if [ $has_error == 0 ] && [ $update_mb == 1 ] ; then
        ! reconfig_mb && has_error=1
    fi

    echomult "Starting the message board..."
    sudo -u "$MB_XRPL_USER" XDG_RUNTIME_DIR="$mb_user_runtime_dir" systemctl --user start $MB_XRPL_SERVICE

    [ $has_error == 1 ] && echomult "\nChanging the configuration exited with an error.\n"  && exit 1

    echomult "\nSuccessfully changed the configuration!\n"
}

function delete_instance()
{
    [ "$EUID" -ne 0 ] && echo "Please run with root privileges (sudo)." && exit 1

    instance_name=$1
    echo "Deleting instance $instance_name"
    ! sudo -u $MB_XRPL_USER MB_DATA_DIR=$MB_XRPL_DATA node $MB_XRPL_BIN delete $instance_name &&
        echo "There was an error in deleting the instance." && exit 1

    # Restart the message board to update the instance count
    local mb_user_id=$(id -u "$MB_XRPL_USER")
    local mb_user_runtime_dir="/run/user/$mb_user_id"

    sudo -u "$MB_XRPL_USER" XDG_RUNTIME_DIR="$mb_user_runtime_dir" systemctl --user restart $MB_XRPL_SERVICE

    echo "Instance deletion completed."
}

# Begin setup execution flow --------------------

if [ "$mode" == "install" ]; then

    if ! $interactive ; then
        inetaddr=${3}              # IP or DNS address.
        init_peer_port=${4}        # Starting peer port for instances.
        init_user_port=${5}        # Starting user port for instances.
        countrycode=${6}           # 2-letter country code.
        alloc_cpu=${7}             # CPU microsec to allocate for contract instances (max 1000000).
        alloc_ramKB=${8}           # Memory to allocate for contract instances.
        alloc_swapKB=${9}          # Swap to allocate for contract instances.
        alloc_diskKB=${10}         # Disk space to allocate for contract instances.
        alloc_instcount=${11}      # Total contract instance count.
        lease_amount=${12}         # Contract instance lease amount in EVRs.
        rippled_server=${13}       # Rippled server URL
        xrpl_account_address=${14} # XRPL account address.
        xrpl_account_secret=${15}  # XRPL account secret.
        email_address=${16}        # User email address
        tls_key_file=${17}         # File path to the tls private key.
        tls_cert_file=${18}        # File path to the tls certificate.
        tls_cabundle_file=${19}    # File path to the tls ca bundle.
        ipv6_subnet=${20}          # ipv6 subnet to be used for ipv6 instance address assignment.
        ipv6_net_interface=${21}   # ipv6 bound network interface to be used for outbound communication.
    fi

    $interactive && ! confirm "This will install Sashimono, Evernode's contract instance management software,
            and register your system as an $evernode host.
            \nMake sure your system does not currently contain any other workloads important
            to you since we will be making modifications to your system configuration.
            \n\nContinue?" && exit 1

    check_sys_req
    check_prereq


    # Display licence file and ask for concent.
    printf "\n*****************************************************************************************************\n\n"
    curl --silent $licence_url | cat
    printf "\n\n*****************************************************************************************************\n"
    $interactive && ! confirm "\nDo you accept the terms of the licence agreement?" && exit 1

    init_setup_helpers

    if [ "$NO_MB" == "" ]; then    
        set_rippled_server
        echo -e "Using Rippled server '$rippled_server'.\n"
        set_host_xrpl_account
        echo -e "Using xrpl account $xrpl_account_address with the specified secret.\n"
    fi

    set_email_address
    echo -e "Using the contact email address '$email_address'.\n"

    set_inet_addr
    echo -e "Using '$inetaddr' as host internet address.\n"

    set_country_code
    echo -e "Using '$countrycode' as country code.\n"

    set_ipv6_subnet
    [ "$ipv6_subnet" != "-" ] && [ "$ipv6_net_interface" != "-" ] && echo -e "Using $ipv6_subnet IPv6 subnet on $ipv6_net_interface for contract instances.\n"

    set_cgrules_svc
    echo -e "Using '$cgrulesengd_service' as cgroups rules engine service.\n"

    set_instance_alloc
    echo -e "Using allocation $(GB $alloc_ramKB) memory, $(GB $alloc_swapKB) Swap, $(GB $alloc_diskKB) disk space, distributed among $alloc_instcount contract instances.\n"

    set_init_ports
    echo -e "Using peer port range $init_peer_port-$((init_peer_port + alloc_instcount)) and user port range $init_user_port-$((init_user_port + alloc_instcount))).\n"

    if [ "$NO_MB" == "" ]; then
        set_lease_amount
        echo -e "Lease amount set as $lease_amount EVRs per Moment.\n"
    fi

    $interactive && ! confirm "\n\nSetup will now begin the installation. Continue?" && exit 1

    echo "Starting installation..."
    install_evernode 0

    rm -r $setup_helper_dir >/dev/null 2>&1

    echomult "Installation successful! Installation log can be found at $logfile
            \n\nYour system is now registered on $evernode. You can check your system status with 'evernode status' command."

elif [ "$mode" == "uninstall" ]; then

    # echomult "\nWARNING! Uninstalling will deregister your host from $evernode and you will LOSE YOUR XRPL ACCOUNT credentials
    #         stored in '$MB_XRPL_DATA/mb-xrpl.cfg' and '$MB_XRPL_DATA/secret.cfg'. This is irreversible. Make sure you have your account address and
    #         secret elsewhere before proceeding.\n"

    # $interactive && ! confirm "\nHave you read above warning and backed up your account credentials?" && exit 1
    $interactive && ! confirm "\nAre you sure you want to uninstall $evernode?" && exit 1

    # Check contract condtion.
    check_exisiting_contracts 0

    # Force uninstall on quiet mode.
    $interactive && uninstall_evernode 0 || uninstall_evernode 0 -f
    echo "Uninstallation complete!"

elif [ "$mode" == "transfer" ]; then
    # If evernode is not installed download setup helpers and call for transfer.
    if $installed ; then
        $interactive && ! confirm "\nThis will uninstall and deregister this host from $evernode
            while allowing you to transfer the registration to a preferred transferee.
            \n\nAre you sure you want to transfer $evernode registration from this host?" && exit 1

        if ! $interactive ; then
            transferee_address=${3}           # Address of the transferee.
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
        if ! $interactive ; then
            xrpl_account_address=${3} # XRPL account address.
            xrpl_account_secret=${4}  # XRPL account secret.
            transferee_address=${5}   # Address of the transferee.
            rippled_server=${6}       # Rippled server URL
        fi

        init_setup_helpers

        # Set rippled server based on the user input.
        set_rippled_server
        echo -e "Using Rippled server '$rippled_server'.\n"

        # Set host account based on the user input.
        set_host_xrpl_account "transfer"

        # Set transferee based on the user input.
        set_transferee_address

        $interactive && ! confirm "\nThis will deregister $xrpl_account_address from $evernode
            while allowing you to transfer the registration to $([ -z $transferee_address ] && echo "same account" || echo "$transferee_address").
            \n\nAre you sure you want to transfer $evernode registration?" && exit 1

        # Execute transfer from js helper.
        exec_jshelper transfer $rippled_server $EVERNODE_GOVERNOR_ADDRESS $xrpl_account_address $xrpl_account_secret $transferee_address

        rm -r $setup_helper_dir >/dev/null 2>&1
    fi

    echo "Transfer process was sucessfully initiated. You can now install and register $evernode using the account $transferee_address."

elif [ "$mode" == "status" ]; then
    reg_info

elif [ "$mode" == "list" ]; then
    sashi list

elif [ "$mode" == "update" ]; then
    update_evernode

elif [ "$mode" == "log" ]; then
    create_log

elif [ "$mode" == "applyssl" ]; then
    apply_ssl $2 $3 $4

elif [ "$mode" == "config" ]; then
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

fi

[ "$mode" != "uninstall" ] && check_installer_pending_finish

exit 0

# surrounding braces  are needed make the whole script to be buffered on client before execution.
}
