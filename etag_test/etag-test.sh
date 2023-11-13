url="https://api.github.com/repos/du1ana/ev-res-test/commits?sha=main"

headers=$(curl -s -I -X GET "$url")

etag_value=$(echo "$headers" | grep -i etag: | awk -F ': ' '{print $2}')

echo "The etag value is: $etag_value"
