KVER=$(uname -r)
BASVER=$(echo "$KVER" | sed 's/-.*//') # Strip distro-specific suffixes (e.g. -generic, -amd64)

echo "Kernel release: $KVER"
echo "Base version:   $BASVER"
echo "Fetching kernel source..."

URL="https://cdn.kernel.org/pub/linux/kernel/v${BASVER%%.*}.x/linux-$BASVER.tar.xz"

echo "Downloading: $URL"
#sudo wget -c "$URL"

echo "Extracting source tree..."
sudo tar -xf "linux-$BASVER.tar.xz"

echo "Source unpacked under: linux-$BASVER"
