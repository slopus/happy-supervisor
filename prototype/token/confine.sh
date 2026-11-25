#!/bin/bash
# Option A as a system command would get it: run as PID 1 of a new mount and PID namespace
# (`unshare --mount --pid --fork --mount-proc --propagation private`). It hides the supervisor's
# private directory and the block devices, then runs "$@" as root without the capabilities that
# could undo that.
#
#   confine.sh basic|plus|ro-etc <command...>
#
# plus also hides systemd's and D-Bus's sockets and makes /sys and /proc/sys read-only. ro-etc
# is plus with /etc read-only.
set -eu
variant=$1
shift

mount -t tmpfs -o mode=000,size=4k hs-hidden "$PRIVATE"

dev=$(mktemp -d /run/hs-dev.XXXXXX)
mount -t tmpfs -o mode=755,size=1m hs-dev "$dev"
for node in null zero full random urandom tty; do
  touch "$dev/$node"
  mount --bind "/dev/$node" "$dev/$node"
done
mkdir "$dev/pts" "$dev/shm"
mount -t devpts -o newinstance,ptmxmode=0666,mode=620 devpts "$dev/pts"
ln -s pts/ptmx "$dev/ptmx"
mount -t tmpfs -o mode=1777 shm "$dev/shm"
ln -s /proc/self/fd "$dev/fd"
ln -s /proc/self/fd/0 "$dev/stdin"
ln -s /proc/self/fd/1 "$dev/stdout"
ln -s /proc/self/fd/2 "$dev/stderr"
mount --move "$dev" /dev

if [ "$variant" != basic ]; then
  # Package scripts take a missing /run/systemd/system for "not booted with systemd" and skip
  # starting services, instead of failing.
  [ ! -d /run/systemd/system ] || mount -t tmpfs -o mode=755,size=4k hs-hidden /run/systemd/system
  for socket in /run/systemd/* /run/dbus/system_bus_socket; do
    if [ -S "$socket" ]; then mount --bind /dev/null "$socket"; fi
  done
  mount -o remount,bind,ro /sys
  mount --bind /proc/sys /proc/sys
  mount -o remount,bind,ro /proc/sys
  mount --bind /dev/null /proc/sysrq-trigger
fi
if [ "$variant" = ro-etc ]; then
  mount --bind /etc /etc
  mount -o remount,bind,ro /etc
fi

exec setpriv \
  --bounding-set=-sys_admin,-sys_ptrace,-sys_module,-sys_rawio,-bpf,-perfmon,-mknod,-dac_read_search,-sys_boot,-syslog \
  -- "$@"
