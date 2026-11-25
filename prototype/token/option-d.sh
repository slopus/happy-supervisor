#!/bin/bash
# Option D on a throwaway machine, as root: system commands as a dedicated happy-system account
# that cannot read private/. Does npm -g work and reach other users, is a sudo rule for apt-get
# root, and does a names-only root helper hold?
#
#   sudo NPM_DIR="$(dirname "$(command -v npm)")" bash prototype/token/option-d.sh
set -u
here=$(cd "$(dirname "$0")" && pwd)
. "$here/lib.sh"
PREFIX=/opt/happy-system/npm
SYSTEM_PATH="$PREFIX/bin:$NPM_DIR:/usr/local/bin:/usr/bin:/bin"

id -u happy-system >/dev/null 2>&1 ||
  useradd --system --create-home --home-dir /home/happy-system --shell /usr/sbin/nologin happy-system
mkdir -p "$PREFIX"
chown happy-system: "$PREFIX"
install -m 755 "$here/hs-apt-install" /usr/local/sbin/hs-apt-install

# as_system <shell line>: the line as a system command would run it under option D.
as_system() {
  (cd / && sudo -u happy-system env -i HOME=/home/happy-system USER=happy-system \
    PATH="$SYSTEM_PATH" NPM_CONFIG_PREFIX="$PREFIX" HOMEBREW_NO_AUTO_UPDATE=1 \
    HOMEBREW_NO_INSTALL_CLEANUP=1 /bin/bash -c "$1")
}

echo "== the token"
check "happy-system reads private/credentials.json" fail as_system "cat $PRIVATE/credentials.json"
check "happy-system lists private/" fail as_system "ls $PRIVATE"

echo "== npm -g into a prefix happy-system owns"
check "npm install -g cowsay" ok as_system "npm install -g cowsay"
check "it landed in the prefix, owned by happy-system" ok \
  test "$(stat -c %U "$PREFIX/lib/node_modules/cowsay")" = happy-system
check "another user (nobody) runs it from PATH" ok \
  sh -c "cd / && sudo -u nobody env PATH='$PREFIX/bin:$NPM_DIR:/usr/bin:/bin' cowsay everyone"
check "nothing was written to /usr/local/lib/node_modules" fail test -e /usr/local/lib/node_modules/cowsay

echo "== apt without root"
check "happy-system: apt-get install -y hello" fail as_system "apt-get install -y -q hello"

echo "== (i) a sudo rule for apt-get alone is root"
echo 'happy-system ALL=(root) NOPASSWD: /usr/bin/apt-get' >/etc/sudoers.d/hs-proto
chmod 440 /etc/sudoers.d/hs-proto
check "sudo apt-get -o APT::Update::Pre-Invoke::=<shell>" ok as_system \
  "sudo -n /usr/bin/apt-get -q -o APT::Update::Pre-Invoke::='cat $PRIVATE/credentials.json > /tmp/hs-sudo-apt' update"
check "  ran as root and took the token" ok stolen /tmp/hs-sudo-apt
rm -f /etc/sudoers.d/hs-proto

echo "== (iii) hs-apt-install, names only, as root"
check "hs-apt-install hello" ok hs-apt-install hello
check "hello runs" ok hello
for refused in "-o" "APT::Update::Pre-Invoke::=id" "./hello.deb" "/tmp/hello.deb" "hello.deb" \
  "hello=2.10-3" "hello/noble" "hello:amd64" "hello-" "coreutils-" "--reinstall" "Hello" "h*"; do
  check "refuses $refused" fail hs-apt-install "$refused"
done
printf 'DPkg::Pre-Invoke { "cat %s/credentials.json > /tmp/hs-apt-config"; };\n' "$PRIVATE" >/tmp/hs-evil.conf
check "plain root apt-get honors a caller's APT_CONFIG" ok \
  env APT_CONFIG=/tmp/hs-evil.conf DEBIAN_FRONTEND=noninteractive apt-get install -y -q --reinstall hello
check "  and runs its hook as root" ok stolen /tmp/hs-apt-config
rm -f /tmp/hs-apt-config
check "hs-apt-install with the caller's APT_CONFIG" ok env APT_CONFIG=/tmp/hs-evil.conf hs-apt-install figlet
check "  does not run its hook" fail stolen /tmp/hs-apt-config

echo "== (ii) Homebrew on Linux, owned by happy-system"
if [ -x /home/linuxbrew/.linuxbrew/bin/brew ]; then
  chown -R happy-system: /home/linuxbrew
  SYSTEM_PATH="/home/linuxbrew/.linuxbrew/bin:$SYSTEM_PATH"
  check "happy-system: brew install hello" ok as_system "brew install hello"
  check "another user runs it" ok sudo -u nobody /home/linuxbrew/.linuxbrew/bin/hello
else
  echo "skipped: no Homebrew at /home/linuxbrew/.linuxbrew"
fi

apt-get purge -y -q hello figlet >/dev/null 2>&1
finish
