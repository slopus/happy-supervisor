#!/bin/sh
# Installs happy-supervisor as this computer's service and joins it to a control plane.
#
#   curl -fsSL https://get.happy.engineering/install.sh \
#     | sudo HAPPY_JOIN_URL=<join url> HAPPY_JOIN_TOKEN=<token> [HAPPY_NODE_NAME=<name>] sh
#
# HAPPY_JOIN_URL is the full join endpoint the control plane handed out with the token. With sudo
# this is a system install: the service runs as root and runs every command, file operation and
# watch as the unprivileged happy-workload user, which this creates (docs/install.md). Without
# sudo it installs for the user who runs it: a user service that runs commands as them.
#
# On Linux sandboxed commands need bubblewrap and unprivileged user namespaces. A system install
# installs bubblewrap when it is missing and, where AppArmor restricts user namespaces (Ubuntu
# 23.10 and later), loads a profile that lets bubblewrap create them. Where it cannot, it refuses
# and says why. A user install refuses when bubblewrap is missing.
#
# With --system (`sh -s -- --system`, sudo only) the control plane may also run chosen commands as
# the account that installs software: on Linux happy-system, which it creates with an npm prefix
# it owns and which cannot read the node's credentials; on macOS Homebrew's owner
# (docs/policy.md, System access). `sudo happy-supervisor system enable|disable --state-dir <the service's>` changes
# that later.
#
# Run again without HAPPY_JOIN_TOKEN to upgrade a joined computer in place (the same sudo or not).
# Uninstall (removes the service, its state, the binary and, for a system install, the
# happy-workload user and on Linux happy-system and its npm prefix):
#
#   curl -fsSL https://get.happy.engineering/install.sh | sudo sh -s -- --uninstall
#
# Optional: HAPPY_SUPERVISOR_VERSION (default: the latest release), HAPPY_INSTALL_BASE (where
# releases are served). Before anything is written outside a temporary directory, the release's
# SHA256SUMS is checked against the release key below with minisign (the computer's own, or a
# pinned minisign 0.12 release whose archive hash is fixed here), and the binary against
# SHA256SUMS.
set -eu

BASE="${HAPPY_INSTALL_BASE:-https://get.happy.engineering}"
# The release signing key (minisign key ID 349DDAD36F92423A).
MINISIGN_PUBKEY="RWQ6QpJv09qdNGB9/hp7j8OjguWGLTtuvAO/d34LiFGJPzFtF2bkY1Lr"
MINISIGN_URL="https://github.com/jedisct1/minisign/releases/download/0.12"
MINISIGN_LINUX_SHA256="9a599b48ba6eb7b1e80f12f36b94ceca7c00b7a5173c95c3efc88d9822957e73"
MINISIGN_MACOS_SHA256="89000b19535765f9cffc65a65d64a820f433ef6db8020667f7570e06bf6aac63"
APPARMOR_PROFILE=/etc/apparmor.d/happy-supervisor-bwrap
WORKLOAD_USER=happy-workload
# System access's account on Linux, which `system enable` creates (src/system_account.rs).
SYSTEM_USER=happy-system
SYSTEM_DIR=/opt/happy-system
SYSTEM_PROFILE=/etc/profile.d/happy-system.sh
CRON_DENY=/etc/cron.deny
LABEL=engineering.happy.supervisor

fail() {
  echo "happy-supervisor install: $*" >&2
  exit 1
}

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=macos ;;
  *) fail "unsupported system $(uname -s): this script installs on Linux and macOS; on Windows use install.ps1" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=x86_64 ;;
  aarch64 | arm64) arch=aarch64 ;;
  *) fail "unsupported architecture $(uname -m): releases are built for x86_64 and aarch64" ;;
esac

# Where this install lives: the system's, or the user's own.
if [ "$(id -u)" = 0 ]; then
  root=1
  BIN=/usr/local/bin/happy-supervisor
  if [ "$os" = linux ]; then
    STATE=/var/lib/happy-supervisor
    UNIT=/etc/systemd/system/happy-supervisor.service
  else
    STATE="/Library/Application Support/happy-supervisor"
    UNIT="/Library/LaunchDaemons/$LABEL.plist"
  fi
else
  root=
  [ -n "${HOME:-}" ] || fail "HOME is not set"
  BIN="$HOME/.local/bin/happy-supervisor"
  if [ "$os" = linux ]; then
    STATE="${XDG_STATE_HOME:-$HOME/.local/state}/happy-supervisor"
    UNIT="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/happy-supervisor.service"
  else
    STATE="$HOME/Library/Application Support/happy-supervisor"
    UNIT="$HOME/Library/LaunchAgents/$LABEL.plist"
  fi
fi
units() {
  if [ -n "$root" ]; then systemctl "$@"; else systemctl --user "$@"; fi
}
service_stop() {
  if [ "$os" = linux ]; then
    units disable --now happy-supervisor 2>/dev/null || true
  else
    launchctl unload "$UNIT" 2>/dev/null || true
  fi
}
service_start() {
  if [ "$os" = linux ]; then
    units daemon-reload
    units enable happy-supervisor
    units restart happy-supervisor
  else
    launchctl load -w "$UNIT"
  fi
}

system=
case "${1:-}" in
  "" | --uninstall) ;;
  --system)
    [ -n "$root" ] || fail "--system needs a sudo install: system access runs as root or another account, which only a supervisor running as root can switch to"
    system=1
    ;;
  *) fail "unknown option $1: the options are --system and --uninstall" ;;
esac
# Runs `system enable` with the binary in $1.
enable_system() {
  [ -z "$system" ] || "$1" system enable --state-dir "$STATE"
}

if [ "${1:-}" = "--uninstall" ]; then
  [ -f "$UNIT" ] && service_stop
  rm -f "$UNIT" "$BIN"
  rm -rf "$STATE"
  if [ -n "$root" ]; then
    if [ -f "$APPARMOR_PROFILE" ]; then
      apparmor_parser -R "$APPARMOR_PROFILE" 2>/dev/null || true
      rm -f "$APPARMOR_PROFILE"
    fi
    if [ "$os" = macos ]; then
      if dscl . -read "/Users/$WORKLOAD_USER" >/dev/null 2>&1; then
        dscl . -delete "/Users/$WORKLOAD_USER"
        dscl . -delete "/Groups/$WORKLOAD_USER" 2>/dev/null || true
        rm -rf "/var/${WORKLOAD_USER:?}"
      fi
    elif id -u "$WORKLOAD_USER" >/dev/null 2>&1; then
      userdel -r "$WORKLOAD_USER" 2>/dev/null || userdel "$WORKLOAD_USER" 2>/dev/null ||
        deluser --remove-home "$WORKLOAD_USER" 2>/dev/null || deluser "$WORKLOAD_USER"
    fi
    if [ "$os" = linux ]; then
      if id -u "$SYSTEM_USER" >/dev/null 2>&1; then
        pkill -KILL -u "$SYSTEM_USER" 2>/dev/null || true
        userdel -r "$SYSTEM_USER" 2>/dev/null || userdel "$SYSTEM_USER" 2>/dev/null ||
          deluser --remove-home "$SYSTEM_USER" 2>/dev/null || deluser "$SYSTEM_USER"
      fi
      rm -rf "$SYSTEM_DIR" "$SYSTEM_PROFILE"
      [ ! -f "$CRON_DENY" ] || sed -i "/^$SYSTEM_USER\$/d" "$CRON_DENY"
    fi
  fi
  echo "happy-supervisor uninstalled"
  exit 0
fi

# A joined computer has credentials; running this again upgrades it.
upgrade=
if [ -f "$STATE/private/credentials.json" ]; then
  [ -z "${HAPPY_JOIN_TOKEN:-}" ] || fail "this computer has already joined; run this without HAPPY_JOIN_TOKEN to upgrade it, or with --uninstall first to join again"
  if [ ! -x "$BIN" ] || [ ! -f "$UNIT" ]; then
    fail "an upgrade needs the installed binary ($BIN) and service ($UNIT)"
  fi
  upgrade=1
else
  : "${HAPPY_JOIN_URL:?set HAPPY_JOIN_URL to the join URL the control plane gave you (https://...)}"
  : "${HAPPY_JOIN_TOKEN:?set HAPPY_JOIN_TOKEN to the join token the control plane gave you}"
fi

if [ "$os" = linux ] && { ! command -v systemctl >/dev/null 2>&1 || [ ! -d /run/systemd/system ]; }; then
  fail "this machine does not run systemd, and the supervisor installs as a systemd service. \
In WSL, enable systemd ([boot] systemd=true in /etc/wsl.conf, then 'wsl --shutdown') and run this again. \
In a container, run this on the host instead."
fi

# Linux: bubblewrap, and user namespaces it may create. Checked before anything is downloaded.
bwrap=
if [ "$os" = linux ] && [ -z "$upgrade" ]; then
  bwrap=$(command -v bwrap || true)
  if [ -z "$bwrap" ]; then
    [ -n "$root" ] || fail "sandboxed commands need bubblewrap, which is not installed and which an install without sudo cannot add: install the bubblewrap package, or run this with sudo"
    echo "installing bubblewrap"
    if command -v apt-get >/dev/null 2>&1; then
      DEBIAN_FRONTEND=noninteractive apt-get install -y bubblewrap >/dev/null
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y bubblewrap >/dev/null
    elif command -v apk >/dev/null 2>&1; then
      apk add --no-cache bubblewrap >/dev/null
    elif command -v zypper >/dev/null 2>&1; then
      zypper --non-interactive install bubblewrap >/dev/null
    elif command -v pacman >/dev/null 2>&1; then
      pacman -S --noconfirm --needed bubblewrap >/dev/null
    else
      fail "sandboxed commands need bubblewrap, and no known package manager (apt-get, dnf, apk, zypper, pacman) is here to install it: install the bubblewrap package and run this again"
    fi
    bwrap=$(command -v bwrap || true)
    [ -n "$bwrap" ] || fail "the bubblewrap package installed no bwrap on PATH"
  fi
fi

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q --https-only -O "$2" "$1"; }
else
  fail "curl or wget is required"
fi
if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | cut -d' ' -f1; }
else
  sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' 0
trap 'exit 1' HUP INT TERM

version="${HAPPY_SUPERVISOR_VERSION:-}"
if [ -z "$version" ]; then
  fetch "$BASE/releases/latest" "$work/latest"
  version=$(tr -d ' \r\n' <"$work/latest")
fi
case "$version" in
  *[!0-9A-Za-z.+-]* | "") fail "bad version '$version'" ;;
esac
file="happy-supervisor-$os-$arch"
echo "downloading happy-supervisor $version ($os-$arch)"
fetch "$BASE/releases/$version/SHA256SUMS" "$work/SHA256SUMS"
fetch "$BASE/releases/$version/SHA256SUMS.minisig" "$work/SHA256SUMS.minisig"
if command -v minisign >/dev/null 2>&1; then
  minisign=minisign
else
  if [ "$os" = linux ]; then
    archive=minisign-0.12-linux.tar.gz pinned=$MINISIGN_LINUX_SHA256
  else
    archive=minisign-0.12-macos.zip pinned=$MINISIGN_MACOS_SHA256
  fi
  fetch "$MINISIGN_URL/$archive" "$work/$archive"
  [ "$(sha256 "$work/$archive")" = "$pinned" ] || fail "checksum mismatch for $archive"
  mkdir "$work/minisign"
  if [ "$os" = linux ]; then
    tar -xzf "$work/$archive" -C "$work/minisign" 2>/dev/null
    minisign="$work/minisign/minisign-linux/$arch/minisign"
  else
    (cd "$work/minisign" && unzip -q "$work/$archive")
    minisign="$work/minisign/minisign"
  fi
  chmod 755 "$minisign"
fi
"$minisign" -Vqm "$work/SHA256SUMS" -x "$work/SHA256SUMS.minisig" -P "$MINISIGN_PUBKEY" ||
  fail "SHA256SUMS is not signed by the release key"
expected=$(awk -v f="$file" '$2 == f || $2 == "*" f { print $1 }' "$work/SHA256SUMS")
if [ -z "$expected" ]; then
  builds=$(awk '{ sub(/^\*/, "", $2); sub(/^happy-supervisor-/, "", $2); print $2 }' "$work/SHA256SUMS" | tr '\n' ' ')
  fail "release $version has no build for $os-$arch; it has: ${builds:-none}"
fi
fetch "$BASE/releases/$version/$file" "$work/$file"
[ "$(sha256 "$work/$file")" = "$expected" ] || fail "checksum mismatch for $file"

# Verified: only now does anything reach a system path, or the user's own.
if [ -n "$upgrade" ]; then
  install -m 755 "$work/$file" "$BIN.new"
  # Before the service stops, so a release without `system` leaves the running one as it was.
  enable_system "$BIN.new" || {
    rm -f "$BIN.new"
    fail "could not enable system access; the running service is unchanged"
  }
  service_stop
  mv -f "$BIN.new" "$BIN"
  service_start
  echo "happy-supervisor upgraded to $version"
  exit 0
fi

if [ "$os" = linux ] && [ -n "$root" ]; then
  # Ubuntu 23.10+ lets a program create unprivileged user namespaces only when a profile says so.
  restricted=$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)
  if [ "$restricted" = 1 ]; then
    command -v apparmor_parser >/dev/null 2>&1 ||
      fail "AppArmor restricts user namespaces here, and apparmor_parser is missing to allow them to bubblewrap"
    if grep -rlsF --exclude="$(basename "$APPARMOR_PROFILE")" "$bwrap" /etc/apparmor.d >/dev/null; then
      echo "an AppArmor profile for $bwrap already exists; leaving it as it is"
    else
      echo "allowing bubblewrap its user namespaces (AppArmor)"
      cat >"$APPARMOR_PROFILE" <<PROFILE
# Installed by happy-supervisor: bubblewrap builds its sandboxes in unprivileged user
# namespaces, which this kernel allows only to programs a profile names.
abi <abi/4.0>,
include <tunables/global>

profile happy-supervisor-bwrap $bwrap flags=(unconfined) {
  userns,
}
PROFILE
      apparmor_parser -r "$APPARMOR_PROFILE" || fail "could not load $APPARMOR_PROFILE"
    fi
  fi
fi

# A system install runs its work as this unprivileged user.
workload=
if [ -n "$root" ]; then
  workload="--workload-user $WORKLOAD_USER"
  if [ "$os" = linux ]; then
    if ! id -u "$WORKLOAD_USER" >/dev/null 2>&1; then
      nologin=/bin/false
      for shell in /usr/sbin/nologin /sbin/nologin; do
        if [ -x "$shell" ]; then nologin=$shell; break; fi
      done
      if command -v useradd >/dev/null 2>&1; then
        useradd --system --create-home --home-dir "/home/$WORKLOAD_USER" --shell "$nologin" "$WORKLOAD_USER"
      elif command -v adduser >/dev/null 2>&1; then
        # BusyBox (Alpine): a system user without a password.
        adduser -S -D -h "/home/$WORKLOAD_USER" -s "$nologin" "$WORKLOAD_USER"
      else
        fail "neither useradd nor adduser is installed, so the $WORKLOAD_USER user cannot be created"
      fi
    fi
  elif ! dscl . -read "/Users/$WORKLOAD_USER" >/dev/null 2>&1; then
    # The first ID from 400 that no user or group has: below 500, macOS hides the account.
    id=$({
      dscl . -list /Users UniqueID
      dscl . -list /Groups PrimaryGroupID
    } | awk '{ print $2 }' | sort -n -u | awk 'BEGIN { n = 400 } $1 == n { n++ } END { print n }')
    dscl . -create "/Groups/$WORKLOAD_USER" PrimaryGroupID "$id"
    dscl . -create "/Users/$WORKLOAD_USER" UniqueID "$id"
    dscl . -create "/Users/$WORKLOAD_USER" PrimaryGroupID "$id"
    dscl . -create "/Users/$WORKLOAD_USER" UserShell /usr/bin/false
    dscl . -create "/Users/$WORKLOAD_USER" NFSHomeDirectory "/var/$WORKLOAD_USER"
    dscl . -create "/Users/$WORKLOAD_USER" IsHidden 1
    mkdir -p "/var/$WORKLOAD_USER"
    chown "$id:$id" "/var/$WORKLOAD_USER"
    chmod 700 "/var/$WORKLOAD_USER"
  fi
fi

mkdir -p "$(dirname "$BIN")"
install -m 755 "$work/$file" "$BIN.new"
mv -f "$BIN.new" "$BIN"

# The token goes in the environment, not the arguments, which ps shows.
# shellcheck disable=SC2086 # $workload is two words or none.
HAPPY_JOIN_TOKEN="$HAPPY_JOIN_TOKEN" "$BIN" join --url "$HAPPY_JOIN_URL" \
  ${HAPPY_NODE_NAME:+--name "$HAPPY_NODE_NAME"} --state-dir "$STATE" $workload
enable_system "$BIN"

mkdir -p "$(dirname "$UNIT")"
if [ "$os" = linux ]; then
  wanted=default.target
  [ -z "$root" ] || wanted=multi-user.target
  cat >"$UNIT" <<UNIT
[Unit]
Description=happy-supervisor
Wants=network-online.target
After=network-online.target

[Service]
ExecStart="$BIN" run --state-dir "$STATE"${workload:+ $workload}
Restart=on-failure
# Exit code 3: the control plane revoked the credential. Join again instead.
RestartPreventExitStatus=3
# The service's cgroup is the supervisor's, for limits.memoryBytes and processes (docs/install.md).
Delegate=yes

[Install]
WantedBy=$wanted
UNIT
  # A user service outlives the user's logins only with lingering.
  [ -n "$root" ] || loginctl enable-linger "$(id -un)" 2>/dev/null ||
    echo "note: could not enable lingering; the service stops when you log out (loginctl enable-linger $(id -un) as an administrator)" >&2
else
  args="<string>$BIN</string><string>run</string><string>--state-dir</string><string>$STATE</string>"
  [ -z "$root" ] || args="$args<string>--workload-user</string><string>$WORKLOAD_USER</string>"
  cat >"$UNIT" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array>$args</array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
</dict>
</plist>
PLIST
fi
service_start
echo "happy-supervisor $version is installed and running"
