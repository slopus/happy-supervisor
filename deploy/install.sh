#!/bin/sh
# Installs happy-supervisor as this computer's service and joins it to a control plane.
#
# This downloads both of the release's binaries for this computer: happy-supervisor-boot
# (docs/boot.md), which becomes the service, and happy-supervisor, which boot runs. The supervisor
# goes into boot's directory (/usr/local/lib/happy-supervisor, or ~/.local/lib/happy-supervisor
# without sudo) as its current version, so the first start downloads nothing more. Boot changes
# the version later when the control plane asks. happy-supervisor itself becomes a script that runs
# the version boot runs, verified, for commands such as `happy-supervisor system enable`.
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
# A sudo install also enables system access (docs/policy.md, System access): the control plane
# may run chosen commands, each reviewed, as the account that installs software, so `apt-get
# install`, `npm install -g` and `brew install` work without sudo. On Linux that is happy-system,
# which it creates with an npm prefix it owns and which cannot read the node's credentials; on
# macOS Homebrew's owner, or root without Homebrew. When `system enable` refuses (it says why), the
# install goes on without it. --no-system (`sh -s -- --no-system`) leaves it off; --system makes a
# refusal fail the install. An install without sudo cannot have it.
# `sudo happy-supervisor system enable|disable --state-dir <the service's>` changes it later.
#
# Run again without HAPPY_JOIN_TOKEN to upgrade a joined computer in place (the same sudo or not);
# a sudo upgrade enables system access too, unless --no-system.
# Uninstall (removes the service, its state, the binary and, for a system install, the
# happy-workload user and on Linux happy-system and its npm prefix):
#
#   curl -fsSL https://get.happy.engineering/install.sh | sudo sh -s -- --uninstall
#
# Optional: HAPPY_SUPERVISOR_VERSION (default: the latest release), HAPPY_INSTALL_BASE (where
# releases are served). Before anything is written outside a temporary directory, the release's
# SHA256SUMS is checked against the release key below with minisign (the computer's own, or a
# pinned minisign 0.12 release whose archive hash is fixed here), and both binaries against
# SHA256SUMS. Boot checks the supervisor's again, against the keys compiled into it, before it
# stores it and before every start.
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
DENY_FILES="/etc/cron.deny /etc/at.deny"
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
  BOOT=/usr/local/bin/happy-supervisor-boot
  BOOT_DIR=/usr/local/lib/happy-supervisor
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
  BOOT="$HOME/.local/bin/happy-supervisor-boot"
  BOOT_DIR="$HOME/.local/lib/happy-supervisor"
  if [ "$os" = linux ]; then
    STATE="${XDG_STATE_HOME:-$HOME/.local/state}/happy-supervisor"
    UNIT="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/happy-supervisor.service"
  else
    STATE="$HOME/Library/Application Support/happy-supervisor"
    UNIT="$HOME/Library/LaunchAgents/$LABEL.plist"
  fi
fi
# A system install runs its work as the unprivileged user WORKLOAD_USER.
workload=
[ -z "$root" ] || workload="--workload-user $WORKLOAD_USER"
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

# System access: on for a sudo install (`default`), unless --no-system; `required` with --system.
system=
[ -z "$root" ] || system=default
case "${1:-}" in
  "" | --uninstall) ;;
  --system)
    [ -n "$root" ] || fail "--system needs a sudo install: system access runs as root or another account, which only a supervisor running as root can switch to"
    system=required
    ;;
  --no-system) system= ;;
  *) fail "unknown option $1: the options are --system, --no-system and --uninstall" ;;
esac
# Runs `system enable` with the binary in $1. By default a refusal only says why and how to
# enable it later; with --system it fails.
enable_system() {
  [ -n "$system" ] || return 0
  "$1" system enable --state-dir "$STATE" && return 0
  [ "$system" = default ] || return 1
  echo "note: system access is off (above); fix that, then run: sudo happy-supervisor system enable --state-dir \"$STATE\"" >&2
}

if [ "${1:-}" = "--uninstall" ]; then
  [ -f "$UNIT" ] && service_stop
  rm -f "$UNIT" "$BIN" "$BOOT"
  rm -rf "$STATE" "$BOOT_DIR"
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
      for deny in $DENY_FILES; do
        [ ! -f "$deny" ] || sed -i "/^$SYSTEM_USER\$/d" "$deny"
      done
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
    # A package manager's output, shown only when it fails.
    pkg_log=$(mktemp)
    quietly() {
      if "$@" >"$pkg_log" 2>&1; then return 0; fi
      cat "$pkg_log" >&2
      return 1
    }
    cannot() { rm -f "$pkg_log"; fail "$1 could not install bubblewrap (its output is above): install the bubblewrap package and run this again"; }
    if command -v apt-get >/dev/null 2>&1; then
      # The package index may be older than the mirror, which then no longer has the .deb it
      # names: refresh it first. A repository that fails to refresh need not stop the install.
      quietly env DEBIAN_FRONTEND=noninteractive apt-get update -q ||
        echo "note: apt-get update failed (above); installing bubblewrap with the package index there is" >&2
      quietly env DEBIAN_FRONTEND=noninteractive apt-get install -y -o DPkg::Lock::Timeout=120 bubblewrap ||
        cannot apt-get
    elif command -v dnf >/dev/null 2>&1; then
      quietly dnf install -y bubblewrap || cannot dnf
    elif command -v apk >/dev/null 2>&1; then
      quietly apk add --no-cache bubblewrap || cannot apk
    elif command -v zypper >/dev/null 2>&1; then
      quietly zypper --non-interactive install bubblewrap || cannot zypper
    elif command -v pacman >/dev/null 2>&1; then
      # A stale sync database names packages the mirror no longer has: sync it and try again.
      quietly pacman -S --noconfirm --needed bubblewrap ||
        quietly pacman -Sy --noconfirm --needed bubblewrap || cannot pacman
    else
      fail "sandboxed commands need bubblewrap, and no known package manager (apt-get, dnf, apk, zypper, pacman) is here to install it: install the bubblewrap package and run this again"
    fi
    rm -f "$pkg_log"
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
file="happy-supervisor-boot-$os-$arch"
supervisor="happy-supervisor-$os-$arch"
echo "downloading happy-supervisor $version and happy-supervisor-boot ($os-$arch)"
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
# The hash SHA256SUMS names for $1, or nothing.
listed() {
  awk -v f="$1" '$2 == f || $2 == "*" f { print $1 }' "$work/SHA256SUMS"
}
expected_supervisor=$(listed "$supervisor")
if [ -z "$expected_supervisor" ]; then
  builds=$(awk '{ sub(/^\*/, "", $2) } $2 !~ /^happy-supervisor-boot-/ { sub(/^happy-supervisor-/, "", $2); print $2 }' "$work/SHA256SUMS" | tr '\n' ' ')
  fail "release $version has no build for $os-$arch; it has: ${builds:-none}"
fi
expected=$(listed "$file")
[ -n "$expected" ] ||
  fail "release $version has no happy-supervisor-boot, which this installer runs the supervisor with: install a later release"
fetch "$BASE/releases/$version/$file" "$work/$file"
[ "$(sha256 "$work/$file")" = "$expected" ] || fail "checksum mismatch for $file"
fetch "$BASE/releases/$version/$supervisor" "$work/$supervisor"
[ "$(sha256 "$work/$supervisor")" = "$expected_supervisor" ] || fail "checksum mismatch for $supervisor"

# happy-supervisor: the version boot runs, verified by boot before it runs.
write_wrapper() {
  mkdir -p "$(dirname "$BIN")"
  cat >"$BIN.new" <<WRAPPER
#!/bin/sh
# happy-supervisor as the service runs it: the current version under happy-supervisor-boot,
# verified before it runs (docs/boot.md). Written by install.sh.
exec "$BOOT" exec --dir "$BOOT_DIR" -- "\$@"
WRAPPER
  chmod 755 "$BIN.new"
  mv -f "$BIN.new" "$BIN"
}
# Boot beside its final place, and the downloaded supervisor stored in boot's directory, verified
# by boot and current. Boot downloads nothing: it is given the files checked above. Writes the
# stored binary's path to $work/supervisor.
install_boot() {
  mkdir -p "$(dirname "$BOOT")"
  install -m 755 "$work/$file" "$BOOT.new"
  "$BOOT.new" install --dir "$BOOT_DIR" --version "$version" --from "$work" >"$work/supervisor" ||
    { rm -f "$BOOT.new"; fail "happy-supervisor-boot could not install happy-supervisor $version"; }
}

# The service: boot, running the supervisor with this install's state and workload user.
write_unit() {
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
ExecStart="$BOOT" run --dir "$BOOT_DIR" --base "$BASE" -- run --state-dir "$STATE"${workload:+ $workload}
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
    args="<string>$BOOT</string><string>run</string><string>--dir</string><string>$BOOT_DIR</string>"
    args="$args<string>--base</string><string>$BASE</string><string>--</string>"
    args="$args<string>run</string><string>--state-dir</string><string>$STATE</string>"
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
}

# Verified: only now does anything reach a system path, or the user's own.
if [ -n "$upgrade" ]; then
  install_boot
  # Before the service stops, so a refusal with --system leaves the running one as it was.
  enable_system "$(cat "$work/supervisor")" || {
    rm -f "$BOOT.new"
    fail "could not enable system access; the running service is unchanged"
  }
  service_stop
  mv -f "$BOOT.new" "$BOOT"
  write_wrapper
  write_unit
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
if [ -n "$root" ]; then
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

install_boot
mv -f "$BOOT.new" "$BOOT"
write_wrapper

# The token goes in the environment, not the arguments, which ps shows.
# shellcheck disable=SC2086 # $workload is two words or none.
HAPPY_JOIN_TOKEN="$HAPPY_JOIN_TOKEN" "$BIN" join --url "$HAPPY_JOIN_URL" \
  ${HAPPY_NODE_NAME:+--name "$HAPPY_NODE_NAME"} --state-dir "$STATE" $workload
enable_system "$BIN" || fail "could not enable system access (above)"
[ -n "$root" ] ||
  echo "note: without sudo there is no system access (installing system-wide software); install with sudo to have it"

write_unit
service_start
echo "happy-supervisor $version is installed and running"
