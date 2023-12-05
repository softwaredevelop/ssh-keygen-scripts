#!/usr/bin/env bash

set -e

BASHDB_VERSION=${1:-"5.0-1.1.2"}
SCRIPT=("${BASH_SOURCE[@]}")
SCRIPT_PATH="${SCRIPT##*/}"
SCRIPT_NAME="${SCRIPT_PATH%.*}"
MARKER_FILE="/usr/local/etc/vscode-markers/${SCRIPT_NAME}"
MARKER_FILE_DIR=$(dirname "${MARKER_FILE}")

if [ "$(id -u)" -ne 0 ]; then
  echo -e 'Script must be run as root. Use sudo, su, or add "USER root" to your Dockerfile before running this script.'
  exit 1
fi

function apt_get_update_if_needed() {
  if [[ -d "/var/lib/apt/lists" && $(ls /var/lib/apt/lists/ | wc -l) -eq 0 ]]; then
    apt-get update
  fi
}

function check_packages() {
  if ! dpkg --status "$@" >/dev/null 2>&1; then
    apt_get_update_if_needed
    apt-get install --no-install-recommends --assume-yes "$@"
  fi
}

function bashdb_inst() {
  curl -O -L -C - https://sourceforge.net/projects/bashdb/files/bashdb/$BASHDB_VERSION/bashdb-"$BASHDB_VERSION".tar.bz2
  if [ ! -d "/usr/src/bashdb" ]; then
    mkdir /usr/src/bashdb
  fi
  tar -xjf bashdb-"$BASHDB_VERSION".tar.bz2 --directory=/usr/src/bashdb --strip-components=1
  rm -f "$BASHDB"
  cd /usr/src/bashdb/ || exit
  ./configure --with-dbg-main
  make --jobs="$(nproc)" all >/dev/null 2>&1
  make --jobs="$(nproc)" check >/dev/null 2>&1
  make install >/dev/null 2>&1
}

if [ -f "${MARKER_FILE}" ]; then
  echo "Marker file found:"
  cat "${MARKER_FILE}"
  # shellcheck source=/dev/null
  source "${MARKER_FILE}"
fi

export DEBIAN_FRONTEND=noninteractive

if [ "${BASHDB_ALREADY_INSTALLED}" != "true" ]; then
  check_packages \
    build-essential \
    ca-certificates \
    curl \
    gawk \
    make \
    xz-utils &&
    bashdb_inst

  BASHDB_ALREADY_INSTALLED="true"
fi

if [ ! -d "$MARKER_FILE_DIR" ]; then
  mkdir -p "$MARKER_FILE_DIR"
fi

echo -e "\
    BASHDB_ALREADY_INSTALLED=${BASHDB_ALREADY_INSTALLED}" >"${MARKER_FILE}"
