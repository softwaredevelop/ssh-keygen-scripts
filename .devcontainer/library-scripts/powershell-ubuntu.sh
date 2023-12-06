#!/usr/bin/env bash

set -e

VERSION_ID=$(lsb_release -rs | tr -d '\n\r')
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

function powershell_inst() {
  curl -O -L -C - https://packages.microsoft.com/config/ubuntu/$VERSION_ID/packages-microsoft-prod.deb &&
    dpkg -i packages-microsoft-prod.deb &&
    rm packages-microsoft-prod.deb &&
    apt-get update &&
    apt-get install --no-install-recommends --assume-yes powershell
}

if [ -f "${MARKER_FILE}" ]; then
  echo "Marker file found:"
  cat "${MARKER_FILE}"
  # shellcheck source=/dev/null
  source "${MARKER_FILE}"
fi

export DEBIAN_FRONTEND=noninteractive

if [ "${POWERSHELL_ALREADY_INSTALLED}" != "true" ]; then
  check_packages \
    apt-transport-https \
    curl \
    software-properties-common &&
    powershell_inst

  POWERSHELL_ALREADY_INSTALLED="true"
fi

if [ ! -d "$MARKER_FILE_DIR" ]; then
  mkdir -p "$MARKER_FILE_DIR"
fi

echo -e "\
    POWERSHELL_ALREADY_INSTALLED=${POWERSHELL_ALREADY_INSTALLED}" >"${MARKER_FILE}"
