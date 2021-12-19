#!/usr/bin/env bash
# -*- coding: utf-8 -*-
# set -e
set -xv
export DEBIAN_FRONTEND=noninteractive

sudo -v

if [[ -d "/var/lib/apt/lists" && $(ls /var/lib/apt/lists/ | wc -l) -eq 0 ]]; then
  sudo apt-get update
  if [[ $(apt list --installed apt-utils 2> /dev/null | wc -l) -lt 2 ]]; then
    sudo apt-get install --no-install-recommends --assume-yes \
      apt-utils
  fi
fi

# if [[ $(apt list --installed locales 2> /dev/null | wc -l) -lt 2 ]]; then
#   if sudo apt-get install --no-install-recommends --assume-yes locales > /dev/null 2>&1; then
#     echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen && sudo locale-gen
#   fi
# fi

if df --type=btrfs / > /dev/null 2>&1 && ! command -v btrfs > /dev/null 2>&1; then
  sudo apt-get install --no-install-recommends --assume-yes \
    btrfs-progs
fi

# USERNAME="vscode"
# if getent passwd | grep "$USERNAME" > /dev/null 2>&1 && [[ ! -e /etc/sudoers.d/$USERNAME ]]; then
#   echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME && chmod 0440 /etc/sudoers.d/$USERNAME
# fi

if [[ $(ls /var/lib/apt/lists/ | wc -l) -ne 0 ]]; then
  sudo apt-get clean
  sudo rm -r /var/lib/apt/lists/*
fi

set +xv
