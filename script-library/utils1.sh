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

if df --type=btrfs / > /dev/null 2>&1 && ! command -v btrfs > /dev/null 2>&1; then
  sudo apt-get install --no-install-recommends --assume-yes \
    btrfs-progs
fi

if [[ $(ls /var/lib/apt/lists/ | wc -l) -ne 0 ]]; then
  sudo apt-get clean
  sudo rm -r /var/lib/apt/lists/*
fi

set +xv
