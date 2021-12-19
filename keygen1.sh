#!/usr/bin/env bash
# -*- coding: utf-8 -*-
# set -e
set -xv
export DEBIAN_FRONTEND=noninteractive

sudo -v

if [[ -d "/var/lib/apt/lists" && $(ls /var/lib/apt/lists/ | wc -l) -eq 0 ]]; then
  sudo apt-get update
fi

function keygen() {

  if ! command -v ssh-keygen > /dev/null 2>&1; then
    sudo apt-get install --no-install-recommends --assume-yes \
      openssh-client
  fi

  RSA_KEYLENTGH=4096
  ECDSA_KEYLENTGH=521

  KDF=$(shuf -i 16-26 -n1)

  REMOTEHOST=${1:-"gh"}
  REMOTEUSER=${2:-"ghuser"}
  KEYTYPE=${3:-"ed25519"}
  SSHPASS=$(tr -cd '[:alnum:][:punct:]' < /dev/urandom | head -c 32)

  if [[ -n $KEYTYPE ]]; then
    ID="id_${KEYTYPE}_"
  fi

  if [[ -z $KEYTYPE ]]; then
    ID="id_rsa_"
    KEYOPT="-a$KDF -trsa -b$RSA_KEYLENTGH"
  elif [[ $KEYTYPE == "rsa" ]]; then
    KEYOPT="-a$KDF -t$KEYTYPE -b$RSA_KEYLENTGH"
  elif [[ $KEYTYPE == "ecdsa" ]]; then
    KEYOPT="-a$KDF -t$KEYTYPE -b$ECDSA_KEYLENTGH"
  elif [[ $KEYTYPE == "ed25519" ]]; then
    KEYOPT="-a$KDF -t$KEYTYPE"
  fi

  KEYNAME="$REMOTEHOST"."$REMOTEUSER"_$(hostname)_$(date +%y%m%d-%H%M%S)

  if df --type=btrfs / > /dev/null 2>&1 && command -v btrfs > /dev/null 2>&1 && [ ! -d "$HOME"/.@ssh ]; then
    if btrfs subvolume create "$HOME"/.@ssh; then
      mkdir "$HOME"/.@ssh/.pw && chmod -R 700 "$HOME"/.@ssh
    fi
  elif [ ! -d "$HOME"/.ssh ] && ! df --type=btrfs / > /dev/null 2>&1; then
    if mkdir -p "$HOME"/.ssh/.pw; then
      chmod -R 700 "$HOME"/.ssh
    fi
  fi

  if command -v ssh-keygen > /dev/null 2>&1 && df --type=btrfs / > /dev/null 2>&1 && [ -d "$HOME"/.@ssh ]; then
    if [[ -n $SSHPASS && -n $KEYNAME ]]; then
      echo "$SSHPASS" > "$HOME"/.@ssh/.pw/pw-"$KEYNAME" && chmod 400 "$HOME"/.@ssh/.pw/pw-"$KEYNAME"
      ssh-keygen $KEYOPT -f"$HOME"/.@ssh/"$ID""$KEYNAME".key -N"$SSHPASS"
      chmod 600 "$HOME"/.@ssh/"$ID""$KEYNAME".key
      chmod 644 "$HOME"/.@ssh/"$ID""$KEYNAME".key.pub
      unset -v SSHPASS
    fi
  elif command -v ssh-keygen > /dev/null 2>&1 && ! df --type=btrfs / > /dev/null 2>&1 && [ -d "$HOME"/.ssh ]; then
    if [[ -n $SSHPASS && -n $KEYNAME ]]; then
      echo "$SSHPASS" > "$HOME"/.ssh/.pw/pw-"$KEYNAME" && chmod 400 "$HOME"/.ssh/.pw/pw-"$KEYNAME"
      ssh-keygen $KEYOPT -f"$HOME"/.ssh/"$ID""$KEYNAME".key -N"$SSHPASS"
      chmod 600 "$HOME"/.ssh/"$ID""$KEYNAME".key
      chmod 644 "$HOME"/.ssh/"$ID""$KEYNAME".key.pub
      unset -v SSHPASS
    fi
  fi
}

function keycheck() {
  ssh-keygen -y -f "$1" > /dev/null 2>&1
  echo $?
}

function keyrm() {
  if [ -d "$HOME"/.@ssh ]; then
    # if sudo btrfs subvolume delete "$HOME"/.@ssh > /dev/null 2>&1; then
    #   echo $?
    # fi
    if sudo rm -rf "$HOME"/.@ssh > /dev/null 2>&1; then
      echo $?
    fi
  elif [ -d "$HOME"/.ssh ]; then
    if sudo rm -rf "$HOME"/.ssh > /dev/null 2>&1; then
      echo $?
    fi
  fi
  ls -la "$HOME"
}

# keygen "$@"
set +xv
