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

  if ! command -v nc > /dev/null 2>&1; then
    sudo apt-get install --no-install-recommends --assume-yes \
      netcat
  fi

  RSA_KEYLENTGH=4096
  ECDSA_KEYLENTGH=521

  KDF=$(shuf -i 16-26 -n1)

  REMOTE_HOSTNAME=${1:-"gh"}
  REMOTE_USER=${2:-"ghuser"}
  KEYTYPE=${3:-"ed25519"}
  SSHPASS=$(tr -cd '[:alnum:][:punct:]' < /dev/urandom | head -c 32)
  COMMENT=${4:-"$REMOTE_USER@$REMOTE_HOSTNAME"}

  if [[ -n $KEYTYPE ]]; then
    ID="id_${KEYTYPE}_"
  fi

  if [[ -z $KEYTYPE ]]; then
    ID="id_rsa_"
    KEYOPT="-a$KDF -trsa -b$RSA_KEYLENTGH -C$COMMENT"
  elif [[ $KEYTYPE == "rsa" ]]; then
    KEYOPT="-a$KDF -t$KEYTYPE -b$RSA_KEYLENTGH -C$COMMENT"
  elif [[ $KEYTYPE == "ecdsa" ]]; then
    KEYOPT="-a$KDF -t$KEYTYPE -b$ECDSA_KEYLENTGH -C$COMMENT"
  elif [[ $KEYTYPE == "ed25519" ]]; then
    KEYOPT="-a$KDF -t$KEYTYPE -C$COMMENT"
  fi

  KEYNAME="$REMOTE_HOSTNAME"."$REMOTE_USER"_$(hostname)_$(date +%s | sha256sum | head -c 6)

  if df --type=btrfs / > /dev/null 2>&1 && command -v btrfs > /dev/null 2>&1 && [ ! -d "$HOME"/.ssh ]; then
    if btrfs subvolume create "$HOME"/.ssh; then
      mkdir "$HOME"/.ssh/.pw && chmod -R 700 "$HOME"/.ssh
    fi
  elif [ ! -d "$HOME"/.ssh ] && ! df --type=btrfs / > /dev/null 2>&1; then
    if mkdir -p "$HOME"/.ssh/.pw; then
      chmod -R 700 "$HOME"/.ssh
    fi
  fi

  if command -v ssh-keygen > /dev/null 2>&1 && [ -d "$HOME"/.ssh ]; then
    if [[ -n $SSHPASS && -n $KEYNAME ]]; then
      echo "$SSHPASS" > "$HOME"/.ssh/.pw/pw_"$KEYNAME" && chmod 400 "$HOME"/.ssh/.pw/pw_"$KEYNAME"
      ssh-keygen $KEYOPT -f"$HOME"/.ssh/"$ID""$KEYNAME".key -N "$SSHPASS"
      chmod 600 "$HOME"/.ssh/"$ID""$KEYNAME".key
      chmod 644 "$HOME"/.ssh/"$ID""$KEYNAME".key.pub
      unset -v SSHPASS
    fi
  fi

  key="$HOME"/.ssh/"$ID""$KEYNAME".key
  config="$HOME"/.ssh/config
  if [ -f "$key" ]; then
    cat << EOF >> "$config"
Host                 $REMOTE_HOSTNAME.$REMOTE_USER
Hostname             $REMOTE_HOSTNAME
IdentitiesOnly       yes
IdentityFile         $key
User                 git
ProxyCommand         nc -X 5 -x 127.0.0.1:9050 %h %p

EOF
  fi
}

# keygen "$@"
set +xv
