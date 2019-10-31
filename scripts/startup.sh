#!/bin/bash

set -x -e

mkdir -p /mnt/.ssh
mkdir -p /mnt/log


if [[ ! -f /mnt/.ssh/id_ed25519.pub ]]
then
    echo "Creating new ssh key pair"
    ssh-keygen -N "" -t ed25519 -f /mnt/.ssh/id_ed25519

fi

chown -R www-data /mnt

sudo -u nobody redis-server /opt/etc/redis.conf
