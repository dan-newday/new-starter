#!/bin/bash

set -euo pipefail
DIR_ME=$(realpath $(dirname $0))

sudo apt update
sudo apt remove docker docker.io containerd runc
sudo apt install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common

sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
sudo apt update
sudo apt install -y --no-install-recommends docker-ce

sudo usermod -a -G docker newday

VERSION_DOCKER_COMPOSE="v2.1.1"
if [[ ! -d ~/.docker/cli-plugins ]]; then
  mkdir -p ~/.docker/cli-plugins
fi

sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo sudo chmod +x /usr/local/bin/docker-compose

echo "# Filthy hack to get docker started in wsl in a more reliable way" >> /home/newday/.bashrc
echo "sudo service docker start >/dev/null 2>&1" >> /home/newday/.bashrc

echo "# Filthy hack to get docker started in wsl in a more reliable way" >> /home/newday/.zshrc
echo "sudo service docker start >/dev/null 2>&1" >> /home/newday/.zshrc

