#!/bin/bash

/bin/bash -c "NONINTERACTIVE=true $(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

sudo apt install -y build-essential

echo 'eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"' >> /home/newday/.zprofile
eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)
