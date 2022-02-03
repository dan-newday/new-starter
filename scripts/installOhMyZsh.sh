#!/bin/bash

sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended

THEME="bira"; sed -i s/^ZSH_THEME=".\+"$/ZSH_THEME=\"$THEME\"/g ~/.zshrc && source ~/.zshrc && echo "Edited line in ~/zshrc :" && cat ~/.zshrc | grep -m 1 ZSH_THEME

