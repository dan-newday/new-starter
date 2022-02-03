#!/bin/bash

set -euo pipefail
DIR_ME=$(realpath $(dirname $0))

# this script is called by root an must fail if no user is provided
. ${DIR_ME}/installUtils.sh
setUserName ${1-""}

CHSH=no  sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"

