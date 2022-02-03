#!/bin/bash

set -euo pipefail
DIR_ME=$(realpath $(dirname $0))

# this script is called by root an must fail if no user is provided
. ${DIR_ME}/installUtils.sh
setUserName ${1-""}

curl -s "https://get.sdkman.io" | bash

