#!/bin/bash

ssh-keygen -q -t rsa -b 4096 -N '' <<< $'\ny' >/dev/null 2>&1


echo -e "\nSSH key pair generated - here is the public key so you can add it to github\n\n"
cat ~/.ssh/id_rsa.pub
echo -e "\n\n"
