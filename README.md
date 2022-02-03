# Welcome to PIMS!

This repo is for bootstrapping a wsl dev environment we can use for jCard/pimms development

## Prerequisites

- Access to Powershell as an administrator

## Fast (ish) development setup
open up powershell as an administrator and run the following command

```sh
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/dan-newday/new-starter/master/wsl2setup.ps1'))
```

## What does it do ?

### On the Windows host
- Installs Windows Subsystem for Linux.
- Installs Virtual Machine Platform.
- Installs WSL2 Kernel Updates.
- Installs an Ubuntu WSL environment.

### In the Ubuntu guest
- Adds a new user.
- Configures passwordless sudo for that user. 
- Updates the system.
- Installs a suite of base packages (zip, unzip, zsh etc).
- Installs Docker.
- Installs OhMyZSH.
- Installs sdkman and OpenJDK 11.0.12.
- Generates 4096 RSA keypair for use wih github.





