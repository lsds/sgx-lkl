#!/bin/bash
set -ex

# This script builds the docker images used for some of the samples to speed up
# the CI. Nightly builds trigger a rebuild of the images, all other builds just
# use the images built during the nightly build.

pwd

#if [[ SGXLKL_NIGHTLY_BUILD -eq 0 ]]; then
#    exit 0
#fi

sudo apt install -y ca-certificates curl apt-transport-https lsb-release gnupg

curl -sL https://packages.microsoft.com/keys/microsoft.asc |
    gpg --dearmor |
    sudo tee /etc/apt/trusted.gpg.d/microsoft.gpg > /dev/null

AZ_REPO=$(lsb_release -cs)
echo "deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli/ $AZ_REPO main" |
    sudo tee /etc/apt/sources.list.d/azure-cli.list

sudo apt update
sudo apt install -y azure-cli

az acr login --name securecontainersregistry

exit 1
