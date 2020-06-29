#!/bin/bash

if [ -z "$SGXLKL_ROOT" ]; then
    echo "ERROR: 'SGXLKL_ROOT' is undefined. Please export SGXLKL_ROOT=<SGX-LKL-OE> source code repository"
    exit 1
fi

SGXLKL_VERSION=$(cat "$SGXLKL_ROOT/VERSION")
if [[ $SGXLKL_VERSION == *-dev ]]; then
    if [[ -n $BUILD_BUILDNUMBER ]]; then
        # If we're running in Azure Pipelines, use build number (YYYYMMDD.n).
        SGXLKL_VERSION=${SGXLKL_VERSION}.${BUILD_BUILDNUMBER}
    else
        SGXLKL_VERSION=${SGXLKL_VERSION}.$(date -u +%Y%m%d%H%M)
    fi
fi
SGXLKL_VERSION=${SGXLKL_VERSION}-$(git rev-parse --short HEAD)
echo "SGXLKL_VERSION=${SGXLKL_VERSION}"

# Expose version as job-scoped variable, referenced with $(SGXLKL_VERSION).
# Syntax: https://docs.microsoft.com/en-us/azure/devops/pipelines/process/variables#set-a-job-scoped-variable-from-a-script
echo "##vso[task.setvariable variable=SGXLKL_VERSION]${SGXLKL_VERSION}"
