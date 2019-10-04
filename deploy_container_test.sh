#!/usr/bin/env bash

#
# This script helps to validate the sgx-lkl-docker behavior for the deploy-container scenario
# It is a "quick and dirty" approach to repeatable __manual__ testing
#
# It is assumed that you've run `./sgx-lkl-docker.sh -s build` successfully.
echo "==================================================================="
echo "= YOU MUST STILL MANUALLY VALIDATE THE OUTPUT FROM THESE COMMANDS ="
echo "=                                                                 ="
echo "=     PLEASE RUN './sgx-lkl-docker.sh -s build' BEFOREHAND        ="
echo "=                                                                 ="
echo "==================================================================="

# Set this to something you don't have instances of currently running
TEST_CONTAINER_TAG="alpine:3.8"

# Logging helper for test names
function test_name() {
    echo "==================== RUNNING TEST ===================="
    echo $1
    echo "======================================================"
}

trap "echo FAILURE. COULD REQUIRE MANUAL CLEANUP. PLEASE VERIFY." EXIT

# Ensure you have no TEST_CONTAINER_TAG instances
UNEXPECTED_TEST_CONT=$(docker container ls -f "ancestor=${TEST_CONTAINER_TAG}" --format "{{ .ID }}" | sed '/^$/d')
echo $UNEXPECTED_TEST_CONT
if [[ ! -z "${UNEXPECTED_TEST_CONT}" ]]; then
    echo "Found unexpected containers derived from '${TEST_CONTAINER_TAG}': ${UNEXPECTED_TEST_CONT}"
    exit
fi

# Given container tag, not existing
test_name "Non-existent ENTRYPOINT (expected error)"
./sgx-lkl-docker.sh -s deploy-container "${TEST_CONTAINER_TAG}"

# Given container tag, existing
test_name "Existent container, given ENTRYPOINT (expect existing ignored, creation)"
LIVE_CONT=$(docker run -d "${TEST_CONTAINER_TAG}")
echo "${LIVE_CONT}"
./sgx-lkl-docker.sh -s deploy-container "${TEST_CONTAINER_TAG}" /bin/pwd
docker stop "${LIVE_CONT}"
docker run --privileged -it --rm "${TEST_CONTAINER_TAG}-secure"

# Given container tag, given run arg
test_name "With run arg (expect run-arg populated)"
./sgx-lkl-docker.sh -s deploy-container "${TEST_CONTAINER_TAG}" /bin/pwd
docker run --privileged -it --rm "${TEST_CONTAINER_TAG}-secure"

# Given container tag, given run arg and args
test_name "With run arg and parameters (expect  run-arg and params populated)"
./sgx-lkl-docker.sh -s deploy-container "${TEST_CONTAINER_TAG}" /bin/cat /proc/mounts
docker run --privileged -it --rm "${TEST_CONTAINER_TAG}-secure"

trap EXIT
echo "SUCCESS"
