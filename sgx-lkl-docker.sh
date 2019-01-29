#!/usr/bin/env bash

# Initialisation of remote Docker machine:
#
# docker-machine create --driver generic --generic-ip-address=<host> --generic-ssh-key ~/.ssh/<key> --generic-ssh-user=<user> <machine_id>

set -e

VOLUME_MOUNTS=$PWD:/sgx-lkl
SSH_AGENT_WORKAROUND=

DEBUG=1
SIM=unknown
LOGIN=
REMOTE_MACHINE=

SGX_LKL_SIGN="/sgx-lkl/build/sgx-lkl-sign -t 8 -k /sgx-lkl/build/config/enclave_debug.key -f /sgx-lkl/build/libsgxlkl.so &&"
SGX_LKL_PARAMS="SGXLKL_VERBOSE=1"
APP=busybox
SGX_DOCKER="--device=/dev/isgx --device=/dev/gsgx -v /var/run/aesmd:/var/run/aesmd"
ESCALATE_CMD="sudo"
IMG_SLACK_SIZE=500 # was 10 MB

function usage() {
    echo
    echo "Usage:"
    echo "`basename $0` <-s|-h>                        Use SGX-LKL in simulation (-s) or SGX hardware mode (-h)"
    echo "  build [-r] [-l]                                Build SGX-LKL"
    echo "                                                   -r: compiles in release mode without debug symbols"
    echo "                                                   -l: do not build automatically but login to container"
    echo "  deploy-app [-m machine] [-a app]               Deploy in-tree application with SGX-LKL"
    echo "                                                   -m machine: deploy on remote Docker machine not localhost"
    echo "                                                   -a app: application to launch"
    echo "                                                     Possible values: busybox, jvm-helloworld"
    echo "                                                     Empty provides a login shell to the container"
    echo "  deploy-container <container_tag> <cmd> [args]  Create secure container run by SGX-LKL from container <container_tag>"
    echo "                                                 that executes binary <cmd> with arguments [args]."
    echo " [-?]       Display this help message."
    exit 1
}

function build() {
    local OPTIND OPTARG opt
    while getopts ":rl" opt; do
        case ${opt} in
            r)
                DEBUG=0
                ;;
            l)
                LOGIN=true
                DOCKER_CMD="/bin/bash"
                ;;
            *)
                echo "Invalid option: -$OPTARG" 1>&2
                usage
                exit 1
                ;;
        esac
    done
    shift $((OPTIND-1))

    echo -n Building SGX-LKL using Docker in
    [[ ${SIM} ]] && echo -n " simulation " || echo -n " hardware "
    echo -n mode
    [[ ${DEBUG} == 0 ]] && echo -n " without " || echo -n " with "
    echo debug symbols...

    if [ "$(uname)" == "Darwin" ]; then
        echo Note that SSH agent access inside the Docker container under macOS depends on https://github.com/uber-common/docker-ssh-agent-forward
        SSH_AGENT_WORKAROUND=`pinata-ssh-mount`
    elif [ "$(uname)" == "Linux" ]; then
        SSH_AGENT_WORKAROUND="--volume $SSH_AUTH_SOCK:/ssh-agent --env SSH_AUTH_SOCK=/ssh-agent"
    fi

    docker build --target builder -t lsds/sgx-lkl:build --build-arg UID=`id -u $USER` --build-arg GID=`id -g $USER` .

    [ -z "${DOCKER_CMD}" ] && DOCKER_CMD="cd /sgx-lkl && make ${SIM} DEBUG=${DEBUG}"

    docker run -it --rm --privileged=true -u `id -u $USER` -v $VOLUME_MOUNTS $SSH_AGENT_WORKAROUND lsds/sgx-lkl:build /bin/bash -c "${DOCKER_CMD}"
}

function deploy-app() {
    local OPTIND OPTARG opt
    while getopts ":m:" opt; do
        case ${opt} in
            m)
                REMOTE_MACHINE=${OPTARG}
                ;;
            *)
                echo "Invalid option: -$OPTARG" 1>&2
                usage
                exit 1
                ;;
        esac
    done

    APP=$@
    case ${APP} in
        busybox)
            APP_BUILD="(cd /sgx-lkl/apps/miniroot && make) &&"
            LAUNCH_CMD="/sgx-lkl/build/sgx-lkl-run"
            APP_IMG="/sgx-lkl/apps/miniroot/sgxlkl-miniroot-fs.img"
            APP_CMD="/bin/busybox uname -a"
            ;;
        jvm-helloworld)
            APP_BUILD="(cd /sgx-lkl/apps/jvm/helloworld-java && make) &&"
            LAUNCH_CMD="/sgx-lkl/tools/sgx-lkl-java"
            APP_IMG="/sgx-lkl/apps/jvm/helloworld-java/sgxlkl-java-fs.img"
            APP_CMD="HelloWorld"
            ;;
        *)
            LOGIN=true
            DOCKER_CMD="/bin/bash"
            ;;
    esac

    echo -n "Deploying SGX-LKL on machine"
    [[ ${REMOTE_MACHINE} ]] && echo -n " '${REMOTE_MACHINE}' " || echo -n " 'localhost' "
    echo -n "in"
    [[ ${SIM} ]] && echo -n " simulation " || echo -n " hardware "
    echo "mode and launching ${APP}"

    if [ ${REMOTE_MACHINE} ]; then
        eval $(docker-machine env ${REMOTE_MACHINE})
    fi

    docker build --target deploy -t lsds/sgx-lkl:deploy .

    if [ $SIM ]; then
        SGX_DOCKER=""
        SGX_LKL_SIGN=""
    fi

    [ -z "${DOCKER_CMD}" ] && DOCKER_CMD="$APP_BUILD $SGX_LKL_PARAMS $LAUNCH_CMD $APP_IMG $APP_CMD"

    [ ! -z "${LOGIN}" ] && DOCKER_CMD="(cd /sgx-lkl/apps/miniroot && make) && ${DOCKER_CMD}"

    docker run -it --rm --privileged=true \
           $SGX_DOCKER \
           lsds/sgx-lkl:deploy \
           /bin/bash -c "$SGX_LKL_SIGN ${DOCKER_CMD}" 
}

function deploy-container() {
    SRC_CONTAINER=$1
    [ -z "${SRC_CONTAINER}" ] && (echo "Missing source container <container_tag>" && usage)

    shift
    BINARY_CMD=$1
    [ -z "${BINARY_CMD}" ] && (echo "Missing command <cmd> to run" && usage)

    shift
    BINARY_ARGS=$@

    SEC_CONTAINER="${SRC_CONTAINER}-secure"

    echo "Creating secure container '${SEC_CONTAINER}' from container '${SRC_CONTAINER}' with default enclave launch command '${BINARY_CMD} ${BINARY_ARGS}'"

    CONTAINER_TAR=${SRC_CONTAINER}.tar
    ENCLAVE_ROOT_IMG=enclave_rootfs.img
    MOUNTPOINT="/mnt/ext4disk"

    docker export -o ${CONTAINER_TAR} ${SRC_CONTAINER}

    TAR_FILESIZE=`du -m ${CONTAINER_TAR} | cut -f1`
    IMG_SIZE=$(( ${TAR_FILESIZE} + ${IMG_SLACK_SIZE} ))

    docker run -it --rm --privileged=true -u `id -u $USER` -v $VOLUME_MOUNTS $SSH_AGENT_WORKAROUND lsds/sgx-lkl:build /bin/bash -c "\\

        dd if=/dev/zero of=${ENCLAVE_ROOT_IMG} count=${IMG_SIZE} bs=1M 2>/dev/null\
            && mkfs.ext4 -q ${ENCLAVE_ROOT_IMG}\
            && ${ESCALATE_CMD} mkdir -p ${MOUNTPOINT}\
            && ${ESCALATE_CMD} mount -t ext4 -o loop ${ENCLAVE_ROOT_IMG} ${MOUNTPOINT}\
            && ${ESCALATE_CMD} tar -C ${MOUNTPOINT} -xf ${CONTAINER_TAR}\
            && ${ESCALATE_CMD} sh -c 'echo \"nameserver 8.8.8.8\" > ${MOUNTPOINT}/etc/resolv.conf'\
            && ${ESCALATE_CMD} umount ${MOUNTPOINT}\
            && ${ESCALATE_CMD} rm -f ${CONTAINER_TAR}"

    docker build -q --build-arg binary_cmd="${BINARY_CMD}" --build-arg binary_args="${BINARY_ARGS}" --target min-deploy -t ${SEC_CONTAINER} .

    rm -f ${ENCLAVE_ROOT_IMG}
}

function main() {
    while getopts ":?hs" opt; do
        case ${opt} in
            h)
                SIM=""
                break
                ;;
            s)
                SIM="sim"
                break
                ;;
            ?)
                usage
                ;;
            \?)
                echo "Unknown option: -$OPTARG" 1>&2
                exit 1
                ;;
        esac
    done

    [ ${SIM} == "unknown" ] && (echo "Missing option: <-s|-h>" 1>&2; usage)

    shift $((OPTIND-1))
    subcommand=$1; shift

    case "$subcommand" in
        build)
            build "$@"
            ;;
        deploy-app)
            deploy-app "$@"
            ;;
        deploy-container)
            deploy-container "$@"
            ;;
        *)
            echo "Missing/unknown command '${subcommand}'" 1>&2
            usage
            exit 1
            ;;
    esac
}

main "$@"
