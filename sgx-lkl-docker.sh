#/bin/bash

# docker-machine create --driver generic --generic-ip-address=maru23.doc.res.ic.ac.uk --generic-ssh-key ~/.ssh/id_rsa-wombats --generic-ssh-user=prp maru23

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

function usage() {
    echo
    echo "Usage:"
    echo "`basename $0`  [-h|-?]                     Display this help message."
    echo "  build <-s|-h> [-r] [-l]                      Build SGX-LKL in simulation (-s) or SGX hardware mode (-h)"
    echo "                                                 -r: compiles in release mode without debug symbols"
    echo "                                                 -l: do not build automatically but login to container"
    echo "  deploy <-s|-h> [-m machine] [-l] [-a app]    Deploy application with SGX-LKL in simulatiuon (-s) or SGX hardware mode (-h)"
    echo "                                                 -m  machine: deploy on remote Docker machine not localhost"
    echo "                                                 -l: do not launch applicaton but just login to container"
    echo "                                                 -a app: application to launch"
    echo "                                                         Possible values: busybox, jvm-helloworld"
}

function parse_params() {    
    while getopts ":shrlm:a:" opt; do
        case ${opt} in
            s)
                SIM=sim
                ;;
            h)
                SIM=""
                ;;
            r)
                DEBUG=0
                ;;
            l)
                LOGIN=true
                DOCKER_CMD="/bin/bash"
                ;;
            m)
                REMOTE_MACHINE=${OPTARG}
                ;;
            a)
                APP=${OPTARG}
                ;;
            *)
                echo "Invalid option: -$OPTARG" 1>&2
                usage
                exit 1
                ;;
        esac
    done
    shift $((OPTIND-1))

    if [[ ${SIM} == "unknown" ]]; then
        echo "Missing option: <-s|-h>" 1>&2
        usage
        exit 1
    fi

}

function build() {
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

function deploy() {
    echo -n Deploying SGX-LKL on machine 
    [[ ${REMOTE_MACHINE} ]] && echo -n " '${REMOTE_MACHINE}' " || echo -n " 'localhost' "
    echo -n in
    [[ ${SIM} ]] && echo -n " simulation " || echo -n " hardware "
    echo mode and launching ${APP}

    if [ ${REMOTE_MACHINE} ]; then
        eval $(docker-machine env ${REMOTE_MACHINE})
    fi

    docker build --target deploy -t lsds/sgx-lkl:deploy .

    if [ $SIM ]; then
        SGX_DOCKER=""
        SGX_LKL_SIGN=""
    fi

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
            echo "Unknown applcation ${APP}" 1>&2
            usage
            exit 1
            ;;
    esac

    [ -z "${DOCKER_CMD}" ] && DOCKER_CMD="$APP_BUILD $SGX_LKL_PARAMS $LAUNCH_CMD $APP_IMG $APP_CMD"

    [ ! -z "${LOGIN}" ] && DOCKER_CMD="(cd /sgx-lkl/apps/miniroot && make) && ${DOCKER_CMD}"

    docker run -it --rm --privileged=true \
           $SGX_DOCKER \
           lsds/sgx-lkl:deploy \
           /bin/bash -c "$SGX_LKL_SIGN ${DOCKER_CMD}" 
}

function main() {
    while getopts ":h?" opt; do
        case ${opt} in
            h|?)
                usage
                exit 0
                ;;
            \?)
                echo "Unknown option: -$OPTARG" 1>&2
                exit 1
                ;;
        esac
    done

    shift $((OPTIND-1))
    subcommand=$1; shift

    case "$subcommand" in
        build)
            parse_params "$@"
            build
            ;;
        deploy)
            parse_params "$@"
            deploy
            ;;
        *)
            echo "Missing/unknown command ${subcommand}" 1>&2
            usage
            exit 1
            ;;
    esac
}

main "$@"
