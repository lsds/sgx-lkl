#/bin/bash

# docker-machine create --driver generic --generic-ip-address=maru23.doc.res.ic.ac.uk --generic-ssh-key ~/.ssh/id_rsa-wombats --generic-ssh-user=prp maru23

VOLUME_MOUNTS=$PWD:/sgx-lkl
SSH_AGENT_WORKAROUND=
DEBUG=1
LOGIN=
SIM=unknown
REMOTE_MACHINE=
SGX_DOCKER="--device=/dev/isgx --device=/dev/gsgx -v /var/run/aesmd:/var/run/aesmd"
SGX_LKL_SIGN="build/sgx-lkl-sign -t 8 -k build/config/enclave_debug.key -f build/libsgxlkl.so &&"

function usage() {
    echo "Usage:"
    echo "`basename $0`  -h|-?                                        Display this help message."
    echo "                   build                  <-s|-h> [-r] [-l]     Build SGX-LKL in simulation (-s) or SGX hardware mode (-h)"
    echo "                                                                  -r: compiles in release mode without debug symbols"
    echo "                                                                  -l: do not build automatically but login to container"
    echo "                   deploy-jvm-helloworld <-s|-h> [-m machine]   Deploy JVM HelloWorld with SGX-LKL in simulatiuon (-s) or SGX hardware mode (-h)"
    echo "                                                                  -m  machine: deploy on remote Docker machine not localhost"
}

function parse_params() {    
    while getopts ":shrlm:" opt; do
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
                LOGIN=1
                ;;
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
    shift $((OPTIND-1))

    if [[ ${SIM} == "unknown" ]]; then
        echo "Missing option: <-s|-h>" 1>&2
        usage
        exit 1
    fi

}

function build-sgx_lkl() {
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

    BUILD_CMD="cd /sgx-lkl && make ${SIM} DEBUG=${DEBUG}"
    if [ ${LOGIN} ]; then
        BUILD_CMD="/bin/bash"
    fi

    docker run -it --rm --privileged=true -u `id -u $USER` -v $VOLUME_MOUNTS $SSH_AGENT_WORKAROUND lsds/sgx-lkl:build /bin/bash -c "${BUILD_CMD}"
}

function deploy-jvm-helloworld() {
    echo -n Deploying JVM HelloWorld with SGX-LKL on machine 
    [[ ${REMOTE_MACHINE} ]] && echo -n " '${REMOTE_MACHINE}' " || echo -n " 'localhost' "
    echo -n in
    [[ ${SIM} ]] && echo -n " simulation " || echo -n " hardware "
    echo mode

    if [ ${REMOTE_MACHINE} ]; then
        eval $(docker-machine env ${REMOTE_MACHINE})
    fi

    docker build --target deploy -t lsds/sgx-lkl:deploy .

    if [ $SIM ]; then
        SGX_DOCKER=""
        SGX_LKL_SIGN=""
    fi

    docker run -it --rm --privileged=true \
           $SGX_DOCKER \
           lsds/sgx-lkl:deploy \
           /bin/bash -c "$SGX_LKL_SIGN \
    cd /sgx-lkl/apps/jvm/helloworld-java && make && \
    ../../../tools/sgx-lkl-java ./sgxlkl-java-fs.img HelloWorld"
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
            build-sgx_lkl
            ;;
        deploy-jvm-helloworld)
            parse_params "$@"
            deploy-jvm-helloworld
            ;;
        *)
            echo "Missing/unknown command ${subcommand}" 1>&2
            usage
            exit 1
            ;;
    esac
}

main "$@"
