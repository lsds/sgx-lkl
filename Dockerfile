# was ubuntu:16.04
FROM phusion/baseimage as builder

ARG UID=1000
ARG GID=1000

WORKDIR /sgx-lkl

RUN apt-get update && apt-get install -y \
  build-essential \
  curl \
  wget \
  pv \
  make gcc g++ bc python xutils-dev flex bison autogen libgcrypt20-dev libjson-c-dev autopoint pkgconf autoconf libtool libcurl4-openssl-dev libprotobuf-dev libprotobuf-c-dev protobuf-compiler protobuf-c-compiler libssl-dev \
  sudo \
  git

RUN useradd --create-home -u ${UID} -s /bin/bash user && \
    adduser user sudo && \
    echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER user
ENV USER=user

FROM phusion/baseimage as deploy

WORKDIR /sgx-lkl

RUN apt-get update && apt-get install -y \
  curl \
  openjdk-8-jdk-headless \
  sudo \
  make \
  && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home -s /bin/bash user && \
    adduser user sudo && \
    echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER user
ENV USER=user

COPY --chown=user:user build build/
COPY --chown=user:user apps apps/
COPY --chown=user:user tools tools/

# Start from a Bash prompt
CMD ["/bin/bash"]

# Building mimimum image that only contains SGX-LKL

FROM phusion/baseimage as min-deploy

WORKDIR /sgx-lkl

RUN apt-get update && apt-get install -y \
  sudo \
  iproute2 iptables net-tools \
  && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home -s /bin/bash user && \
    adduser user sudo && \
    echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER user
ENV USER=user

ARG binary_cmd
ENV env_binary_cmd="${binary_cmd}"
ARG binary_args
ENV env_binary_args=${binary_args}

COPY --chown=user:user build build/
COPY --chown=user:user enclave_rootfs.img  .

# Start from a Bash prompt
CMD ["/bin/bash", "-c", "sudo ip tuntap add dev sgxlkl_tap0 mode tap user user \
    && sudo ip link set dev sgxlkl_tap0 up \
    && sudo ip addr add dev sgxlkl_tap0 10.0.1.254/24 \
    && sudo iptables -I FORWARD -m state -s 10.0.1.0/24 --state NEW,RELATED,ESTABLISHED -j ACCEPT \
    && sudo iptables -I FORWARD -m state -d 10.0.1.0/24 --state NEW,RELATED,ESTABLISHED -j ACCEPT \
    && sudo iptables -t nat -A POSTROUTING -s 10.0.1.0/24 ! -d 10.0.1.0/24 -j MASQUERADE \
    && sudo sysctl -w net.ipv4.ip_forward=1 \
    && sudo chown user /dev/net/tun \
    && SGXLKL_TAP=sgxlkl_tap0 SGXLKL_HEAP=2500M /sgx-lkl/build/sgx-lkl-run /sgx-lkl/enclave_rootfs.img ${env_binary_cmd} ${env_binary_args}"]
