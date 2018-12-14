# was ubuntu:16.04
FROM phusion/baseimage as builder

ARG UID=1000
ARG GID=1000

WORKDIR /sgx-lkl

RUN apt-get update && apt-get install -y \
  build-essential \
  curl \
  make gcc bc python xutils-dev flex bison \
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

