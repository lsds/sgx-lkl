FROM alpine:3.10

ARG UID
ARG GID

USER root
RUN apk add --no-cache bash shadow sudo build-base gcc wget git curl cmake python3 vim python2

RUN addgroup -g 1001 -S alpine; \
    adduser -u 1000 -S -G alpine -s /bin/bash user; \
    echo "user ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/user && \
    chmod 0440 /etc/sudoers.d/user

WORKDIR /home/user
RUN chown user:alpine /home/user
USER user

ENV PS1="\[\033[31;40;1m\][\u@\h]\[\033[32;40;1m\] \W\[\033[33;40;1m\]>\[\033[0m\]"

RUN git clone --progress https://github.com/opencv/dldt.git && \
    cd dldt/inference-engine && \
    git checkout tags/2020.1 && \
    git submodule init && \
    git submodule update --recursive --progress

RUN cd dldt && \
    mkdir build && \
    cd build && \
    cmake -DCMAKE_BUILD_TYPE=Debug \
          -DTHREADING=SEQ \
          -DENABLE_VPU=OFF \
          -DENABLE_GNA=OFF \
          -DENABLE_CLDNN=OFF \
          -DENABLE_OPENCV=OFF \
          ..

RUN cd dldt/build && make --jobs=$(nproc --all)

# Start from a Bash prompt
CMD ["/bin/bash"]
