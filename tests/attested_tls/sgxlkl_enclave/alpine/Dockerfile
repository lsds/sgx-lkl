# Copyright Microsoft. 
# Licensed under the attached Microsoft Software License Terms

FROM alpine:3.10

ARG UID
ARG GID

USER root

#RUN echo "http://dl-8.alpinelinux.org/alpine/edge/community" >> /etc/apk/repositories

RUN apk add --no-cache bash shadow sudo build-base wget git krb5-libs libstdc++ curl-dev bind-tools mbedtls-dev && \
    addgroup -S alpine; \
    adduser -S -G alpine -s /bin/bash user; \
    echo "user ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/user && \
    chmod 0440 /etc/sudoers.d/user

ENV PS1="\[\033[31;40;1m\][\u@\h]\[\033[32;40;1m\] \W\[\033[33;40;1m\]>\[\033[0m\]"

# Start from a Bash prompt
CMD ["/bin/bash"]
