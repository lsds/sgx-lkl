FROM alpine:3.8

ARG UID
ARG GID

USER root

#Install packages
RUN apk add --no-cache bash shadow sudo tzdata && \
    addgroup -S alpine; \
    adduser -S -G alpine -s /bin/bash user; \
    echo "user ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/user && \
    chmod 0440 /etc/sudoers.d/user

#Build iozone package
RUN apk --update upgrade && \
    apk add --no-cache --virtual=temporary curl gcc make build-base && \
    curl http://www.iozone.org/src/current/iozone3_489.tar > /tmp/iozone.tar && \
    cd /tmp && \
    tar -xf /tmp/iozone.tar && \
    cd /tmp/iozone*/src/current && \
    make linux && \
    cp iozone /usr/bin/iozone && \
    apk del temporary && \
    rm -rf /var/cache/apk/* /tmp/iozone*

USER user

# Start from a Bash prompt
CMD ["/bin/bash"]
