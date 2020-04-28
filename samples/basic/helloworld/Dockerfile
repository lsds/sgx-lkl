FROM alpine:3.8

ARG UID
ARG GID

USER root

# Build packages: build-base gcc wget git curl

RUN apk add --no-cache bash shadow sudo && \
    addgroup -S alpine; \
    adduser -S -G alpine -s /bin/bash user; \
    echo "user ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/user && \
    chmod 0440 /etc/sudoers.d/user

WORKDIR /app
RUN chown user:alpine /app
USER user

#ENV PS1="\[\033[31;40;1m\][\u@\h]\[\033[32;40;1m\] \W\[\033[33;40;1m\]>\[\033[0m\]"

COPY --chown=user:alpine app/ .

# Start from a Bash prompt
CMD ["/bin/bash"]