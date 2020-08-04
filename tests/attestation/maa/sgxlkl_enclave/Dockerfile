FROM alpine:3.10

ARG UID
ARG GID

USER root

RUN apk update
RUN apk add --no-cache bash shadow sudo curl krb5-libs libstdc++ mbedtls curl && \
    addgroup -S alpine; \
    adduser -S -G alpine -s /bin/bash user; \
    echo "user ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/user && \
    chmod 0440 /etc/sudoers.d/user

WORKDIR /
RUN chown user:alpine /
USER user

ADD /alpine_sgxLklApp /sgxLklApp
ADD /sgxlkl_cert.der /sgxlkl_cert.der
ADD /sgxlkl_private_key.pem /sgxlkl_private_key.pem

ENV PS1="\[\033[31;40;1m\][\u@\h]\[\033[32;40;1m\] \W\[\033[33;40;1m\]>\[\033[0m\]"

# Start from a Bash prompt
CMD ["/bin/bash"]
