# builder for compile
FROM alpine:3.10 AS builder

ARG UID
ARG GID

USER root

RUN apk update
RUN apk add --no-cache bash shadow unixodbc-dev build-base

ADD *.c /app/
ADD *.h /app/
RUN gcc -g -fshort-wchar -fPIC -o /app/cksp.so -shared /app/cksp.c
RUN gcc -g -o /app/odbc_app -fshort-wchar /app/odbc_app.c /app/odbc_proxy.c -lodbc -ldl

ENV PS1="\[\033[31;40;1m\][\u@\h]\[\033[32;40;1m\] \W\[\033[33;40;1m\]>\[\033[0m\]"

# build image for execution
FROM alpine:3.10

RUN apk add --no-cache bash shadow sudo curl && \
    addgroup -S alpine; \
    adduser -S -G alpine -s /bin/bash user; \
    echo "user ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/user && \
    chmod 0440 /etc/sudoers.d/user

COPY --from=builder /app/cksp.so .
COPY --from=builder /app/odbc_app .

RUN mkdir -p /tmp/msodbcinstall && cd /tmp/msodbcinstall && \
curl -O https://download.microsoft.com/download/e/4/e/e4e67866-dffd-428c-aac7-8d28ddafb39b/msodbcsql17_17.5.2.2-1_amd64.apk 
RUN cd /tmp/msodbcinstall && sudo apk add --allow-untrusted $(ls)
RUN rm -rf /tmp/msodbcinstall

WORKDIR /
# Start from a Bash prompt
CMD ["/bin/bash"]
