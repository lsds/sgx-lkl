FROM alpine:3.10

RUN apk add --no-cache \
    wget openjdk8-dbg

RUN mkdir /dacapo \
    && wget "https://sourceforge.net/projects/dacapobench/files/latest/download" -O /dacapo/dacapo-9.12-MR1-bach.jar
