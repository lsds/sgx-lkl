FROM alpine:3.10

RUN apk add --no-cache \
    wget fontconfig ttf-dejavu openjdk8-jre

RUN mkdir /dacapo \
    && wget "https://downloads.sourceforge.net/project/dacapobench/9.12-bach-MR1/dacapo-9.12-MR1-bach.jar" -O /dacapo/dacapo-9.12-MR1-bach.jar
