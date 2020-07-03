FROM alpine:3.6 AS builder

RUN apk add --no-cache gcc musl-dev

ADD *.c /
RUN gcc -pthread -g -o pthread_join-test pthread_join-test.c

FROM alpine:3.6

COPY --from=builder pthread_join-test .
