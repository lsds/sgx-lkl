FROM alpine:3.10 AS builder

RUN apk add --no-cache gcc musl-dev

ADD *.c /
RUN gcc -pthread -g -o fsgsbase_unset-test fsgsbase_unset-test.c

FROM alpine:3.10

COPY --from=builder fsgsbase_unset-test .
