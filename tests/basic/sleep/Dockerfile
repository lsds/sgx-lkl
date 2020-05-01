FROM alpine:3.6 AS builder

RUN apk add --no-cache gcc musl-dev

ADD *.c /
RUN gcc -g -o sleep-test sleep-test.c

FROM alpine:3.6

COPY --from=builder sleep-test .
