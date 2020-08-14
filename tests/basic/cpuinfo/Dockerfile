FROM alpine:3.6 AS builder

RUN apk add --no-cache gcc musl-dev

ADD *.c /
RUN gcc -o cpuinfo -O0 -ggdb3 cpuinfo.c

FROM alpine:3.6

COPY --from=builder cpuinfo .
