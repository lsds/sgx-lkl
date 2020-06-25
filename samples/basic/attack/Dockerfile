FROM alpine:3.6 AS builder

RUN apk add --no-cache gcc musl-dev

ADD *.c /
RUN gcc -g -o read_secret read_secret.c

FROM alpine:3.6

COPY --from=builder read_secret .
ADD secret.txt /
