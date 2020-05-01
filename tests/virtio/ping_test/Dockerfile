FROM alpine:3.6 AS builder

RUN apk add --no-cache gcc musl-dev

ADD *.c /
RUN gcc -g -o dummy_server dummy_server.c

FROM alpine:3.6

COPY --from=builder dummy_server .
