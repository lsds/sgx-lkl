FROM alpine:3.6 AS builder

RUN apk add --no-cache gcc musl-dev

ADD *.c /
RUN gcc -o signal -O0 -ggdb3 signal.c

FROM alpine:3.6

COPY --from=builder signal .
