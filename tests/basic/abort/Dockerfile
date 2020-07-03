FROM alpine:3.6 AS builder

RUN apk add --no-cache gcc musl-dev

ADD *.c /
RUN gcc -fPIE -pie -o abort -O0 -ggdb3 abort.c

FROM alpine:3.6

COPY --from=builder abort .
