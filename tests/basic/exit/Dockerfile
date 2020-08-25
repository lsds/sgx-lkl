FROM alpine:3.6 AS builder

RUN apk add --no-cache gcc musl-dev

ADD *.c /
RUN gcc -fPIE -pie -o exit-test exit-test.c
RUN gcc -fPIE -pie -o segfault-test segfault-test.c
RUN gcc -fPIE -pie -o raise-test raise-test.c
RUN gcc -fPIE -pie -o spin-test spin-test.c

FROM alpine:3.6

COPY --from=builder *-test /
