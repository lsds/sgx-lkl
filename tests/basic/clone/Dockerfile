FROM alpine:3.6 AS builder

RUN apk add --no-cache gcc musl-dev

ADD *.c /
ADD *.s /
RUN gcc -fPIE -pie -o clone clone.c clone.s -Wl,-z,defs -g

FROM alpine:3.6

COPY --from=builder clone .
