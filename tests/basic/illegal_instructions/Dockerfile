FROM alpine:3.6 AS builder

RUN apk add --no-cache gcc musl-dev linux-headers

ADD illegal_instructions-test.c .
RUN gcc -g -o illegal_instructions-test illegal_instructions-test.c

FROM alpine:3.6

COPY --from=builder illegal_instructions-test .
