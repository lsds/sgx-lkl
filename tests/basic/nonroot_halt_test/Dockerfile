FROM alpine:3.6 AS builder

RUN apk add --no-cache gcc musl-dev

ADD nonroot_halt_test.c .
RUN gcc -g -o nonroot_halt_test nonroot_halt_test.c

FROM alpine:3.6

COPY --from=builder nonroot_halt_test .
