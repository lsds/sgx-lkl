FROM alpine:3.6 AS builder

RUN apk add --no-cache gcc musl-dev

ADD *.c /
RUN gcc -g -o global_vars_test global_vars_test.c

FROM alpine:3.6

COPY --from=builder global_vars_test .
RUN echo "Hello World!" > /helloworld.txt
