FROM alpine:3.6 AS builder

RUN apk add --no-cache gcc musl-dev

ADD *.c /
RUN gcc -g -o helloworld helloworld.c

FROM alpine:3.6

COPY --from=builder helloworld .
ADD app /app
