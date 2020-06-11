FROM alpine:3.6 AS builder

RUN apk add --no-cache gcc musl-dev

ADD *.c /
RUN gcc -g -o hello-eeid hello-eeid.c

FROM alpine:3.6

COPY --from=builder hello-eeid .
ADD app /app
