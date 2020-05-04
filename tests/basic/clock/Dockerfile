FROM alpine:3.6 AS builder

RUN apk add --no-cache gcc musl-dev

ADD *.c /
RUN gcc -g -o clock clock.c

FROM alpine:3.6

COPY --from=builder clock .
ADD app /app
