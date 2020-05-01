FROM alpine:3.6 AS builder

RUN apk add --no-cache gcc musl-dev

ADD stat.c .
RUN gcc -g -o stat stat.c

FROM alpine:3.6

COPY --from=builder stat .
ADD app /app
