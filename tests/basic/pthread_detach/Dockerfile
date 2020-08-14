FROM alpine:3.6 AS builder

RUN apk add --no-cache gcc musl-dev

ADD *.c /
RUN gcc -fPIE -pie -o pthread_detach pthread_detach.c -g

FROM alpine:3.6

COPY --from=builder pthread_detach .
