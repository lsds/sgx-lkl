# This test explicitly uses Alpine 3.8, as that Node.JS version 
# requires a working epoll_wait syscall, which we want to test. 
FROM alpine:3.8

RUN apk add --no-cache \
    nodejs

RUN mkdir -p /app

COPY index.js /app/index.js
