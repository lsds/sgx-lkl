FROM alpine:3.10

RUN apk add --no-cache \
    g++ libgomp

COPY /app /app

RUN cd /app && \
    g++ -o openmp-test -fopenmp openmp-test.cc

CMD [/app/openmp-test]