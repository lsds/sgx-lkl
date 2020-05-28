FROM alpine:3.10

RUN apk add --no-cache \
    python3 py3-numpy

ADD app /app

ENTRYPOINT ["python3"]
CMD ["/app/python-helloworld.py"]
