FROM alpine:3.10

RUN apk add --no-cache \
    python3 py3-numpy

ADD src /src

ENTRYPOINT ["python3"]
CMD ["/src/python-helloworld.py"]
