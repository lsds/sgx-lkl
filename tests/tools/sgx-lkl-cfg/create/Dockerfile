FROM alpine:3.10

RUN apk add --no-cache python3

COPY src/* /src/

ENV GREETING="Hello"

WORKDIR /src

ENTRYPOINT ["python3"]
CMD ["/src/app.py", "John"]
