# image for compile
FROM alpine:3.10 AS base-image

RUN apk add --no-cache unixodbc-dev build-base

ADD *.c /app/
ADD *.h /app/
RUN gcc -g -fshort-wchar -fPIC -o /app/cksp.so -shared /app/cksp.c
RUN gcc -g -o /app/odbc_app -fshort-wchar /app/odbc_app.c /app/odbc_helper.c -lodbc -ldl

# build image for execution
FROM alpine:3.10

RUN apk add --no-cache curl

WORKDIR /
COPY --from=base-image /app/cksp.so .
COPY --from=base-image /app/odbc_app .
 
RUN mkdir -p /tmp/msodbcinstall && cd /tmp/msodbcinstall && \
curl -O https://download.microsoft.com/download/e/4/e/e4e67866-dffd-428c-aac7-8d28ddafb39b/msodbcsql17_17.5.2.2-1_amd64.apk 
RUN cd /tmp/msodbcinstall && apk add --allow-untrusted $(ls)
RUN rm -rf /tmp/msodbcinstall
