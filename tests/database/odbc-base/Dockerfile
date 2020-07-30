# image for compile
FROM alpine:3.10 AS base-image

RUN apk add --no-cache unixodbc-dev build-base curl

WORKDIR /app/msodbcinstall

RUN curl -O https://download.microsoft.com/download/e/4/e/e4e67866-dffd-428c-aac7-8d28ddafb39b/msodbcsql17_17.5.2.2-1_amd64.apk && apk add --allow-untrusted $(ls)

ADD *.c /app/
ADD *.h /app/
RUN gcc -g -o /app/odbc_app -I/opt/microsoft/msodbcsql17/include /app/odbc_app.c /app/odbc_helper.c -lodbc

# build image for execution
FROM alpine:3.10

RUN apk add --no-cache curl

WORKDIR /
COPY --from=base-image /app/msodbcinstall /msodbcinstall
COPY --from=base-image /app/odbc_app .
 
RUN cd /msodbcinstall && apk add --allow-untrusted $(ls)
RUN rm -rf /msodbcinstall
