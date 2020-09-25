FROM alpine:3.7

RUN apk add --no-cache \
    mariadb mariadb-client

RUN mysql_install_db --user=root --basedir=/usr --datadir=/var/lib/mysql

COPY my.cnf /etc/mysql/my.cnf

ENTRYPOINT ["mysqld"]