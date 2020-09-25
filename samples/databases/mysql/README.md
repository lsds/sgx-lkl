Running MySQL with SGX-LKL-OE
=============================

The following instructions launch a MySQL instance inside of an SGX enclave and then run the multi-threaded sysbench OLTP benchmark using that instance.

1. Install the ``mariadb-client`` and ``sysbench`` Ubuntu packages on the host.

2. Ensure that you have set up networking support for SGX-LKL by having run `tools/sgx-lkl-setup`.

3. Launch MySQL in an SGX hardware enclave with:

```
make run-hw
```
or in software mode with:

```
make run-sw
```

4. After the MySQL instance is running, create a new benchmarking database:

```
mysql -h 10.0.1.1 -u root -e 'create database sbtest'
```

5. Prepare the sysbench OLTP data in the database. The following command creates an approx. 2.5 GB database spread across 10 tables:
```
sysbench oltp_read_write --threads=4 --db-driver=mysql --mysql-host=10.0.1.1 --mysql-user=root --tables=10 --table-size=1000000 prepare
```

6. Run the OLTP sysbench benchmark with 4 threads for 20 seconds:
```
sysbench oltp_read_write --threads=4 --events=0 --time=20 --db-driver=mysql --mysql-host=10.0.1.1 --mysql-user=root --tables=10 --table-size=1000000 --report-interval=1 run
```
