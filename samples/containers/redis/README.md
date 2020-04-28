Running Redis with SGX-LKL-OE
=============================

1. Ensure that you have set up netoworking and TLS support by running `tools/sgx-lkl-setup`.

2. Build the Redis file sytem image:

```
make
```

3. Run the Redis service with:

```
make run-hw
```

or 

```
make run-sw
```

4. Execute client requests against this instance:

```
./run-redis-client.sh
```
