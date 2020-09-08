Running Redis with SGX-LKL-OE
=============================

1. Make sure that you have installed ``redis-cli``. In Ubuntu, the package that
   contains it is called ``redis-tools``.

2. Ensure that you have set up netoworking and TLS support by running `tools/sgx-lkl-setup`.

3. Build the Redis file sytem image:

```
make
```

4. Run the Redis service with:

```
make run-hw
```

or 

```
make run-sw
```

5. Execute client requests against this instance:

```
./run-redis-client.sh
```
