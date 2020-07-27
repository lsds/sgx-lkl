Running NodeJS with SGX-LKL
===========================

1. Build a Docker container with NodeJS:
```
$ docker build -t nodejs .
```

2. Convert the container to an SGX-LKL root file system image:
```
$ sgx-lkl-disk create --docker=nodejs --size=100M nodejs.img
```

3. Run NodeJS demo program with SGX-LKL:
```
$ sgx-lkl-run-oe --sw-debug --host-config=nodejs-host_config.json --enclave-config=nodejs-enclave_config.json
```