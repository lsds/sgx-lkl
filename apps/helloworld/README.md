This is a simple Hello World example of how to cross-compile a C application for running with SGX-LKL. To build and run the example simply run

```make test```

or alternatively build and run the example separately:

```
make sgxlkl-disk.img
../../build/sgx-lkl-run sgxlkl-disk.img /app/helloworld
```
