SGX-LKL-OE Hello World Sample
=============================

This is a simple Hello World example of how to cross-compile a C application for running with SGX-LKL. 

To build and run the example simply run

```
make
make run
```

or alternatively build and run the helloworld example directly:

```
make sgxlkl-helloworld.img
../../../build/sgx-lkl-run-oe --hw-debug sgxlkl-helloworld.img /app/helloworld
```
