SGX-LKL-OE OpenMP Sample Application
==============================================

NOTE: This sample currently only works in software mode.

1. Run the OpenMP sample application from `app/openmp-test.cc` using:

```
make run-hw
```

or 

```
make run-sw
```

Note that Alpine Linux currently only includes binary packages for the GCC OpenMP 
implementation (and not the LLVM one).