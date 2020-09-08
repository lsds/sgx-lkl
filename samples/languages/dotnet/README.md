Running a DotNet application using SGX-LKL-OE
=============================================

It is possible to run this sample by typing:

```
make run-hw
```

or

```
make run-sw
```

Manual steps
------------

Alternatively, it is possible to run the sample by doing the following steps:

1. Build the Docker container that contains the DotNet application:

```
docker build -t dotnet-app:dev .
```

2. Build the SGX-LKL-OE root file system image from the container:
```
${SGXLKL_ROOT}/tools/sgx-lkl-disk create --size=250M --docker=dotnet-app:dev sgxlkl-dotnet.img
```

3. Run with SGX-LKL-OE:

```
DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 SGXLKL_MMAP_FILES=Shared SGXLKL_VERBOSE=1 ${SGXLKL_ROOT}/build/sgx-lkl-run-oe --hw-debug sgxlkl-dotnet.img /usr/bin/dotnet /app/HelloWorld.dll

```
Note that CoreCLR at the moment requires at least a 1 GB enclave size.
