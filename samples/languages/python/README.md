SGX-LKL-OE Python and NumPy Sample Application
==============================================

In this sample you will run a simple Python application in SGX-LKL and get used to the available tools.
The aim of this sample is to verify that an application works in SGX-LKL without considering more advanced topics like encryption, attestation, networking, and deployment via Docker.

The Python application is packaged as a Docker image. Let's first verify that it works outside of SGX-LKL:

```sh
docker build -t pythonapp .
docker run --rm pythonapp
# Output:
# Confidential Computing using Intel SGX in Python with NumPy... 
# [[   0    1    2 ...   97   98   99]
#  [ 100  101  102 ...  197  198  199]
#  [ 200  201  202 ...  297  298  299]
#  ...
#  [9700 9701 9702 ... 9797 9798 9799]
#  [9800 9801 9802 ... 9897 9898 9899]
#  [9900 9901 9902 ... 9997 9998 9999]]
```

The Python script is located in the `app/` folder, the Docker image is defined in the `Dockerfile`. Have a look at both files to understand what is happening.

We can now convert the Docker image into a filesystem image which SGX-LKL can use:

```sh
sgx-lkl-disk create --docker=pythonapp --size=300M pythonapp.img
```

The filesystem image contains only the files of the Docker image, but not its runtime metadata (like entrypoint, working directory, and environment variables). To run SGX-LKL we need to create configuration files containing these information. Fortunately, during conversion, this runtime metadata was queried from Docker and stored in special files named `pythonapp.img.*`. The `sgx-lkl-cfg` tool can use these files to generate an initial set of SGX-LKL host and application configuration files:

```sh
sgx-lkl-cfg create --disk pythonapp.img
```
Have a look at the generated `host-config.json` and `app-config.json` files and verify that they are as expected.

We are now ready to run the application in SGX-LKL:

```sh
sgx-lkl-run-oe --host-config=host-config.json --app-config=app-config.json --hw-debug
```
Use `--sw-debug` if your machine does not support SGX.
