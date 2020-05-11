TensorFlow with SGX-LKL-OE
==========================

This is an example of TensorFlow running inside an SGX enclave with SGX-LKL-OE. It 
trains a simple LeNet convolutional model using the MNIST dataset for hand-written digit
recognition.

The training script is here: `app/benchmark/mnist_lenet.py`

A. Build SGX-LKL-OE
--------------------

1. Increase the configuration setting for enclave heap memory to 1.2GB (= 4KB * 327680):
```
sed -i "/NumHeapPages=/c\NumHeapPages=327680" config/params.conf
```

2. Compile SGX-LKL-OE from sources:
```
make
sudo make install
/opt/sgx-lkl/bin/sgx-lkl-setup
export PATH=$PATH:/opt/sgx-lkl/bin
```

B. Building and running TensorFlow
----------------------------------

```
cd samples/ml/tensorflow
docker build -t alpine-tensorflow -f Dockerfile-TF1.15 .
make
make run
```
