PyTorch with SGX-LKL-OE
==========================

This is an example of PyTorch running inside an SGX enclave with SGX-LKL-OE.

The training script is here: `app/sample.py`

Build and run PyTorch with SGX-LKL-OE:
```
cd samples/ml/pytorch
docker build -t alpine-pytorch .
make
make run-hw
```
