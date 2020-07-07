### Sample programs to demonstrate SGX-LKL functionality

1. Basic
   
   a. [Attack](basic/attack) \
        This sample demonstrates how memory contents can be easily read when running in regular Docker but are protected in hardware enclaves.
        Test the two scenarios and see how i) SGX-LKL protects data as compared to regular containers and ii) SGX-LKL hardware provides protection to the data in it

   b. [Helloworld](basic/helloworld) \
        Cross-compile a C application for running with SGX-LKL
        Simple hello world C program run in sgx-lkl
    
2. Containers
   
    a. [Alpine](containers/alpine) \
        Miniroot is a quick way of building a small Alpine disk image, appropriate for use with sgx-musl hosting redis.
        Some basic packages are installed by default and additions can be made
    
    b. [Encrypted](containers/encrypted) \
        Running an Encrypted and Integrity Protected Confidential Container with SGX-LKL. This sample created an encrypted image using a AES cipher and creates keys. You can run python applications in the container using `dm-integrity` and `dm-verity`
        Prints hello world from an encrypted confidential container

    c. [Redis](containers/redis) \
        Build redis file system within SGX-LKL and experiment with the redis-cli commands in this enclave 

1. Languages
   
    a. [Dotnet](languages/dotnet) \
        Run a hello-world .NET progream within an SGX-LKL image hosted in a docker container

    b. [Java](languages/java) \
        Run a hello-world program written in java from within SGX-LKL

    c. [Openmp](languages/openmp) \
        Run a OpenMP sample application in SGX-LKL

    d. [Python](languages/python) \
        Run a small python application within SGX-LKL. Uses pythons numpy to display numbers from 0 to 9999. Uses alpine as the root image

2. Machine Learning
   
    a. [Openvino](ml/openvino) \
        Use openvino deep-learning optimization tools to perform image classification using [SqueezeNet](https://arxiv.org/abs/1602.07360) topology (`squeezenet1.1`). For more information look at [this](ml/openvino/app/public_models/squeezenet1.md)

    b. [Pytorch](ml/pytorch) \
        Use pytorch open source machine learning library to run [this](ml/pytorch/app/sample.py) sample within SGX-LKL. It uses the `nn` package which modularizes a neural network and implements a two-layer network. 

    c. [Tensorflow](ml/tensorflow) \
        This is an example of TensorFlow running inside an SGX enclave with SGX-LKL-OE. It trains a simple LeNet convolutional model using the MNIST dataset for hand-written digit recognition.
