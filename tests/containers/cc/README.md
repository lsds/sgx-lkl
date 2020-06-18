This test does not run SGX-LKL on the host but inside a Docker container.
For this, a self-contained SGX-LKL installation is mounted into the container.
To run this test, make sure you installed SGX-LKL and made it self-contained:

```sh
export SGXLKL_PREFIX=/opt/sgx-lkl
sudo make install PREFIX=$SGXLKL_PREFIX
sudo -E tools/make_self_contained.sh
```

You can now run the test with `SGXLKL_PREFIX` still set.
