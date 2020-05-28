#!/bin/bash

export PATH="../../../build:$PATH"

sgx-lkl-run-oe --host-config=host-config.json --app-config=app-config.json $@
