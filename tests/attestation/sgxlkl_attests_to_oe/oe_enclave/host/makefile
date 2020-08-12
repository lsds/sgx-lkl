# Detect C and C++ compiler options
# if not gcc and g++, default to clang-7
C_COMPILER=$(notdir $(CC))
ifeq ($(C_COMPILER), gcc)
        CXX_COMPILER=$(notdir $(CXX))
        USE_GCC = true
endif

ifeq ($(USE_GCC),)
        CC = clang-7
        CXX = clang++-7
        C_COMPILER=clang
        CXX_COMPILER=clang++
endif

CFLAGS=$(shell pkg-config oehost-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --libs)
INCDIR=$(shell pkg-config oeenclave-$(C_COMPILER) --variable=includedir)

all: build

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../tlssrv.edl --untrusted \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CC) -c $(CFLAGS) $(INCLUDES) tlssrv_u.c
	$(CXX) -c $(CXXFLAGS) $(INCLUDES) host.cpp
	$(CXX) -o tlssrv_host host.o tlssrv_u.o $(LDFLAGS) -L/opt/openenclave/lib/openenclave/enclave -lpthread -lcurl -lmbedtls -lmbedcrypto

clean:
	rm -f tlssrv_host* *.o tlssrv_u.* tlssrv_args.h
