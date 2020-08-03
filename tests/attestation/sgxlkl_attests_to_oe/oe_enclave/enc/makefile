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

CFLAGS=$(shell pkg-config oeenclave-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --libs)
INCDIR=$(shell pkg-config oeenclave-$(C_COMPILER) --variable=includedir)
COMMONS="../../common"

.PHONY: all build clean run

all:
	$(MAKE) build
	$(MAKE) sign

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../tlssrv.edl --trusted \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CXX) -c $(CXXFLAGS) $(INCLUDES) -std=c++11 tlssrv.cpp
	$(CXX) -c $(CFLAGS) $(CINCLUDES) $(COMMONS)/gencreds.cpp
	$(CC) -c $(CFLAGS) $(CINCLUDES) tlssrv_t.c
	$(CXX) -o tlssrv_enc tlssrv.o gencreds.o tlssrv_t.o $(LDFLAGS) -lmbedtls -lmbedcrypto -loehostsock -loehostresolver -loecore -loelibc -loesyscall

sign:
	oesign sign -e tlssrv_enc -c enc.conf -k private.pem

clean:
	rm -f *.o tlssrv_enc tlssrv_enc.signed tlssrv_t.* tlssrv_args.h
