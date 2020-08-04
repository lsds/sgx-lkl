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
COMMONS="../../../common"

all: build

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../oeApp.edl --untrusted \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CC) -c $(CFLAGS) $(INCLUDES) oeApp_u.c
	$(CC) -c $(CXXFLAGS) $(INCLUDES) $(COMMONS)/json_utils.c
	$(CXX) -c $(CXXFLAGS) $(INCLUDES) $(COMMONS)/curl_helper.cpp
	$(CXX) -c $(CXXFLAGS) $(INCLUDES) $(COMMONS)/auth_helper.cpp
	$(CXX) -c $(CXXFLAGS) $(INCLUDES) $(COMMONS)/maa_helper.cpp
	$(CXX) -c $(CXXFLAGS) $(INCLUDES) host.cpp
	$(CXX) -o oeApp_host host.o oeApp_u.o curl_helper.o auth_helper.o json_utils.o maa_helper.o $(LDFLAGS)  -L/opt/openenclave/lib/openenclave/enclave -lpthread -lcurl -lmbedtls -lmbedcrypto

clean:
	rm -f oeApp_host* *.o oeApp_u.* oeApp_args.h
