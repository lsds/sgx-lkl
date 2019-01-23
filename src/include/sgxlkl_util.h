/*
 * Copyright 2016, 2017, 2018 Imperial College London
 */
#ifndef _SGXLKL_UTIL_INCLUDE
#define _SGXLKL_UTIL_INCLUDE

#include <stdint.h>

uint64_t getenv_uint64(const char *var, uint64_t def, uint64_t max);
char *getenv_str(const char *var, const char *def);
int getenv_bool(const char *var, int def);

uint64_t next_pow2(uint64_t x);

#endif /* _SGXLKL_UTIL_INCLUDE*/
