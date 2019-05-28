/*
 * Copyright 2016, 2017, 2018 Imperial College London
 */
#ifndef _SGXLKL_UTIL_INCLUDE
#define _SGXLKL_UTIL_INCLUDE

#include <stdint.h>
#include <unistd.h>

void sgxlkl_fail(char *msg, ...);
void sgxlkl_err(char *msg, ...);
void sgxlkl_warn(char *msg, ...);
void sgxlkl_info(char *msg, ...);

uint64_t size_str_to_uint64(const char *str, uint64_t def, uint64_t max);
uint64_t getenv_uint64(const char *var, uint64_t def, uint64_t max);
char *getenv_str(const char *var, const char *def);
int getenv_bool(const char *var, int def);

uint64_t next_pow2(uint64_t x);
ssize_t hex_to_bytes(const char *hex, char **result);

#endif /* _SGXLKL_UTIL_INCLUDE*/
