#ifndef _ENV_H
#define _ENV_H

#include "shared/oe_compat.h"

uint64_t size_str_to_uint64(const char* str, uint64_t def, uint64_t max);

void size_uint64_to_str(uint64_t size, char* buf, uint64_t len);

uint64_t getenv_uint64(const char* var, uint64_t def, uint64_t max);

char* getenv_str(const char* var, const char* def);

int getenv_bool(const char* var, int def);

#endif /* _ENV_H */