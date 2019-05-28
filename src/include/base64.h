#pragma once

#include <stdbool.h>
#include <stddef.h>

unsigned char *sgxlkl_base64_encode(const unsigned char *src, size_t len,
                  unsigned char *out, size_t *out_len);
unsigned char *sgxlkl_base64_decode(const unsigned char *src, size_t len,
                  unsigned char *out, size_t *out_len);

bool sgxlkl_base64_validate(const unsigned char *src, size_t len);
