#ifndef _SGXLKL_UTIL_H
#define _SGXLKL_UTIL_H

#include <stdint.h>
#include <unistd.h>

void sgxlkl_host_fail(char* msg, ...);
void sgxlkl_host_err(char* msg, ...);
void sgxlkl_host_warn(char* msg, ...);
void sgxlkl_host_info(char* msg, ...);
void sgxlkl_host_verbose(char* msg, ...);
void sgxlkl_host_verbose_raw(char* msg, ...);

#endif
