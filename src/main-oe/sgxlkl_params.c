#include "host/sgxlkl_params.h"

const char* sgxlkl_auto_passthrough[11] = {"SGXLKL_DEBUGMOUNT",
                                           "SGXLKL_PRINT_APP_RUNTIME",
                                           "SGXLKL_TRACE_HOST_SYSCALL",
                                           "SGXLKL_TRACE_INTERNAL_SYSCALL",
                                           "SGXLKL_TRACE_LKL_SYSCALL",
                                           "SGXLKL_TRACE_IGNORED_SYSCALL",
                                           "SGXLKL_TRACE_UNSUPPORTED_SYSCALL",
                                           "SGXLKL_TRACE_REDIRECT_SYSCALL",
                                           "SGXLKL_TRACE_MMAP",
                                           "SGXLKL_TRACE_SYSCALL",
                                           "SGXLKL_TRACE_THREAD"};