// Copyright Microsoft.
// Licensed under the attached Microsoft Software License Terms

#ifndef LOG_UTILS_H
#define LOG_UTILS_H

#define CONSOLE_ESCAPE "\033"
#define CONSOLE_RED CONSOLE_ESCAPE "[0;31m"
#define CONSOLE_GREEN CONSOLE_ESCAPE "[0;32m"
#define CONSOLE_YELLOW CONSOLE_ESCAPE "[0;33m"
#define CONSOLE_RESET CONSOLE_ESCAPE "[0m"

#define FAILMSG(str) CONSOLE_RED str CONSOLE_RESET
#define SUCCESSMSG(str) CONSOLE_GREEN str CONSOLE_RESET

#include <stdint.h>

#endif  // LOG_UTILS_H