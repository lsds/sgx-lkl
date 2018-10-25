/*
 * Copyright 2016, 2017, 2018 Imperial College London
 */

#ifndef _MUSLKL_LIB_JMP_BUF_H
#define _MUSLKL_LIB_JMP_BUF_H

void sgxlkl_jmp_buf_set(struct lkl_jmp_buf *jmpb, void (*f)(void));
void sgxlkl_jmp_buf_longjmp(struct lkl_jmp_buf *jmpb, int val);

#endif
