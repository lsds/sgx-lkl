/*
 * Copyright 2016, 2017, 2018 Imperial College London
 * 
 * This file is part of SGX-LKL.
 * 
 * SGX-LKL is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * SGX-LKL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with SGX-LKL.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _MUSLKL_LIB_JMP_BUF_H
#define _MUSLKL_LIB_JMP_BUF_H

void sgxlkl_jmp_buf_set(struct lkl_jmp_buf *jmpb, void (*f)(void));
void sgxlkl_jmp_buf_longjmp(struct lkl_jmp_buf *jmpb, int val);

#endif
