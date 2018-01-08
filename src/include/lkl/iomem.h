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

#ifndef _LKL_LIB_IOMEM_H
#define _LKL_LIB_IOMEM_H

struct lkl_iomem_ops {
    int (*read)(void *data, int offset, void *res, int size);
    int (*write)(void *data, int offset, void *value, int size);
};

void* register_iomem(void *data, int size, const struct lkl_iomem_ops *ops);
void unregister_iomem(void *iomem_base);
void *lkl_ioremap(long addr, int size);
int lkl_iomem_access(const volatile void *addr, void *res, int size, int write);

#endif /* _LKL_LIB_IOMEM_H */
