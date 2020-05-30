#ifndef _VIC_DEFS_H
#define _VIC_DEFS_H

#define VIC_COUNTOF(ARR) (sizeof(ARR) / sizeof(ARR[0]))

#define VIC_OFFSETOF(TYPE, MEMBER) __builtin_offsetof(TYPE, MEMBER)

#define VIC_UNUSED __attribute__((unused))

#define __LUKS_CONCAT(X, Y) X##Y
#define VIC_CONCAT(X, Y) __LUKS_CONCAT(X, Y)

#define VIC_STATIC_ASSERT(COND) \
    typedef char VIC_CONCAT(__vic_static_assert, __LINE__)[(COND) ? 1 : -1] \
    VIC_UNUSED

#define VIC_CHECK_FIELD(T1, T2, F)                                   \
    VIC_STATIC_ASSERT(VIC_OFFSETOF(T1, F) == VIC_OFFSETOF(T2, F)); \
    VIC_STATIC_ASSERT(sizeof(((T1*)0)->F) == sizeof(((T2*)0)->F));

#define VIC_PRINTF_FORMAT(N, M) __attribute__((format(printf, N, M)))

#define VIC_STRLIT(STR) STR, sizeof(STR)-1

#define VIC_PACK_BEGIN _Pragma("pack(push, 1)")
#define VIC_PACK_END _Pragma("pack(pop)")

#define VIC_WEAK(NAME) __attribute__((__weak__, alias(#NAME)))

#endif /* _VIC_DEFS_H */
