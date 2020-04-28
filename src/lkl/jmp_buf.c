#include <lkl_host.h>
#include <setjmp.h>

void sgxlkl_jmp_buf_set(struct lkl_jmp_buf* jmpb, void (*f)(void))
{
    if (!setjmp(*((jmp_buf*)jmpb->buf)))
        f();
}

void sgxlkl_jmp_buf_longjmp(struct lkl_jmp_buf* jmpb, int val)
{
    longjmp(*((jmp_buf*)jmpb->buf), val);
}
