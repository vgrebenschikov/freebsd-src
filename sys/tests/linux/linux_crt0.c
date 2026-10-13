/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Vladimir Grebenshchikov <vova@zote.me>
 */

#include "linux_syscalls.h"
#include "linux_crt0.h"

void
linux_start(void)
{

	linux_exit(main());
}

#if defined(__x86_64__)
__asm__(".global _start\n"
    "_start:\n"
    "xor %ebp,%ebp\n"
    "andq $-16,%rsp\n"
    "call linux_start\n"
    "ud2\n");
#elif defined(__aarch64__)
__asm__(".global _start\n"
    "_start:\n"
    "mov x29, xzr\n"
    "mov x30, xzr\n"
    "bl linux_start\n"
    "brk #0\n");
#else
#error "Unsupported Linux architecture"
#endif
