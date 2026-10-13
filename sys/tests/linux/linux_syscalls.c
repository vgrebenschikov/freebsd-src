/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Vladimir Grebenshchikov <vova@zote.me>
 */

#include "linux_syscalls.h"

#if defined(__x86_64__)
static long
linux_syscall(long number, long arg1, long arg2, long arg3, long arg4)
{
	register long r10 __asm__("r10") = arg4;
	long result;

	__asm__ volatile("syscall" : "=a" (result) : "a" (number),
	    "D" (arg1), "S" (arg2), "d" (arg3), "r" (r10) : "rcx", "r11",
	    "memory");
	return (result);
}

long
linux_close(int fd)
{

	return (linux_syscall(3, fd, 0, 0, 0));
}

long
linux_open(const char *path, int flags, int mode)
{

	return (linux_syscall(2, (long)path, flags, mode, 0));
}

long
linux_write(int fd, const void *buffer, long length)
{

	return (linux_syscall(1, fd, (long)buffer, length, 0));
}

_Noreturn void
linux_exit(int status)
{

	(void)linux_syscall(231, status, 0, 0, 0);
	for (;;)
		;
}

#elif defined(__aarch64__)
static long
linux_syscall(long number, long arg1, long arg2, long arg3, long arg4)
{
	register long x0 __asm__("x0") = arg1;
	register long x1 __asm__("x1") = arg2;
	register long x2 __asm__("x2") = arg3;
	register long x3 __asm__("x3") = arg4;
	register long x8 __asm__("x8") = number;

	__asm__ volatile("svc 0" : "+r" (x0) : "r" (x1), "r" (x2),
	    "r" (x3), "r" (x8) : "memory", "cc");
	return (x0);
}

long
linux_close(int fd)
{

	return (linux_syscall(57, fd, 0, 0, 0));
}

long
linux_open(const char *path, int flags, int mode)
{

	return (linux_syscall(56, -100, (long)path, flags, mode));
}

long
linux_write(int fd, const void *buffer, long length)
{

	return (linux_syscall(64, fd, (long)buffer, length, 0));
}

_Noreturn void
linux_exit(int status)
{

	(void)linux_syscall(94, status, 0, 0, 0);
	for (;;)
		;
}

#else
#error "Unsupported Linux architecture"
#endif
