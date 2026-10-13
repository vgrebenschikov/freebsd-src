/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Vladimir Grebenshchikov <vova@zote.me>
 */

#include "linux_syscalls.h"

#if defined(__x86_64__)
static long
linux_syscall(long number, long arg1, long arg2, long arg3, long arg4,
    long arg5, long arg6)
{
	register long r10 __asm__("r10") = arg4;
	register long r8 __asm__("r8") = arg5;
	register long r9 __asm__("r9") = arg6;
	long result;

	__asm__ volatile("syscall" : "=a" (result) : "a" (number),
	    "D" (arg1), "S" (arg2), "d" (arg3), "r" (r10), "r" (r8),
	    "r" (r9) : "rcx", "r11", "memory");
	return (result);
}

long
linux_close(int fd)
{

	return (linux_syscall(3, fd, 0, 0, 0, 0, 0));
}

long
linux_epoll_create1(int flags)
{

	return (linux_syscall(291, flags, 0, 0, 0, 0, 0));
}

long
linux_epoll_ctl(int epfd, int op, int fd, struct linux_epoll_event *event)
{

	return (linux_syscall(233, epfd, op, fd, (long)event, 0, 0));
}

long
linux_epoll_wait(int epfd, struct linux_epoll_event *event)
{

	return (linux_syscall(232, epfd, (long)event, 1, 0, 0, 0));
}

long
linux_fcntl(int fd, int command, long argument)
{

	return (linux_syscall(72, fd, command, argument, 0, 0, 0));
}

long
linux_fork(void)
{

	return (linux_syscall(57, 0, 0, 0, 0, 0, 0));
}

long
linux_open(const char *path, int flags, int mode)
{

	return (linux_syscall(2, (long)path, flags, mode, 0, 0, 0));
}

long
linux_pipe(int pipefd[2])
{

	return (linux_syscall(22, (long)pipefd, 0, 0, 0, 0, 0));
}

long
linux_waitpid(int pid, int *status)
{

	return (linux_syscall(61, pid, (long)status, 0, 0, 0, 0));
}

long
linux_write(int fd, const void *buffer, long length)
{

	return (linux_syscall(1, fd, (long)buffer, length, 0, 0, 0));
}

_Noreturn void
linux_exit(int status)
{

	(void)linux_syscall(231, status, 0, 0, 0, 0, 0);
	for (;;)
		;
}

#elif defined(__aarch64__)
static long
linux_syscall(long number, long arg1, long arg2, long arg3, long arg4,
    long arg5, long arg6)
{
	register long x0 __asm__("x0") = arg1;
	register long x1 __asm__("x1") = arg2;
	register long x2 __asm__("x2") = arg3;
	register long x3 __asm__("x3") = arg4;
	register long x4 __asm__("x4") = arg5;
	register long x5 __asm__("x5") = arg6;
	register long x8 __asm__("x8") = number;

	__asm__ volatile("svc 0" : "+r" (x0) : "r" (x1), "r" (x2),
	    "r" (x3), "r" (x4), "r" (x5), "r" (x8) : "memory", "cc");
	return (x0);
}

long
linux_close(int fd)
{

	return (linux_syscall(57, fd, 0, 0, 0, 0, 0));
}

long
linux_epoll_create1(int flags)
{

	return (linux_syscall(20, flags, 0, 0, 0, 0, 0));
}

long
linux_epoll_ctl(int epfd, int op, int fd, struct linux_epoll_event *event)
{

	return (linux_syscall(21, epfd, op, fd, (long)event, 0, 0));
}

long
linux_epoll_wait(int epfd, struct linux_epoll_event *event)
{

	return (linux_syscall(22, epfd, (long)event, 1, 0, 0, 0));
}

long
linux_fcntl(int fd, int command, long argument)
{

	return (linux_syscall(25, fd, command, argument, 0, 0, 0));
}

long
linux_fork(void)
{

	return (linux_syscall(220, 17, 0, 0, 0, 0, 0));
}

long
linux_open(const char *path, int flags, int mode)
{

	return (linux_syscall(56, -100, (long)path, flags, mode, 0, 0));
}

long
linux_pipe(int pipefd[2])
{

	return (linux_syscall(59, (long)pipefd, 0, 0, 0, 0, 0));
}

long
linux_waitpid(int pid, int *status)
{

	return (linux_syscall(260, pid, (long)status, 0, 0, 0, 0));
}

long
linux_write(int fd, const void *buffer, long length)
{

	return (linux_syscall(64, fd, (long)buffer, length, 0, 0, 0));
}

_Noreturn void
linux_exit(int status)
{

	(void)linux_syscall(94, status, 0, 0, 0, 0, 0);
	for (;;)
		;
}

#else
#error "Unsupported Linux architecture"
#endif
