/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Vladimir Grebenshchikov <vova@zote.me>
 */

#ifndef _LINUX_TEST_SYSCALLS_H_
#define	_LINUX_TEST_SYSCALLS_H_

#define	LINUX_O_RDWR	2
#define	LINUX_F_GETFD	1
#define	LINUX_EPOLLIN	1
#define	LINUX_EPOLL_CLOEXEC	02000000
#define	LINUX_EPOLL_CTL_ADD	1
#define	LINUX_EPOLL_CTL_MOD	3

struct linux_epoll_event {
	unsigned int events;
#if defined(__aarch64__)
	unsigned int padding;
#endif
	unsigned long data;
}
#if defined(__x86_64__)
__attribute__((packed))
#endif
;

#if defined(__x86_64__)
_Static_assert(sizeof(struct linux_epoll_event) == 12,
    "Linux x86-64 epoll ABI");
#elif defined(__aarch64__)
_Static_assert(sizeof(struct linux_epoll_event) == 16,
    "Linux AArch64 epoll ABI");
#endif

long linux_close(int fd);
long linux_epoll_create1(int flags);
long linux_epoll_ctl(int epfd, int op, int fd,
    struct linux_epoll_event *event);
long linux_epoll_wait(int epfd, struct linux_epoll_event *event);
long linux_fcntl(int fd, int command, long argument);
long linux_fork(void);
long linux_open(const char *path, int flags, int mode);
long linux_pipe(int pipefd[2]);
long linux_waitpid(int pid, int *status);
long linux_write(int fd, const void *buffer, long length);
_Noreturn void linux_exit(int status);

#endif /* _LINUX_TEST_SYSCALLS_H_ */
