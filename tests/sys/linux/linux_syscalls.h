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
#define	LINUX_EINTR	4

typedef int linux_pid_t;
typedef __SIZE_TYPE__ linux_size_t;
typedef __PTRDIFF_TYPE__ linux_ssize_t;

struct linux_epoll_event {
	unsigned int events;
#if defined(__aarch64__)
	unsigned int padding;
#endif
	unsigned long data;
}
#if defined(__amd64__)
__attribute__((packed))
#endif
;

#if defined(__amd64__)
_Static_assert(sizeof(struct linux_epoll_event) == 12,
    "Linux x86-64 epoll ABI");
#elif defined(__aarch64__)
_Static_assert(sizeof(struct linux_epoll_event) == 16,
    "Linux AArch64 epoll ABI");
#endif

int linux_close(int fd);
int linux_close_range(unsigned int first, unsigned int last,
    unsigned int flags);
int linux_epoll_create1(int flags);
int linux_epoll_ctl(int epfd, int op, int fd,
    struct linux_epoll_event *event);
int linux_epoll_wait(int epfd, struct linux_epoll_event *event);
int linux_fcntl(int fd, int command, long argument);
linux_pid_t linux_fork(void);
int linux_open(const char *path, int flags, int mode);
int linux_pipe(int pipefd[2]);
linux_pid_t linux_waitpid(linux_pid_t pid, int *status);
linux_ssize_t linux_write(int fd, const void *buffer, linux_size_t length);
_Noreturn void linux_exit(int status);

#endif /* _LINUX_TEST_SYSCALLS_H_ */
