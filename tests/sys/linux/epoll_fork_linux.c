/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Vladimir Grebenshchikov <vova@zote.me>
 */

#include "linux_syscalls.h"

static int failed;

static void
putstr(const char *string)
{
	const char *p;
	linux_size_t length;
	linux_ssize_t written;

	for (p = string; *p != '\0'; p++)
		;
	length = p - string;
	while (length > 0) {
		written = linux_write(1, string, length);
		if (written == -LINUX_EINTR)
			continue;
		if (written <= 0)
			return;
		string += written;
		length -= written;
	}
}

static void
check(const char *description, long actual, long expected)
{

	if (actual == expected)
		return;
	putstr("FAIL: ");
	putstr(description);
	putstr("\n");
	failed++;
}

static int
setup(long result, const char *description)
{

	if (result >= 0)
		return ((int)result);
	putstr("SETUP FAILED: ");
	putstr(description);
	putstr("\n");
	failed++;
	return (-1);
}

static void
test_flags(int flags)
{
	struct linux_epoll_event event = { 0 }, output = { 0 };
	int epfd, extra[2], pipefd[2], status = 0;
	linux_pid_t child, result;

	event.events = LINUX_EPOLLIN;
	event.data = 0x1234;
	epfd = setup(linux_epoll_create1(flags), "epoll_create1");
	if (epfd < 0)
		return;
	if (setup(linux_pipe(pipefd), "pipe") < 0)
		return;
	if (setup(linux_epoll_ctl(epfd, LINUX_EPOLL_CTL_ADD, pipefd[0],
	    &event), "epoll_ctl(ADD)") < 0)
		return;
	if (setup(linux_write(pipefd[1], "x", 1), "write") < 0)
		return;

	child = linux_fork();
	if (child < 0) {
		(void)setup(child, "fork");
		return;
	}
	if (child == 0) {
		failed = 0;
		check("epoll F_GETFD", linux_fcntl(epfd, LINUX_F_GETFD, 0),
		    flags != 0 ? 1 : 0);
		check("pipe F_GETFD", linux_fcntl(pipefd[0], LINUX_F_GETFD, 0),
		    0);
		check("inherited readiness", linux_epoll_wait(epfd, &output), 1);
		check("inherited event data", output.data, event.data);
		if (setup(linux_pipe(extra), "child pipe") >= 0)
			check("epoll_ctl after fd allocation", linux_epoll_ctl(epfd,
			    LINUX_EPOLL_CTL_MOD, pipefd[0], &event), 0);
		linux_exit(failed != 0 ? 1 : 0);
	}

	do {
		result = linux_waitpid(child, &status);
	} while (result == -LINUX_EINTR);
	check("waitpid", result, child);
	check("child status", status, 0);
	(void)linux_close(epfd);
	(void)linux_close(pipefd[0]);
	(void)linux_close(pipefd[1]);
}

int
main(void)
{

	test_flags(0);
	test_flags(LINUX_EPOLL_CLOEXEC);
	return (failed != 0 ? 1 : 0);
}
