/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Vladimir Grebenshchikov <vova@zote.me>
 */

#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <libutil.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

static void
linux_helper(const atf_tc_t *tc, char *path, size_t pathlen)
{
	const char *srcdir;
	size_t len;

	len = 0;
	if (sysctlbyname("compat.linux.emul_path", NULL, &len, NULL, 0) != 0)
		atf_tc_skip("Linux ABI is not available: %s", strerror(errno));
	srcdir = atf_tc_get_config_var(tc, "srcdir");
	if (snprintf(path, pathlen, "%s/devfs_pty_linux", srcdir) >=
	    (int)pathlen)
		atf_tc_fail("test helper path is too long");
	if (access(path, X_OK) != 0)
		atf_tc_fail("Linux test helper is not executable (%s): %s",
		    path, strerror(errno));
}

ATF_TC(ctty_last_close);
ATF_TC_HEAD(ctty_last_close, tc)
{

	atf_tc_set_md_var(tc, "descr", "Keep a Linux controlling terminal "
	    "across the last slave close");
	atf_tc_set_md_var(tc, "require.kmods", "linux64");
}
ATF_TC_BODY(ctty_last_close, tc)
{
	/*
	 * Set up the controlling terminal natively, then let a Linux process
	 * perform the last closes.  Linux expects the session's reference to
	 * survive those closes, so reopening /dev/tty must succeed.
	 */
	char buf[16], helper[PATH_MAX];
	int master, pipefd[2], slave, status;
	ssize_t nread;
	pid_t child;

	linux_helper(tc, helper, sizeof(helper));
	ATF_REQUIRE_MSG(openpty(&master, &slave, NULL, NULL, NULL) == 0,
	    "openpty failed: %s", strerror(errno));
	ATF_REQUIRE_MSG(pipe(pipefd) == 0, "pipe failed: %s", strerror(errno));

	child = fork();
	ATF_REQUIRE_MSG(child >= 0, "fork failed: %s", strerror(errno));
	if (child == 0) {
		(void)close(master);
		(void)close(pipefd[0]);
		if (setsid() < 0)
			_exit(10);
		if (ioctl(slave, TIOCSCTTY, 0) < 0)
			_exit(11);
		if (dup2(slave, STDIN_FILENO) < 0 ||
		    dup2(slave, STDOUT_FILENO) < 0 ||
		    dup2(slave, STDERR_FILENO) < 0)
			_exit(12);
		if (slave > STDERR_FILENO)
			(void)close(slave);
		if (pipefd[1] != 3) {
			if (dup2(pipefd[1], 3) < 0)
				_exit(13);
			(void)close(pipefd[1]);
		}
		execl(helper, "devfs_pty_linux", (char *)NULL);
		_exit(14);
	}

	(void)close(slave);
	(void)close(pipefd[1]);
	nread = read(pipefd[0], buf, sizeof(buf) - 1);
	ATF_REQUIRE_MSG(nread >= 0, "read failed: %s", strerror(errno));
	buf[nread] = '\0';
	ATF_REQUIRE_MSG(waitpid(child, &status, 0) == child,
	    "waitpid failed: %s", strerror(errno));
	(void)close(pipefd[0]);
	(void)close(master);

	ATF_REQUIRE_MSG(WIFEXITED(status), "Linux helper died from signal %d",
	    WTERMSIG(status));
	ATF_CHECK_MSG(strcmp(buf, "ok\n") == 0,
	    "opening /dev/tty after the last slave close returned: %s", buf);
	ATF_CHECK_MSG(WEXITSTATUS(status) == 0,
	    "Linux helper exited with status %d", WEXITSTATUS(status));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, ctty_last_close);
	return (atf_no_error());
}
