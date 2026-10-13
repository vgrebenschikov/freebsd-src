/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Vladimir Grebenshchikov <vova@zote.me>
 */

#include <sys/sysctl.h>
#include <sys/wait.h>

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

ATF_TC(epoll_descriptor);
ATF_TC_HEAD(epoll_descriptor, tc)
{

	atf_tc_set_md_var(tc, "descr", "Preserve Linux epoll descriptors and "
	    "registrations across fork");
	atf_tc_set_md_var(tc, "require.kmods", "linux64");
}
ATF_TC_BODY(epoll_descriptor, tc)
{
	char helper[PATH_MAX];
	const char *srcdir;
	size_t len;
	int status;
	pid_t child;

	len = 0;
	if (sysctlbyname("compat.linux.emul_path", NULL, &len, NULL, 0) != 0)
		atf_tc_skip("Linux ABI is not available: %s", strerror(errno));
	srcdir = atf_tc_get_config_var(tc, "srcdir");
	ATF_REQUIRE_MSG(snprintf(helper, sizeof(helper), "%s/epoll_fork_linux",
	    srcdir) < (int)sizeof(helper), "test helper path is too long");
	ATF_REQUIRE_MSG(access(helper, X_OK) == 0,
	    "Linux test helper is not executable (%s): %s", helper,
	    strerror(errno));

	child = fork();
	ATF_REQUIRE_MSG(child >= 0, "fork failed: %s", strerror(errno));
	if (child == 0) {
		execl(helper, "epoll_fork_linux", (char *)NULL);
		_exit(127);
	}
	ATF_REQUIRE_MSG(waitpid(child, &status, 0) == child,
	    "waitpid failed: %s", strerror(errno));
	ATF_REQUIRE_MSG(WIFEXITED(status), "Linux helper died from signal %d",
	    WTERMSIG(status));
	ATF_CHECK_MSG(WEXITSTATUS(status) == 0,
	    "Linux helper exited with status %d", WEXITSTATUS(status));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, epoll_descriptor);
	return (atf_no_error());
}
