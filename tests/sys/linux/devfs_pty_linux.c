/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Vladimir Grebenshchikov <vova@zote.me>
 */

#include "linux_syscalls.h"

int
main(void)
{
	long fd;

	(void)linux_close_range(0, 2, 0);

	fd = linux_open("/dev/tty", LINUX_O_RDWR, 0);
	if (fd < 0) {
		(void)linux_write(3, "fail\n", 5);
		return (1);
	}
	(void)linux_close(fd);
	(void)linux_write(3, "ok\n", 3);
	return (0);
}
