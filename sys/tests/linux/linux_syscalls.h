/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Vladimir Grebenshchikov <vova@zote.me>
 */

#ifndef _LINUX_TEST_SYSCALLS_H_
#define	_LINUX_TEST_SYSCALLS_H_

#define	LINUX_O_RDWR	2

long linux_close(int fd);
long linux_open(const char *path, int flags, int mode);
long linux_write(int fd, const void *buffer, long length);
_Noreturn void linux_exit(int status);

#endif /* _LINUX_TEST_SYSCALLS_H_ */
