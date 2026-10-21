/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Vladimir Grebenshchikov <vova@zote.me>
 */

#include "linux_syscalls.h"

#define	LINUX_AF_INET		2
#define	LINUX_SOCK_DGRAM	2
#define	LINUX_SOCK_NONBLOCK	000004000
#define	LINUX_POLLIN		0x0001

struct linux_sockaddr_in {
	unsigned short sin_family;
	unsigned short sin_port;
	unsigned int sin_addr;
	unsigned char sin_zero[8];
};

struct linux_iovec {
	void *iov_base;
	linux_size_t iov_len;
};

struct linux_msghdr {
	void *msg_name;
	unsigned int msg_namelen;
	struct linux_iovec *msg_iov;
	linux_size_t msg_iovlen;
	void *msg_control;
	linux_size_t msg_controllen;
	unsigned int msg_flags;
};

struct linux_mmsghdr {
	struct linux_msghdr msg_hdr;
	unsigned int msg_len;
};

struct linux_pollfd {
	int fd;
	short events;
	short revents;
};

struct linux_timespec {
	long tv_sec;
	long tv_nsec;
};

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
		written = write(1, string, length);
		if (written == -1 && errno == LINUX_EINTR)
			continue;
		if (written <= 0)
			return;
		string += written;
		length -= written;
	}
}

static int
setup(long result, const char *description)
{

	if (result >= 0)
		return ((int)result);
	putstr("SETUP FAILED: ");
	putstr(description);
	putstr("\n");
	return (-1);
}

int
main(void)
{
	struct linux_sockaddr_in address = { 0 };
	struct linux_mmsghdr messages[2] = { 0 };
	struct linux_pollfd pollfd;
	struct linux_timespec timeout;
	struct linux_iovec iov[2];
	unsigned int address_length;
	char payload, received[2] = { 0 };
	int fd, result;

	fd = setup(socket(LINUX_AF_INET,
	    LINUX_SOCK_DGRAM | LINUX_SOCK_NONBLOCK, 0), "socket");
	if (fd < 0)
		return (1);
	address.sin_family = LINUX_AF_INET;
	address.sin_addr = __builtin_bswap32(0x7f000001U);
	if (setup(bind(fd, &address, sizeof(address)), "bind") < 0)
		return (1);
	address_length = sizeof(address);
	if (setup(getsockname(fd, &address, &address_length), "getsockname") < 0)
		return (1);

	payload = 'x';
	if (setup(sendto(fd, &payload, sizeof(payload), 0, &address,
	    sizeof(address)), "sendto") < 0)
		return (1);
	pollfd.fd = fd;
	pollfd.events = LINUX_POLLIN;
	pollfd.revents = 0;
	timeout.tv_sec = 1;
	timeout.tv_nsec = 0;
	if (setup(ppoll(&pollfd, 1, &timeout, 0, 0), "ppoll") != 1) {
		putstr("SETUP FAILED: socket did not become readable\n");
		return (1);
	}

	for (unsigned int i = 0; i < 2; i++) {
		iov[i].iov_base = &received[i];
		iov[i].iov_len = sizeof(received[i]);
		messages[i].msg_hdr.msg_iov = &iov[i];
		messages[i].msg_hdr.msg_iovlen = 1;
	}
	result = recvmmsg(fd, messages, 2, 0, 0);
	if (result != 1) {
		putstr("FAIL: recvmmsg did not return one datagram\n");
		return (1);
	}
	if (messages[0].msg_len != sizeof(payload)) {
		putstr("FAIL: incorrect datagram length\n");
		return (1);
	}
	if (received[0] != payload) {
		putstr("FAIL: incorrect datagram payload\n");
		return (1);
	}

	(void)close(fd);
	return (0);
}
