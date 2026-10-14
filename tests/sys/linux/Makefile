PACKAGE=	tests

TESTSDIR=	${TESTSBASE}/sys/linux

.if ${MACHINE_ARCH} == "amd64"
LINUX_TARGET=	x86_64-linux-gnu
LINUX_SYSARCH=	amd64
.elif ${MACHINE_ARCH} == "aarch64"
LINUX_TARGET=	aarch64-linux-gnu
LINUX_SYSARCH=	arm64
.endif

.if defined(LINUX_TARGET)
ATF_TESTS_C+=	devfs_pty
ATF_TESTS_C+=	epoll_fork

LIBADD.devfs_pty=	util

LINUX_HELPERS=	devfs_pty_linux epoll_fork_linux
LINUX_SYSCALL_H=	${SRCTOP}/sys/${LINUX_SYSARCH}/linux/linux_syscall.h
LINUX_CFLAGS=	--target=${LINUX_TARGET} \
		-I${LINUX_SYSCALL_H:H} -fno-stack-protector \
		-fno-builtin -O2 -Wall -Wextra -Werror
LINUX_LDFLAGS=	-fuse-ld=lld -nostdlib -static -Wl,-e,_start \
		-Wl,--build-id=none
LINUX_CRT=	linux_crt0.c linux_syscalls.c linux_syscalls.h \
		${LINUX_SYSCALL_H}

SCRIPTS+=	${LINUX_HELPERS}
CLEANFILES+=	${LINUX_HELPERS}

.for _helper in ${LINUX_HELPERS}
SCRIPTSDIR_${_helper}=	${TESTSDIR}

${_helper}: ${_helper}.c ${LINUX_CRT}
	${CC} ${LINUX_CFLAGS} ${LINUX_LDFLAGS} -o ${.TARGET} \
	    ${.ALLSRC:M*.c}
	brandelf -t Linux ${.TARGET}
.endfor
.endif

.include <bsd.test.mk>
