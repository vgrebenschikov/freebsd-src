PACKAGE=	tests

TESTSDIR=	${TESTSBASE}/sys/linux

.if ${MACHINE_ARCH} == "amd64"
LINUX_TARGET=	x86_64-linux-gnu
.elif ${MACHINE_ARCH} == "aarch64"
LINUX_TARGET=	aarch64-linux-gnu
.endif

.if defined(LINUX_TARGET)
ATF_TESTS_C+=	devfs_pty
ATF_TESTS_C+=	epoll_fork

LIBADD.devfs_pty=	util

SCRIPTS+=	devfs_pty_linux
SCRIPTSDIR_devfs_pty_linux=	${TESTSDIR}
SCRIPTS+=	epoll_fork_linux
SCRIPTSDIR_epoll_fork_linux=	${TESTSDIR}
CLEANFILES+=	devfs_pty_linux epoll_fork_linux

devfs_pty_linux: devfs_pty_linux.c linux_crt0.c linux_crt0.h \
	linux_syscalls.c linux_syscalls.h
	${CC} --target=${LINUX_TARGET} -fuse-ld=lld -nostdlib -static \
	    -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror \
	    -Wl,-e,_start -Wl,--build-id=none -o ${.TARGET} ${.ALLSRC:M*.c}

epoll_fork_linux: epoll_fork_linux.c linux_crt0.c linux_crt0.h \
	linux_syscalls.c linux_syscalls.h
	${CC} --target=${LINUX_TARGET} -fuse-ld=lld -nostdlib -static \
	    -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror \
	    -Wl,-e,_start -Wl,--build-id=none -o ${.TARGET} ${.ALLSRC:M*.c}
.endif

.include <bsd.test.mk>
