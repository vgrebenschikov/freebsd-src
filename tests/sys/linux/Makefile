PACKAGE=	tests

TESTSDIR=	${TESTSBASE}/sys/linux

.include <src.lua.mk>

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
LINUX_CFLAGS=	--target=${LINUX_TARGET} \
		-I${SRCTOP}/sys -fno-stack-protector -fno-builtin -O2 \
		-Wall -Wextra -Werror
LINUX_LDFLAGS=	-fuse-ld=lld -nostdlib -static -Wl,-e,_start \
		-Wl,--build-id=none -Wl,--gc-sections
LINUX_SYSCALL_MASTER=	${SRCTOP}/sys/${LINUX_SYSARCH}/linux/syscalls.master
LINUX_SYSCALL_STUBS=	linux_syscall_stubs.S
LINUX_SYSCALL_GENDEPS=	${SRCTOP}/sys/tools/syscalls/config.lua \
		${SRCTOP}/sys/tools/syscalls/core/freebsd-syscall.lua \
		${SRCTOP}/sys/tools/syscalls/core/scarg.lua \
		${SRCTOP}/sys/tools/syscalls/core/scret.lua \
		${SRCTOP}/sys/tools/syscalls/core/syscall.lua \
		${SRCTOP}/sys/tools/syscalls/tools/util.lua
LINUX_CRT=	linux_crt0.c linux_syscalls.h ${LINUX_SYSCALL_STUBS}

SCRIPTS+=	${LINUX_HELPERS}
CLEANFILES+=	${LINUX_HELPERS} ${LINUX_SYSCALL_STUBS}

${LINUX_SYSCALL_STUBS}: gen_syscall_stubs.lua ${LINUX_SYSCALL_MASTER} \
	    ${LINUX_SYSCALL_GENDEPS}
	${LUA} ${.CURDIR}/gen_syscall_stubs.lua ${SRCTOP} ${LINUX_SYSARCH} \
	    ${LINUX_SYSCALL_MASTER} > ${.TARGET}

.for _helper in ${LINUX_HELPERS}
SCRIPTSDIR_${_helper}=	${TESTSDIR}

${_helper}: ${_helper}.c ${LINUX_CRT}
	${CC} ${LINUX_CFLAGS} ${LINUX_LDFLAGS} -o ${.TARGET} \
	    ${.ALLSRC:M*.c} ${LINUX_SYSCALL_STUBS}
	brandelf -t Linux ${.TARGET}
.endfor
.endif

.include <bsd.test.mk>
