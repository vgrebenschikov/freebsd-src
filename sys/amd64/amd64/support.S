/*-
 * Copyright (c) 2018-2019 The FreeBSD Foundation
 * Copyright (c) 2003 Peter Wemm.
 * Copyright (c) 1993 The Regents of the University of California.
 * All rights reserved.
 *
 * Portions of this software were developed by
 * Konstantin Belousov <kib@FreeBSD.org> under sponsorship from
 * the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "opt_ddb.h"

#include <machine/asmacros.h>
#include <machine/specialreg.h>
#include <machine/pmap.h>

#include "assym.inc"

	.text

/* Address: %rdi */
ENTRY(pagezero_std)
	PUSH_FRAME_POINTER
	movl	$PAGE_SIZE/8,%ecx
	xorl	%eax,%eax
	rep
	stosq
	POP_FRAME_POINTER
	ret
END(pagezero_std)

ENTRY(pagezero_erms)
	PUSH_FRAME_POINTER
	movl	$PAGE_SIZE,%ecx
	xorl	%eax,%eax
	rep
	stosb
	POP_FRAME_POINTER
	ret
END(pagezero_erms)

/*
 * pagecopy(%rdi=from, %rsi=to)
 */
ENTRY(pagecopy)
	PUSH_FRAME_POINTER
	movl	$PAGE_SIZE/8,%ecx
	movq	%rdi,%r9
	movq	%rsi,%rdi
	movq	%r9,%rsi
	rep
	movsq
	POP_FRAME_POINTER
	ret
END(pagecopy)

/*
 * memcmp(b1, b2, len)
 *	   rdi,rsi,rdx
 */
ENTRY(memcmp)
	PUSH_FRAME_POINTER

	xorl	%eax,%eax
10:
	cmpq	$16,%rdx
	ja	101632f

	cmpb	$8,%dl
	jg	100816f

	cmpb	$4,%dl
	jg	100408f

	cmpb	$2,%dl
	jge	100204f

	cmpb	$1,%dl
	jl	100000f
	movzbl	(%rdi),%eax
	movzbl	(%rsi),%r8d
	subl	%r8d,%eax
100000:
	POP_FRAME_POINTER
	ret

	ALIGN_TEXT
100816:
	movq	(%rdi),%r8
	movq	(%rsi),%r9
	cmpq	%r8,%r9
	jne	80f
	movq	-8(%rdi,%rdx),%r8
	movq	-8(%rsi,%rdx),%r9
	cmpq	%r8,%r9
	jne	10081608f
	POP_FRAME_POINTER
	ret
	ALIGN_TEXT
100408:
	movl	(%rdi),%r8d
	movl	(%rsi),%r9d
	cmpl	%r8d,%r9d
	jne	80f
	movl	-4(%rdi,%rdx),%r8d
	movl	-4(%rsi,%rdx),%r9d
	cmpl	%r8d,%r9d
	jne	10040804f
	POP_FRAME_POINTER
	ret
	ALIGN_TEXT
100204:
	movzwl	(%rdi),%r8d
	movzwl	(%rsi),%r9d
	cmpl	%r8d,%r9d
	jne	1f
	movzwl	-2(%rdi,%rdx),%r8d
	movzwl	-2(%rsi,%rdx),%r9d
	cmpl	%r8d,%r9d
	jne	1f
	POP_FRAME_POINTER
	ret
	ALIGN_TEXT
101632:
	cmpq	$32,%rdx
	ja	103200f
	movq	(%rdi),%r8
	movq	(%rsi),%r9
	cmpq	%r8,%r9
	jne	80f
	movq	8(%rdi),%r8
	movq	8(%rsi),%r9
	cmpq	%r8,%r9
	jne	10163208f
	movq	-16(%rdi,%rdx),%r8
	movq	-16(%rsi,%rdx),%r9
	cmpq	%r8,%r9
	jne	10163216f
	movq	-8(%rdi,%rdx),%r8
	movq	-8(%rsi,%rdx),%r9
	cmpq	%r8,%r9
	jne	10163224f
	POP_FRAME_POINTER
	ret
	ALIGN_TEXT
103200:
	movq	(%rdi),%r8
	movq	8(%rdi),%r9
	subq	(%rsi),%r8
	subq	8(%rsi),%r9
	orq	%r8,%r9
	jnz	10320000f

	movq    16(%rdi),%r8
	movq    24(%rdi),%r9
	subq    16(%rsi),%r8
	subq    24(%rsi),%r9
	orq	%r8,%r9
	jnz     10320016f

	leaq	32(%rdi),%rdi
	leaq	32(%rsi),%rsi
	subq	$32,%rdx
	cmpq	$32,%rdx
	jae	103200b
	cmpb	$0,%dl
	jne	10b
	POP_FRAME_POINTER
	ret

/*
 * Mismatch was found.
 *
 * Before we compute it we narrow down the range (16 -> 8 -> 4 bytes).
 */
	ALIGN_TEXT
10320016:
	leaq	16(%rdi),%rdi
	leaq	16(%rsi),%rsi
10320000:
	movq	(%rdi),%r8
	movq	(%rsi),%r9
	cmpq	%r8,%r9
	jne	80f
	leaq	8(%rdi),%rdi
	leaq	8(%rsi),%rsi
	jmp	80f
	ALIGN_TEXT
10081608:
10163224:
	leaq	-8(%rdi,%rdx),%rdi
	leaq	-8(%rsi,%rdx),%rsi
	jmp	80f
	ALIGN_TEXT
10163216:
	leaq	-16(%rdi,%rdx),%rdi
	leaq	-16(%rsi,%rdx),%rsi
	jmp	80f
	ALIGN_TEXT
10163208:
	leaq	8(%rdi),%rdi
	leaq	8(%rsi),%rsi
	jmp	80f
	ALIGN_TEXT
10040804:
	leaq	-4(%rdi,%rdx),%rdi
	leaq	-4(%rsi,%rdx),%rsi
	jmp	1f

	ALIGN_TEXT
80:
	movl	(%rdi),%r8d
	movl	(%rsi),%r9d
	cmpl	%r8d,%r9d
	jne	1f
	leaq	4(%rdi),%rdi
	leaq	4(%rsi),%rsi

/*
 * We have up to 4 bytes to inspect.
 */
1:
	movzbl	(%rdi),%eax
	movzbl	(%rsi),%r8d
	cmpb	%r8b,%al
	jne	2f

	movzbl	1(%rdi),%eax
	movzbl	1(%rsi),%r8d
	cmpb	%r8b,%al
	jne	2f

	movzbl	2(%rdi),%eax
	movzbl	2(%rsi),%r8d
	cmpb	%r8b,%al
	jne	2f

	movzbl	3(%rdi),%eax
	movzbl	3(%rsi),%r8d
2:
	subl	%r8d,%eax
	POP_FRAME_POINTER
	ret
END(memcmp)

/*
 * memmove(dst, src, cnt)
 *         rdi, rsi, rdx
 */

/*
 * Register state at entry is supposed to be as follows:
 * rdi - destination
 * rsi - source
 * rdx - count
 *
 * The macro possibly clobbers the above and: rcx, r8, r9, r10
 * It does not clobber rax nor r11.
 */
.macro MEMMOVE erms overlap begin end
	\begin

	/*
	 * For sizes 0..32 all data is read before it is written, so there
	 * is no correctness issue with direction of copying.
	 */
	cmpq	$32,%rcx
	jbe	101632f

.if \overlap == 1
	movq	%rdi,%r8
	subq	%rsi,%r8
	cmpq	%rcx,%r8	/* overlapping && src < dst? */
	jb	2f
.endif

	cmpq	$256,%rcx
	ja	1256f

	ALIGN_TEXT
103200:
	movq	(%rsi),%rdx
	movq	%rdx,(%rdi)
	movq	8(%rsi),%rdx
	movq	%rdx,8(%rdi)
	movq	16(%rsi),%rdx
	movq	%rdx,16(%rdi)
	movq	24(%rsi),%rdx
	movq	%rdx,24(%rdi)
	leaq	32(%rsi),%rsi
	leaq	32(%rdi),%rdi
	subq	$32,%rcx
	cmpq	$32,%rcx
	jae	103200b
	cmpb	$0,%cl
	jne	101632f
	\end
	ret
	ALIGN_TEXT
101632:
	cmpb	$16,%cl
	jl	100816f
	movq	(%rsi),%rdx
	movq	8(%rsi),%r8
	movq	-16(%rsi,%rcx),%r9
	movq	-8(%rsi,%rcx),%r10
	movq	%rdx,(%rdi)
	movq	%r8,8(%rdi)
	movq	%r9,-16(%rdi,%rcx)
	movq	%r10,-8(%rdi,%rcx)
	\end
	ret
	ALIGN_TEXT
100816:
	cmpb	$8,%cl
	jl	100408f
	movq	(%rsi),%rdx
	movq	-8(%rsi,%rcx),%r8
	movq	%rdx,(%rdi)
	movq	%r8,-8(%rdi,%rcx,)
	\end
	ret
	ALIGN_TEXT
100408:
	cmpb	$4,%cl
	jl	100204f
	movl	(%rsi),%edx
	movl	-4(%rsi,%rcx),%r8d
	movl	%edx,(%rdi)
	movl	%r8d,-4(%rdi,%rcx)
	\end
	ret
	ALIGN_TEXT
100204:
	cmpb	$2,%cl
	jl	100001f
	movzwl	(%rsi),%edx
	movzwl	-2(%rsi,%rcx),%r8d
	movw	%dx,(%rdi)
	movw	%r8w,-2(%rdi,%rcx)
	\end
	ret
	ALIGN_TEXT
100001:
	cmpb	$1,%cl
	jl	100000f
	movb	(%rsi),%dl
	movb	%dl,(%rdi)
100000:
	\end
	ret

	ALIGN_TEXT
1256:
	testb	$15,%dil
	jnz	100f
.if \erms == 1
	rep
	movsb
.else
	shrq	$3,%rcx                         /* copy by 64-bit words */
	rep
	movsq
	movq	%rdx,%rcx
	andl	$7,%ecx                         /* any bytes left? */
	jne	100408b
.endif
	\end
	ret
100:
	movq	(%rsi),%r8
	movq	8(%rsi),%r9
	movq	%rdi,%r10
	movq	%rdi,%rcx
	andq	$15,%rcx
	leaq	-16(%rdx,%rcx),%rdx
	neg	%rcx
	leaq	16(%rdi,%rcx),%rdi
	leaq	16(%rsi,%rcx),%rsi
	movq	%rdx,%rcx
.if \erms == 1
	rep
	movsb
	movq	%r8,(%r10)
	movq	%r9,8(%r10)
.else
	shrq	$3,%rcx                         /* copy by 64-bit words */
	rep
	movsq
	movq	%r8,(%r10)
	movq	%r9,8(%r10)
	movq	%rdx,%rcx
	andl	$7,%ecx                         /* any bytes left? */
	jne	100408b
.endif
	\end
	ret

.if \overlap == 1
	/*
	 * Copy backwards.
	 */
        ALIGN_TEXT
2:
	cmpq	$256,%rcx
	ja	2256f

	leaq	-8(%rdi,%rcx),%rdi
	leaq	-8(%rsi,%rcx),%rsi

	cmpq	$32,%rcx
	jb	2016f

	ALIGN_TEXT
2032:
	movq	(%rsi),%rdx
	movq	%rdx,(%rdi)
	movq	-8(%rsi),%rdx
	movq	%rdx,-8(%rdi)
	movq	-16(%rsi),%rdx
	movq	%rdx,-16(%rdi)
	movq	-24(%rsi),%rdx
	movq	%rdx,-24(%rdi)
	leaq	-32(%rsi),%rsi
	leaq	-32(%rdi),%rdi
	subq	$32,%rcx
	cmpq	$32,%rcx
	jae	2032b
	cmpb	$0,%cl
	jne	2016f
	\end
	ret
	ALIGN_TEXT
2016:
	cmpb	$16,%cl
	jl	2008f
	movq	(%rsi),%rdx
	movq	%rdx,(%rdi)
	movq	-8(%rsi),%rdx
	movq	%rdx,-8(%rdi)
	subb	$16,%cl
	jz	2000f
	leaq	-16(%rsi),%rsi
	leaq	-16(%rdi),%rdi
2008:
	cmpb	$8,%cl
	jl	2004f
	movq	(%rsi),%rdx
	movq	%rdx,(%rdi)
	subb	$8,%cl
	jz	2000f
	leaq	-8(%rsi),%rsi
	leaq	-8(%rdi),%rdi
2004:
	cmpb	$4,%cl
	jl	2002f
	movl	4(%rsi),%edx
	movl	%edx,4(%rdi)
	subb	$4,%cl
	jz	2000f
	leaq	-4(%rsi),%rsi
	leaq	-4(%rdi),%rdi
2002:
	cmpb	$2,%cl
	jl	2001f
	movw	6(%rsi),%dx
	movw	%dx,6(%rdi)
	subb	$2,%cl
	jz	2000f
	leaq	-2(%rsi),%rsi
	leaq	-2(%rdi),%rdi
2001:
	cmpb	$1,%cl
	jl	2000f
	movb	7(%rsi),%dl
	movb	%dl,7(%rdi)
2000:
	\end
	ret
	ALIGN_TEXT
2256:
	std
	leaq	-8(%rdi,%rcx),%rdi
	leaq	-8(%rsi,%rcx),%rsi
	shrq	$3,%rcx
	rep
	movsq
	cld
	movq	%rdx,%rcx
	andb	$7,%cl
	jne	2004b
	\end
	ret
.endif
.endm

.macro MEMMOVE_BEGIN
	PUSH_FRAME_POINTER
	movq	%rdi,%rax
	movq	%rdx,%rcx
.endm

.macro MEMMOVE_END
	POP_FRAME_POINTER
.endm

ENTRY(memmove_std)
	MEMMOVE erms=0 overlap=1 begin=MEMMOVE_BEGIN end=MEMMOVE_END
END(memmove_std)

ENTRY(memmove_erms)
	MEMMOVE erms=1 overlap=1 begin=MEMMOVE_BEGIN end=MEMMOVE_END
END(memmove_erms)

/*
 * memcpy(dst, src, len)
 *        rdi, rsi, rdx
 *
 * Note: memcpy does not support overlapping copies
 */
ENTRY(memcpy_std)
	MEMMOVE erms=0 overlap=0 begin=MEMMOVE_BEGIN end=MEMMOVE_END
END(memcpy_std)

ENTRY(memcpy_erms)
	MEMMOVE erms=1 overlap=0 begin=MEMMOVE_BEGIN end=MEMMOVE_END
END(memcpy_erms)

/*
 * memset(dst, c,   len)
 *        rdi, rsi, rdx
 */
.macro MEMSET erms
	PUSH_FRAME_POINTER
	movq	%rdi,%rax
	movq	%rdx,%rcx
	movzbq	%sil,%r8
	movabs	$0x0101010101010101,%r10
	imulq	%r8,%r10

	cmpq	$32,%rcx
	jbe	101632f

	cmpq	$256,%rcx
	ja	1256f

	ALIGN_TEXT
103200:
	movq	%r10,(%rdi)
	movq	%r10,8(%rdi)
	movq	%r10,16(%rdi)
	movq	%r10,24(%rdi)
	leaq	32(%rdi),%rdi
	subq	$32,%rcx
	cmpq	$32,%rcx
	ja	103200b
	cmpb	$16,%cl
	ja	201632f
	movq	%r10,-16(%rdi,%rcx)
	movq	%r10,-8(%rdi,%rcx)
	POP_FRAME_POINTER
	ret
	ALIGN_TEXT
101632:
	cmpb	$16,%cl
	jl	100816f
201632:
	movq	%r10,(%rdi)
	movq	%r10,8(%rdi)
	movq	%r10,-16(%rdi,%rcx)
	movq	%r10,-8(%rdi,%rcx)
	POP_FRAME_POINTER
	ret
	ALIGN_TEXT
100816:
	cmpb	$8,%cl
	jl	100408f
	movq	%r10,(%rdi)
	movq	%r10,-8(%rdi,%rcx)
	POP_FRAME_POINTER
	ret
	ALIGN_TEXT
100408:
	cmpb	$4,%cl
	jl	100204f
	movl	%r10d,(%rdi)
	movl	%r10d,-4(%rdi,%rcx)
	POP_FRAME_POINTER
	ret
	ALIGN_TEXT
100204:
	cmpb	$2,%cl
	jl	100001f
	movw	%r10w,(%rdi)
	movw	%r10w,-2(%rdi,%rcx)
	POP_FRAME_POINTER
	ret
	ALIGN_TEXT
100001:
	cmpb	$0,%cl
	je	100000f
	movb	%r10b,(%rdi)
100000:
	POP_FRAME_POINTER
	ret
	ALIGN_TEXT
1256:
	movq	%rdi,%r9
	movq	%r10,%rax
	testl	$15,%edi
	jnz	3f
1:
.if \erms == 1
	rep
	stosb
	movq	%r9,%rax
.else
	movq	%rcx,%rdx
	shrq	$3,%rcx
	rep
	stosq
	movq	%r9,%rax
	andl	$7,%edx
	jnz	2f
	POP_FRAME_POINTER
	ret
2:
	movq	%r10,-8(%rdi,%rdx)
.endif
	POP_FRAME_POINTER
	ret
	ALIGN_TEXT
3:
	movq	%r10,(%rdi)
	movq	%r10,8(%rdi)
	movq	%rdi,%r8
	andq	$15,%r8
	leaq	-16(%rcx,%r8),%rcx
	neg	%r8
	leaq	16(%rdi,%r8),%rdi
	jmp	1b
.endm

ENTRY(memset_std)
	MEMSET erms=0
END(memset_std)

ENTRY(memset_erms)
	MEMSET erms=1
END(memset_erms)

/* fillw(pat, base, cnt) */
/*       %rdi,%rsi, %rdx */
ENTRY(fillw)
	PUSH_FRAME_POINTER
	movq	%rdi,%rax
	movq	%rsi,%rdi
	movq	%rdx,%rcx
	rep
	stosw
	POP_FRAME_POINTER
	ret
END(fillw)

/*
 * strlen(string)
 *	  %rdi
 *
 * Uses the ((x - 0x01....01) & ~x & 0x80....80) trick.
 *
 * 0x01....01 is replaced with 0x0 - 0x01....01 so that it can be added
 * with leaq.
 *
 * For a description see either:
 * - "Hacker's Delight" by Henry S. Warren, Jr.
 * - "Optimizing subroutines in assembly language: An optimization guide for x86 platforms"
 *   by Agner Fog
 *
 * The latter contains a 32-bit variant of the same algorithm coded in assembly for i386.
 */
ENTRY(strlen)
	PUSH_FRAME_POINTER
	movabsq	$0xfefefefefefefeff,%r8
	movabsq	$0x8080808080808080,%r9

	movq	%rdi,%r10
	movq	%rdi,%rcx
	testb	$7,%dil
	jz	2f

	/*
	 * Handle misaligned reads: align to 8 and fill
	 * the spurious bytes.
	 */
	andq	$~7,%rdi
	movq	(%rdi),%r11
	shlq	$3,%rcx
	movq	$-1,%rdx
	shlq	%cl,%rdx
	notq	%rdx
	orq	%rdx,%r11

	leaq	(%r11,%r8),%rcx
	notq	%r11
	andq	%r11,%rcx
	andq	%r9,%rcx
	jnz	3f

	/*
	 * Main loop.
	 */
	ALIGN_TEXT
1:
	leaq	8(%rdi),%rdi
2:
	movq	(%rdi),%r11
	leaq	(%r11,%r8),%rcx
	notq	%r11
	andq	%r11,%rcx
	andq	%r9,%rcx
	jz	1b
3:
	bsfq	%rcx,%rcx
	shrq	$3,%rcx
	leaq	(%rcx,%rdi),%rax
	subq	%r10,%rax
	POP_FRAME_POINTER
	ret
END(strlen)

/*****************************************************************************/
/* copyout and fubyte family                                                 */
/*****************************************************************************/
/*
 * Access user memory from inside the kernel. These routines should be
 * the only places that do this.
 *
 * These routines set curpcb->pcb_onfault for the time they execute. When a
 * protection violation occurs inside the functions, the trap handler
 * returns to *curpcb->pcb_onfault instead of the function.
 */

.macro SMAP_DISABLE smap
.if	\smap
	stac
.endif
.endm


.macro SMAP_ENABLE smap
.if	\smap
	clac
.endif
.endm

.macro COPYINOUT_BEGIN
.endm

.macro COPYINOUT_END
	movq	%rax,PCB_ONFAULT(%r11)
	POP_FRAME_POINTER
.endm

.macro COPYINOUT_SMAP_END
	SMAP_ENABLE smap=1
	COPYINOUT_END
.endm

/*
 * copyout(from_kernel, to_user, len)
 *         %rdi,        %rsi,    %rdx
 */
.macro	COPYOUT smap erms
	PUSH_FRAME_POINTER
	movq	PCPU(CURPCB),%r11
	movq	$copy_fault,PCB_ONFAULT(%r11)

	/*
	 * Check explicitly for non-user addresses.
	 * First, prevent address wrapping.
	 */
	movq	%rsi,%rax
	addq	%rdx,%rax
	jc	copy_fault
/*
 * XXX STOP USING VM_MAXUSER_ADDRESS.
 * It is an end address, not a max, so every time it is used correctly it
 * looks like there is an off by one error, and of course it caused an off
 * by one error in several places.
 */
	movq	$VM_MAXUSER_ADDRESS,%rcx
	cmpq	%rcx,%rax
	ja	copy_fault

	/*
	 * Set return value to zero. Remaining failure mode goes through
	 * copy_fault.
	 */
	xorl	%eax,%eax

	/*
	 * Set up arguments for MEMMOVE.
	 */
	movq	%rdi,%r8
	movq	%rsi,%rdi
	movq	%r8,%rsi
	movq	%rdx,%rcx


	SMAP_DISABLE \smap
.if	\smap == 1
	MEMMOVE erms=\erms overlap=0 begin=COPYINOUT_BEGIN end=COPYINOUT_SMAP_END
.else
	MEMMOVE erms=\erms overlap=0 begin=COPYINOUT_BEGIN end=COPYINOUT_END
.endif
	/* NOTREACHED */
.endm

ENTRY(copyout_nosmap_std)
	COPYOUT smap=0 erms=0
END(copyout_nosmap_std)

ENTRY(copyout_smap_std)
	COPYOUT smap=1 erms=0
END(copyout_smap_std)

ENTRY(copyout_nosmap_erms)
	COPYOUT smap=0 erms=1
END(copyout_nosmap_erms)

ENTRY(copyout_smap_erms)
	COPYOUT smap=1 erms=1
END(copyout_smap_erms)

/*
 * copyin(from_user, to_kernel, len)
 *        %rdi,      %rsi,      %rdx
 */
.macro	COPYIN smap erms
	PUSH_FRAME_POINTER
	movq	PCPU(CURPCB),%r11
	movq	$copy_fault,PCB_ONFAULT(%r11)

	/*
	 * make sure address is valid
	 */
	movq	%rdi,%rax
	addq	%rdx,%rax
	jc	copy_fault
	movq	$VM_MAXUSER_ADDRESS,%rcx
	cmpq	%rcx,%rax
	ja	copy_fault

	xorl	%eax,%eax

	movq	%rdi,%r8
	movq	%rsi,%rdi
	movq	%r8,%rsi
	movq	%rdx,%rcx

	SMAP_DISABLE \smap
.if	\smap == 1
	MEMMOVE erms=\erms overlap=0 begin=COPYINOUT_BEGIN end=COPYINOUT_SMAP_END
.else
	MEMMOVE erms=\erms overlap=0 begin=COPYINOUT_BEGIN end=COPYINOUT_END
.endif
	/* NOTREACHED */
.endm

ENTRY(copyin_nosmap_std)
	COPYIN smap=0 erms=0
END(copyin_nosmap_std)

ENTRY(copyin_smap_std)
	COPYIN smap=1 erms=0
END(copyin_smap_std)

ENTRY(copyin_nosmap_erms)
	COPYIN smap=0 erms=1
END(copyin_nosmap_erms)

ENTRY(copyin_smap_erms)
	COPYIN smap=1 erms=1
END(copyin_smap_erms)

	ALIGN_TEXT
copy_fault:
	testl	$CPUID_STDEXT_SMAP,cpu_stdext_feature(%rip)
	je	1f
	clac
1:	movq	$0,PCB_ONFAULT(%r11)
	movl	$EFAULT,%eax
	POP_FRAME_POINTER
	ret

/*
 * casueword32.  Compare and set user integer.  Returns -1 on fault,
 *        0 if access was successful, and 1 when comparison failed.
 *        Old value is written to *oldp.
 *        dst = %rdi, old = %esi, oldp = %rdx, new = %ecx
 */
ENTRY(casueword32_nosmap)
	PUSH_FRAME_POINTER
	movq	PCPU(CURPCB),%r8
	movq	$fusufault,PCB_ONFAULT(%r8)

	movq	$VM_MAXUSER_ADDRESS-4,%rax
	cmpq	%rax,%rdi			/* verify address is valid */
	ja	fusufault

	movl	%esi,%eax			/* old */
	lock cmpxchgl %ecx,(%rdi)		/* new = %ecx */
	setne	%cl

	/*
	 * The old value is in %eax.  If the store succeeded it will be the
	 * value we expected (old) from before the store, otherwise it will
	 * be the current value.  Save %eax into %esi to prepare the return
	 * value.
	 */
	movl	%eax,%esi
	xorl	%eax,%eax
	movq	%rax,PCB_ONFAULT(%r8)

	/*
	 * Access the oldp after the pcb_onfault is cleared, to correctly
	 * catch corrupted pointer.
	 */
	movl	%esi,(%rdx)			/* oldp = %rdx */
	POP_FRAME_POINTER
	movzbl	%cl, %eax
	ret
END(casueword32_nosmap)

ENTRY(casueword32_smap)
	PUSH_FRAME_POINTER
	movq	PCPU(CURPCB),%r8
	movq	$fusufault,PCB_ONFAULT(%r8)

	movq	$VM_MAXUSER_ADDRESS-4,%rax
	cmpq	%rax,%rdi			/* verify address is valid */
	ja	fusufault

	movl	%esi,%eax			/* old */
	stac
	lock cmpxchgl %ecx,(%rdi)		/* new = %ecx */
	clac
	setne	%cl

	/*
	 * The old value is in %eax.  If the store succeeded it will be the
	 * value we expected (old) from before the store, otherwise it will
	 * be the current value.  Save %eax into %esi to prepare the return
	 * value.
	 */
	movl	%eax,%esi
	xorl	%eax,%eax
	movq	%rax,PCB_ONFAULT(%r8)

	/*
	 * Access the oldp after the pcb_onfault is cleared, to correctly
	 * catch corrupted pointer.
	 */
	movl	%esi,(%rdx)			/* oldp = %rdx */
	POP_FRAME_POINTER
	movzbl	%cl, %eax
	ret
END(casueword32_smap)

/*
 * casueword.  Compare and set user long.  Returns -1 on fault,
 *        0 if access was successful, and 1 when comparison failed.
 *        Old value is written to *oldp.
 *        dst = %rdi, old = %rsi, oldp = %rdx, new = %rcx
 */
ENTRY(casueword_nosmap)
	PUSH_FRAME_POINTER
	movq	PCPU(CURPCB),%r8
	movq	$fusufault,PCB_ONFAULT(%r8)

	movq	$VM_MAXUSER_ADDRESS-4,%rax
	cmpq	%rax,%rdi			/* verify address is valid */
	ja	fusufault

	movq	%rsi,%rax			/* old */
	lock cmpxchgq %rcx,(%rdi)		/* new = %rcx */
	setne	%cl

	/*
	 * The old value is in %rax.  If the store succeeded it will be the
	 * value we expected (old) from before the store, otherwise it will
	 * be the current value.
	 */
	movq	%rax,%rsi
	xorl	%eax,%eax
	movq	%rax,PCB_ONFAULT(%r8)
	movq	%rsi,(%rdx)
	POP_FRAME_POINTER
	movzbl	%cl, %eax
	ret
END(casueword_nosmap)

ENTRY(casueword_smap)
	PUSH_FRAME_POINTER
	movq	PCPU(CURPCB),%r8
	movq	$fusufault,PCB_ONFAULT(%r8)

	movq	$VM_MAXUSER_ADDRESS-4,%rax
	cmpq	%rax,%rdi			/* verify address is valid */
	ja	fusufault

	movq	%rsi,%rax			/* old */
	stac
	lock cmpxchgq %rcx,(%rdi)		/* new = %rcx */
	clac
	setne	%cl

	/*
	 * The old value is in %rax.  If the store succeeded it will be the
	 * value we expected (old) from before the store, otherwise it will
	 * be the current value.
	 */
	movq	%rax,%rsi
	xorl	%eax,%eax
	movq	%rax,PCB_ONFAULT(%r8)
	movq	%rsi,(%rdx)
	POP_FRAME_POINTER
	movzbl	%cl, %eax
	ret
END(casueword_smap)

/*
 * Fetch (load) a 64-bit word, a 32-bit word, a 16-bit word, or an 8-bit
 * byte from user memory.
 * addr = %rdi, valp = %rsi
 */

ENTRY(fueword_nosmap)
	PUSH_FRAME_POINTER
	movq	PCPU(CURPCB),%rcx
	movq	$fusufault,PCB_ONFAULT(%rcx)

	movq	$VM_MAXUSER_ADDRESS-8,%rax
	cmpq	%rax,%rdi			/* verify address is valid */
	ja	fusufault

	xorl	%eax,%eax
	movq	(%rdi),%r11
	movq	%rax,PCB_ONFAULT(%rcx)
	movq	%r11,(%rsi)
	POP_FRAME_POINTER
	ret
END(fueword_nosmap)

ENTRY(fueword_smap)
	PUSH_FRAME_POINTER
	movq	PCPU(CURPCB),%rcx
	movq	$fusufault,PCB_ONFAULT(%rcx)

	movq	$VM_MAXUSER_ADDRESS-8,%rax
	cmpq	%rax,%rdi			/* verify address is valid */
	ja	fusufault

	xorl	%eax,%eax
	stac
	movq	(%rdi),%r11
	clac
	movq	%rax,PCB_ONFAULT(%rcx)
	movq	%r11,(%rsi)
	POP_FRAME_POINTER
	ret
END(fueword_smap)

ENTRY(fueword32_nosmap)
	PUSH_FRAME_POINTER
	movq	PCPU(CURPCB),%rcx
	movq	$fusufault,PCB_ONFAULT(%rcx)

	movq	$VM_MAXUSER_ADDRESS-4,%rax
	cmpq	%rax,%rdi			/* verify address is valid */
	ja	fusufault

	xorl	%eax,%eax
	movl	(%rdi),%r11d
	movq	%rax,PCB_ONFAULT(%rcx)
	movl	%r11d,(%rsi)
	POP_FRAME_POINTER
	ret
END(fueword32_nosmap)

ENTRY(fueword32_smap)
	PUSH_FRAME_POINTER
	movq	PCPU(CURPCB),%rcx
	movq	$fusufault,PCB_ONFAULT(%rcx)

	movq	$VM_MAXUSER_ADDRESS-4,%rax
	cmpq	%rax,%rdi			/* verify address is valid */
	ja	fusufault

	xorl	%eax,%eax
	stac
	movl	(%rdi),%r11d
	clac
	movq	%rax,PCB_ONFAULT(%rcx)
	movl	%r11d,(%rsi)
	POP_FRAME_POINTER
	ret
END(fueword32_smap)

ENTRY(fuword16_nosmap)
	PUSH_FRAME_POINTER
	movq	PCPU(CURPCB),%rcx
	movq	$fusufault,PCB_ONFAULT(%rcx)

	movq	$VM_MAXUSER_ADDRESS-2,%rax
	cmpq	%rax,%rdi
	ja	fusufault

	movzwl	(%rdi),%eax
	movq	$0,PCB_ONFAULT(%rcx)
	POP_FRAME_POINTER
	ret
END(fuword16_nosmap)

ENTRY(fuword16_smap)
	PUSH_FRAME_POINTER
	movq	PCPU(CURPCB),%rcx
	movq	$fusufault,PCB_ONFAULT(%rcx)

	movq	$VM_MAXUSER_ADDRESS-2,%rax
	cmpq	%rax,%rdi
	ja	fusufault

	stac
	movzwl	(%rdi),%eax
	clac
	movq	$0,PCB_ONFAULT(%rcx)
	POP_FRAME_POINTER
	ret
END(fuword16_smap)

ENTRY(fubyte_nosmap)
	PUSH_FRAME_POINTER
	movq	PCPU(CURPCB),%rcx
	movq	$fusufault,PCB_ONFAULT(%rcx)

	movq	$VM_MAXUSER_ADDRESS-1,%rax
	cmpq	%rax,%rdi
	ja	fusufault

	movzbl	(%rdi),%eax
	movq	$0,PCB_ONFAULT(%rcx)
	POP_FRAME_POINTER
	ret
END(fubyte_nosmap)

ENTRY(fubyte_smap)
	PUSH_FRAME_POINTER
	movq	PCPU(CURPCB),%rcx
	movq	$fusufault,PCB_ONFAULT(%rcx)

	movq	$VM_MAXUSER_ADDRESS-1,%rax
	cmpq	%rax,%rdi
	ja	fusufault

	stac
	movzbl	(%rdi),%eax
	clac
	movq	$0,PCB_ONFAULT(%rcx)
	POP_FRAME_POINTER
	ret
END(fubyte_smap)

/*
 * Store a 64-bit word, a 32-bit word, a 16-bit word, or an 8-bit byte to
 * user memory.
 * addr = %rdi, value = %rsi
 */
ENTRY(suword_nosmap)
	PUSH_FRAME_POINTER
	movq	PCPU(CURPCB),%rcx
	movq	$fusufault,PCB_ONFAULT(%rcx)

	movq	$VM_MAXUSER_ADDRESS-8,%rax
	cmpq	%rax,%rdi			/* verify address validity */
	ja	fusufault

	movq	%rsi,(%rdi)
	xorl	%eax,%eax
	movq	%rax,PCB_ONFAULT(%rcx)
	POP_FRAME_POINTER
	ret
END(suword_nosmap)

ENTRY(suword_smap)
	PUSH_FRAME_POINTER
	movq	PCPU(CURPCB),%rcx
	movq	$fusufault,PCB_ONFAULT(%rcx)

	movq	$VM_MAXUSER_ADDRESS-8,%rax
	cmpq	%rax,%rdi			/* verify address validity */
	ja	fusufault

	stac
	movq	%rsi,(%rdi)
	clac
	xorl	%eax,%eax
	movq	%rax,PCB_ONFAULT(%rcx)
	POP_FRAME_POINTER
	ret
END(suword_smap)

ENTRY(suword32_nosmap)
	PUSH_FRAME_POINTER
	movq	PCPU(CURPCB),%rcx
	movq	$fusufault,PCB_ONFAULT(%rcx)

	movq	$VM_MAXUSER_ADDRESS-4,%rax
	cmpq	%rax,%rdi			/* verify address validity */
	ja	fusufault

	movl	%esi,(%rdi)
	xorl	%eax,%eax
	movq	%rax,PCB_ONFAULT(%rcx)
	POP_FRAME_POINTER
	ret
END(suword32_nosmap)

ENTRY(suword32_smap)
	PUSH_FRAME_POINTER
	movq	PCPU(CURPCB),%rcx
	movq	$fusufault,PCB_ONFAULT(%rcx)

	movq	$VM_MAXUSER_ADDRESS-4,%rax
	cmpq	%rax,%rdi			/* verify address validity */
	ja	fusufault

	stac
	movl	%esi,(%rdi)
	clac
	xorl	%eax,%eax
	movq	%rax,PCB_ONFAULT(%rcx)
	POP_FRAME_POINTER
	ret
END(suword32_smap)

ENTRY(suword16_nosmap)
	PUSH_FRAME_POINTER
	movq	PCPU(CURPCB),%rcx
	movq	$fusufault,PCB_ONFAULT(%rcx)

	movq	$VM_MAXUSER_ADDRESS-2,%rax
	cmpq	%rax,%rdi			/* verify address validity */
	ja	fusufault

	movw	%si,(%rdi)
	xorl	%eax,%eax
	movq	%rax,PCB_ONFAULT(%rcx)
	POP_FRAME_POINTER
	ret
END(suword16_nosmap)

ENTRY(suword16_smap)
	PUSH_FRAME_POINTER
	movq	PCPU(CURPCB),%rcx
	movq	$fusufault,PCB_ONFAULT(%rcx)

	movq	$VM_MAXUSER_ADDRESS-2,%rax
	cmpq	%rax,%rdi			/* verify address validity */
	ja	fusufault

	stac
	movw	%si,(%rdi)
	clac
	xorl	%eax,%eax
	movq	%rax,PCB_ONFAULT(%rcx)
	POP_FRAME_POINTER
	ret
END(suword16_smap)

ENTRY(subyte_nosmap)
	PUSH_FRAME_POINTER
	movq	PCPU(CURPCB),%rcx
	movq	$fusufault,PCB_ONFAULT(%rcx)

	movq	$VM_MAXUSER_ADDRESS-1,%rax
	cmpq	%rax,%rdi			/* verify address validity */
	ja	fusufault

	movl	%esi,%eax
	movb	%al,(%rdi)
	xorl	%eax,%eax
	movq	%rax,PCB_ONFAULT(%rcx)
	POP_FRAME_POINTER
	ret
END(subyte_nosmap)

ENTRY(subyte_smap)
	PUSH_FRAME_POINTER
	movq	PCPU(CURPCB),%rcx
	movq	$fusufault,PCB_ONFAULT(%rcx)

	movq	$VM_MAXUSER_ADDRESS-1,%rax
	cmpq	%rax,%rdi			/* verify address validity */
	ja	fusufault

	movl	%esi,%eax
	stac
	movb	%al,(%rdi)
	clac
	xorl	%eax,%eax
	movq	%rax,PCB_ONFAULT(%rcx)
	POP_FRAME_POINTER
	ret
END(subyte_smap)

	ALIGN_TEXT
fusufault:
	testl	$CPUID_STDEXT_SMAP,cpu_stdext_feature(%rip)
	je	1f
	clac
1:	movq	PCPU(CURPCB),%rcx
	xorl	%eax,%eax
	movq	%rax,PCB_ONFAULT(%rcx)
	decq	%rax
	POP_FRAME_POINTER
	ret

/*
 * copyinstr(from, to, maxlen, int *lencopied)
 *           %rdi, %rsi, %rdx, %rcx
 *
 *	copy a string from 'from' to 'to', stop when a 0 character is reached.
 *	return ENAMETOOLONG if string is longer than maxlen, and
 *	EFAULT on protection violations. If lencopied is non-zero,
 *	return the actual length in *lencopied.
 */
.macro COPYINSTR smap
	PUSH_FRAME_POINTER
	movq	%rdx,%r8			/* %r8 = maxlen */
	movq	PCPU(CURPCB),%r9
	movq	$cpystrflt,PCB_ONFAULT(%r9)

	movq	$VM_MAXUSER_ADDRESS,%rax

	/* make sure 'from' is within bounds */
	subq	%rdi,%rax
	jbe	cpystrflt

	SMAP_DISABLE \smap

	/* restrict maxlen to <= VM_MAXUSER_ADDRESS-from */
	cmpq	%rdx,%rax
	jb	8f
1:
	incq	%rdx
2:
	decq	%rdx
.if \smap == 0
	jz	copyinstr_toolong
.else
	jz	copyinstr_toolong_smap
.endif

	movb	(%rdi),%al
	movb	%al,(%rsi)
	incq	%rsi
	incq	%rdi
	testb	%al,%al
	jnz	2b

	SMAP_ENABLE \smap

	/* Success -- 0 byte reached */
	decq	%rdx
	xorl	%eax,%eax

	/* set *lencopied and return %eax */
	movq	%rax,PCB_ONFAULT(%r9)

	testq	%rcx,%rcx
	jz	3f
	subq	%rdx,%r8
	movq	%r8,(%rcx)
3:
	POP_FRAME_POINTER
	ret
	ALIGN_TEXT
8:
	movq	%rax,%rdx
	movq	%rax,%r8
	jmp 1b

.endm

ENTRY(copyinstr_nosmap)
	COPYINSTR smap=0
END(copyinstr_nosmap)

ENTRY(copyinstr_smap)
	COPYINSTR smap=1
END(copyinstr_smap)

cpystrflt:
	testl	$CPUID_STDEXT_SMAP,cpu_stdext_feature(%rip)
	je	1f
	clac
1:	movl	$EFAULT,%eax
cpystrflt_x:
	/* set *lencopied and return %eax */
	movq	$0,PCB_ONFAULT(%r9)

	testq	%rcx,%rcx
	jz	1f
	subq	%rdx,%r8
	movq	%r8,(%rcx)
1:
	POP_FRAME_POINTER
	ret

copyinstr_toolong_smap:
	clac
copyinstr_toolong:
	/* rdx is zero - return ENAMETOOLONG or EFAULT */
	movq	$VM_MAXUSER_ADDRESS,%rax
	cmpq	%rax,%rdi
	jae	cpystrflt
	movl	$ENAMETOOLONG,%eax
	jmp	cpystrflt_x

/*
 * Handling of special amd64 registers and descriptor tables etc
 */
/* void lgdt(struct region_descriptor *rdp); */
ENTRY(lgdt)
	/* reload the descriptor table */
	lgdt	(%rdi)

	/* flush the prefetch q */
	jmp	1f
	nop
1:
	movl	$KDSEL,%eax
	movl	%eax,%ds
	movl	%eax,%es
	movl	%eax,%fs	/* Beware, use wrmsr to set 64 bit base */
	movl	%eax,%gs
	movl	%eax,%ss

	/* reload code selector by turning return into intersegmental return */
	popq	%rax
	pushq	$KCSEL
	pushq	%rax
	lretq
END(lgdt)

/*****************************************************************************/
/* setjump, longjump                                                         */
/*****************************************************************************/

ENTRY(setjmp)
	movq	%rbx,0(%rdi)			/* save rbx */
	movq	%rsp,8(%rdi)			/* save rsp */
	movq	%rbp,16(%rdi)			/* save rbp */
	movq	%r12,24(%rdi)			/* save r12 */
	movq	%r13,32(%rdi)			/* save r13 */
	movq	%r14,40(%rdi)			/* save r14 */
	movq	%r15,48(%rdi)			/* save r15 */
	movq	0(%rsp),%rdx			/* get rta */
	movq	%rdx,56(%rdi)			/* save rip */
	xorl	%eax,%eax			/* return(0); */
	ret
END(setjmp)

ENTRY(longjmp)
	movq	0(%rdi),%rbx			/* restore rbx */
	movq	8(%rdi),%rsp			/* restore rsp */
	movq	16(%rdi),%rbp			/* restore rbp */
	movq	24(%rdi),%r12			/* restore r12 */
	movq	32(%rdi),%r13			/* restore r13 */
	movq	40(%rdi),%r14			/* restore r14 */
	movq	48(%rdi),%r15			/* restore r15 */
	movq	56(%rdi),%rdx			/* get rta */
	movq	%rdx,0(%rsp)			/* put in return frame */
	xorl	%eax,%eax			/* return(1); */
	incl	%eax
	ret
END(longjmp)

/*
 * Support for reading MSRs in the safe manner.  (Instead of panic on #gp,
 * return an error.)
 */
ENTRY(rdmsr_safe)
/* int rdmsr_safe(u_int msr, uint64_t *data) */
	PUSH_FRAME_POINTER
	movq	PCPU(CURPCB),%r8
	movq	PCB_ONFAULT(%r8),%r9
	movq	$msr_onfault,PCB_ONFAULT(%r8)
	movl	%edi,%ecx
	rdmsr			/* Read MSR pointed by %ecx. Returns
				   hi byte in edx, lo in %eax */
	salq	$32,%rdx	/* sign-shift %rdx left */
	movl	%eax,%eax	/* zero-extend %eax -> %rax */
	orq	%rdx,%rax
	movq	%rax,(%rsi)
	movq	%r9,PCB_ONFAULT(%r8)
	xorl	%eax,%eax
	POP_FRAME_POINTER
	ret

/*
 * Support for writing MSRs in the safe manner.  (Instead of panic on #gp,
 * return an error.)
 */
ENTRY(wrmsr_safe)
/* int wrmsr_safe(u_int msr, uint64_t data) */
	PUSH_FRAME_POINTER
	movq	PCPU(CURPCB),%r8
	movq	PCB_ONFAULT(%r8),%r9
	movq	$msr_onfault,PCB_ONFAULT(%r8)
	movl	%edi,%ecx
	movl	%esi,%eax
	sarq	$32,%rsi
	movl	%esi,%edx
	wrmsr			/* Write MSR pointed by %ecx. Accepts
				   hi byte in edx, lo in %eax. */
	movq	%r9,PCB_ONFAULT(%r8)
	xorl	%eax,%eax
	POP_FRAME_POINTER
	ret

/*
 * MSR operations fault handler
 */
	ALIGN_TEXT
msr_onfault:
	movq	%r9,PCB_ONFAULT(%r8)
	movl	$EFAULT,%eax
	POP_FRAME_POINTER
	ret

/*
 * void pmap_pti_pcid_invalidate(uint64_t ucr3, uint64_t kcr3);
 * Invalidates address space addressed by ucr3, then returns to kcr3.
 * Done in assembler to ensure no other memory accesses happen while
 * on ucr3.
 */
	ALIGN_TEXT
ENTRY(pmap_pti_pcid_invalidate)
	pushfq
	cli
	movq	%rdi,%cr3	/* to user page table */
	movq	%rsi,%cr3	/* back to kernel */
	popfq
	retq

/*
 * void pmap_pti_pcid_invlpg(uint64_t ucr3, uint64_t kcr3, vm_offset_t va);
 * Invalidates virtual address va in address space ucr3, then returns to kcr3.
 */
	ALIGN_TEXT
ENTRY(pmap_pti_pcid_invlpg)
	pushfq
	cli
	movq	%rdi,%cr3	/* to user page table */
	invlpg	(%rdx)
	movq	%rsi,%cr3	/* back to kernel */
	popfq
	retq

/*
 * void pmap_pti_pcid_invlrng(uint64_t ucr3, uint64_t kcr3, vm_offset_t sva,
 *     vm_offset_t eva);
 * Invalidates virtual addresses between sva and eva in address space ucr3,
 * then returns to kcr3.
 */
	ALIGN_TEXT
ENTRY(pmap_pti_pcid_invlrng)
	pushfq
	cli
	movq	%rdi,%cr3	/* to user page table */
1:	invlpg	(%rdx)
	addq	$PAGE_SIZE,%rdx
	cmpq	%rdx,%rcx
	ja	1b
	movq	%rsi,%cr3	/* back to kernel */
	popfq
	retq

	.altmacro
	.macro	rsb_seq_label l
rsb_seq_\l:
	.endm
	.macro	rsb_call_label l
	call	rsb_seq_\l
	.endm
	.macro	rsb_seq count
	ll=1
	.rept	\count
	rsb_call_label	%(ll)
	nop
	rsb_seq_label %(ll)
	addq	$8,%rsp
	ll=ll+1
	.endr
	.endm

ENTRY(rsb_flush)
	rsb_seq	32
	ret

/* all callers already saved %rax, %rdx, and %rcx */
ENTRY(handle_ibrs_entry)
	cmpb	$0,hw_ibrs_ibpb_active(%rip)
	je	1f
	movl	$MSR_IA32_SPEC_CTRL,%ecx
	rdmsr
	orl	$(IA32_SPEC_CTRL_IBRS|IA32_SPEC_CTRL_STIBP),%eax
	orl	$(IA32_SPEC_CTRL_IBRS|IA32_SPEC_CTRL_STIBP)>>32,%edx
	wrmsr
	movb	$1,PCPU(IBPB_SET)
	testl	$CPUID_STDEXT_SMEP,cpu_stdext_feature(%rip)
	je	rsb_flush
1:	ret
END(handle_ibrs_entry)

ENTRY(handle_ibrs_exit)
	cmpb	$0,PCPU(IBPB_SET)
	je	1f
	movl	$MSR_IA32_SPEC_CTRL,%ecx
	rdmsr
	andl	$~(IA32_SPEC_CTRL_IBRS|IA32_SPEC_CTRL_STIBP),%eax
	andl	$~((IA32_SPEC_CTRL_IBRS|IA32_SPEC_CTRL_STIBP)>>32),%edx
	wrmsr
	movb	$0,PCPU(IBPB_SET)
1:	ret
END(handle_ibrs_exit)

/* registers-neutral version, but needs stack */
ENTRY(handle_ibrs_exit_rs)
	cmpb	$0,PCPU(IBPB_SET)
	je	1f
	pushq	%rax
	pushq	%rdx
	pushq	%rcx
	movl	$MSR_IA32_SPEC_CTRL,%ecx
	rdmsr
	andl	$~(IA32_SPEC_CTRL_IBRS|IA32_SPEC_CTRL_STIBP),%eax
	andl	$~((IA32_SPEC_CTRL_IBRS|IA32_SPEC_CTRL_STIBP)>>32),%edx
	wrmsr
	popq	%rcx
	popq	%rdx
	popq	%rax
	movb	$0,PCPU(IBPB_SET)
1:	ret
END(handle_ibrs_exit_rs)

	.noaltmacro

/*
 * Flush L1D cache.  Load enough of the data from the kernel text
 * to flush existing L1D content.
 *
 * N.B. The function does not follow ABI calling conventions, it corrupts %rbx.
 * The vmm.ko caller expects that only %rax, %rdx, %rbx, %rcx, %r9, and %rflags
 * registers are clobbered.  The NMI handler caller only needs %r13 and %r15
 * preserved.
 */
ENTRY(flush_l1d_sw)
#define	L1D_FLUSH_SIZE	(64 * 1024)
	movq	$KERNBASE, %r9
	movq	$-L1D_FLUSH_SIZE, %rcx
	/*
	 * pass 1: Preload TLB.
	 * Kernel text is mapped using superpages.  TLB preload is
	 * done for the benefit of older CPUs which split 2M page
	 * into 4k TLB entries.
	 */
1:	movb	L1D_FLUSH_SIZE(%r9, %rcx), %al
	addq	$PAGE_SIZE, %rcx
	jne	1b
	xorl	%eax, %eax
	cpuid
	movq	$-L1D_FLUSH_SIZE, %rcx
	/* pass 2: Read each cache line. */
2:	movb	L1D_FLUSH_SIZE(%r9, %rcx), %al
	addq	$64, %rcx
	jne	2b
	lfence
	ret
#undef	L1D_FLUSH_SIZE
END(flush_l1d_sw)

ENTRY(flush_l1d_sw_abi)
	pushq	%rbx
	call	flush_l1d_sw
	popq	%rbx
	ret
END(flush_l1d_sw_abi)

ENTRY(mds_handler_void)
	retq
END(mds_handler_void)

ENTRY(mds_handler_verw)
	subq	$8, %rsp
	movw	%ds, (%rsp)
	verw	(%rsp)
	addq	$8, %rsp
	retq
END(mds_handler_verw)

ENTRY(mds_handler_ivb)
	pushq	%rax
	pushq	%rdx
	pushq	%rcx

	movq	%cr0, %rax
	testb	$CR0_TS, %al
	je	1f
	clts
1:	movq	PCPU(MDS_BUF), %rdx
	movdqa	%xmm0, PCPU(MDS_TMP)
	pxor	%xmm0, %xmm0

	lfence
	orpd	(%rdx), %xmm0
	orpd	(%rdx), %xmm0
	mfence
	movl	$40, %ecx
	addq	$16, %rdx
2:	movntdq	%xmm0, (%rdx)
	addq	$16, %rdx
	decl	%ecx
	jnz	2b
	mfence

	movdqa	PCPU(MDS_TMP),%xmm0
	testb	$CR0_TS, %al
	je	3f
	movq	%rax, %cr0
3:	popq	%rcx
	popq	%rdx
	popq	%rax
	retq
END(mds_handler_ivb)

ENTRY(mds_handler_bdw)
	pushq	%rax
	pushq	%rbx
	pushq	%rcx
	pushq	%rdi
	pushq	%rsi

	movq	%cr0, %rax
	testb	$CR0_TS, %al
	je	1f
	clts
1:	movq	PCPU(MDS_BUF), %rbx
	movdqa	%xmm0, PCPU(MDS_TMP)
	pxor	%xmm0, %xmm0

	movq	%rbx, %rdi
	movq	%rbx, %rsi
	movl	$40, %ecx
2:	movntdq	%xmm0, (%rbx)
	addq	$16, %rbx
	decl	%ecx
	jnz	2b
	mfence
	movl	$1536, %ecx
	rep; movsb
	lfence

	movdqa	PCPU(MDS_TMP),%xmm0
	testb	$CR0_TS, %al
	je	3f
	movq	%rax, %cr0
3:	popq	%rsi
	popq	%rdi
	popq	%rcx
	popq	%rbx
	popq	%rax
	retq
END(mds_handler_bdw)

ENTRY(mds_handler_skl_sse)
	pushq	%rax
	pushq	%rdx
	pushq	%rcx
	pushq	%rdi

	movq	%cr0, %rax
	testb	$CR0_TS, %al
	je	1f
	clts
1:	movq	PCPU(MDS_BUF), %rdi
	movq	PCPU(MDS_BUF64), %rdx
	movdqa	%xmm0, PCPU(MDS_TMP)
	pxor	%xmm0, %xmm0

	lfence
	orpd	(%rdx), %xmm0
	orpd	(%rdx), %xmm0
	xorl	%eax, %eax
2:	clflushopt	5376(%rdi, %rax, 8)
	addl	$8, %eax
	cmpl	$8 * 12, %eax
	jb	2b
	sfence
	movl	$6144, %ecx
	xorl	%eax, %eax
	rep; stosb
	mfence

	movdqa	PCPU(MDS_TMP), %xmm0
	testb	$CR0_TS, %al
	je	3f
	movq	%rax, %cr0
3:	popq	%rdi
	popq	%rcx
	popq	%rdx
	popq	%rax
	retq
END(mds_handler_skl_sse)

ENTRY(mds_handler_skl_avx)
	pushq	%rax
	pushq	%rdx
	pushq	%rcx
	pushq	%rdi

	movq	%cr0, %rax
	testb	$CR0_TS, %al
	je	1f
	clts
1:	movq	PCPU(MDS_BUF), %rdi
	movq	PCPU(MDS_BUF64), %rdx
	vmovdqa	%ymm0, PCPU(MDS_TMP)
	vpxor	%ymm0, %ymm0, %ymm0

	lfence
	vorpd	(%rdx), %ymm0, %ymm0
	vorpd	(%rdx), %ymm0, %ymm0
	xorl	%eax, %eax
2:	clflushopt	5376(%rdi, %rax, 8)
	addl	$8, %eax
	cmpl	$8 * 12, %eax
	jb	2b
	sfence
	movl	$6144, %ecx
	xorl	%eax, %eax
	rep; stosb
	mfence

	vmovdqa	PCPU(MDS_TMP), %ymm0
	testb	$CR0_TS, %al
	je	3f
	movq	%rax, %cr0
3:	popq	%rdi
	popq	%rcx
	popq	%rdx
	popq	%rax
	retq
END(mds_handler_skl_avx)

ENTRY(mds_handler_skl_avx512)
	pushq	%rax
	pushq	%rdx
	pushq	%rcx
	pushq	%rdi

	movq	%cr0, %rax
	testb	$CR0_TS, %al
	je	1f
	clts
1:	movq	PCPU(MDS_BUF), %rdi
	movq	PCPU(MDS_BUF64), %rdx
	vmovdqa64	%zmm0, PCPU(MDS_TMP)
	vpxord	%zmm0, %zmm0, %zmm0

	lfence
	vorpd	(%rdx), %zmm0, %zmm0
	vorpd	(%rdx), %zmm0, %zmm0
	xorl	%eax, %eax
2:	clflushopt	5376(%rdi, %rax, 8)
	addl	$8, %eax
	cmpl	$8 * 12, %eax
	jb	2b
	sfence
	movl	$6144, %ecx
	xorl	%eax, %eax
	rep; stosb
	mfence

	vmovdqa64	PCPU(MDS_TMP), %zmm0
	testb	$CR0_TS, %al
	je	3f
	movq	%rax, %cr0
3:	popq	%rdi
	popq	%rcx
	popq	%rdx
	popq	%rax
	retq
END(mds_handler_skl_avx512)

ENTRY(mds_handler_silvermont)
	pushq	%rax
	pushq	%rdx
	pushq	%rcx

	movq	%cr0, %rax
	testb	$CR0_TS, %al
	je	1f
	clts
1:	movq	PCPU(MDS_BUF), %rdx
	movdqa	%xmm0, PCPU(MDS_TMP)
	pxor	%xmm0, %xmm0

	movl	$16, %ecx
2:	movntdq	%xmm0, (%rdx)
	addq	$16, %rdx
	decl	%ecx
	jnz	2b
	mfence

	movdqa	PCPU(MDS_TMP),%xmm0
	testb	$CR0_TS, %al
	je	3f
	movq	%rax, %cr0
3:	popq	%rcx
	popq	%rdx
	popq	%rax
	retq
END(mds_handler_silvermont)

/*
 * Do the same as Linux and execute IRET explicitly, despite IPI
 * return does it as well.
 */
ENTRY(cpu_sync_core)
/*
 * Can utilize SERIALIZE when instruction is moved from
 * 'future extensions' to SDM.
 */
	movq	(%rsp), %rdx
	movl	%ss, %eax
	pushq	%rax
	pushq	%rsp
	addq	$16, (%rsp)
	pushfq
	movl	%cs, %eax
	pushq	%rax
	pushq	%rdx
	iretq
END(cpu_sync_core)
