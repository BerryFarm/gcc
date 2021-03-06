dnl  MIPS64 mpn_submul_1 -- Multiply a limb vector with a single limb and
dnl  subtract the product from a second limb vector.

dnl  Copyright 1992, 1994, 1995, 2000, 2001, 2002 Free Software Foundation,
dnl  Inc.

dnl  This file is part of the GNU MP Library.

dnl  The GNU MP Library is free software; you can redistribute it and/or modify
dnl  it under the terms of the GNU Lesser General Public License as published
dnl  by the Free Software Foundation; either version 3 of the License, or (at
dnl  your option) any later version.

dnl  The GNU MP Library is distributed in the hope that it will be useful, but
dnl  WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
dnl  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
dnl  License for more details.

dnl  You should have received a copy of the GNU Lesser General Public License
dnl  along with the GNU MP Library.  If not, see http://www.gnu.org/licenses/.

include(`../config.m4')

C INPUT PARAMETERS
C res_ptr	$4
C s1_ptr	$5
C size		$6
C s2_limb	$7

ASM_START()
PROLOGUE(mpn_submul_1)

C feed-in phase 0
	ld	$8,0($5)

C feed-in phase 1
	daddiu	$5,$5,8
	dmultu	$8,$7

	daddiu	$6,$6,-1
	beq	$6,$0,$LC0
	 move	$2,$0		C zero cy2

	daddiu	$6,$6,-1
	beq	$6,$0,$LC1
	ld	$8,0($5)	C load new s1 limb as early as possible

Loop:	ld	$10,0($4)
	mflo	$3
	mfhi	$9
	daddiu	$5,$5,8
	daddu	$3,$3,$2	C add old carry limb to low product limb
	dmultu	$8,$7
	ld	$8,0($5)	C load new s1 limb as early as possible
	daddiu	$6,$6,-1	C decrement loop counter
	sltu	$2,$3,$2	C carry from previous addition -> $2
	dsubu	$3,$10,$3
	sgtu	$10,$3,$10
	daddu	$2,$2,$10
	sd	$3,0($4)
	daddiu	$4,$4,8
	bne	$6,$0,Loop
	 daddu	$2,$9,$2	C add high product limb and carry from addition

C wind-down phase 1
$LC1:	ld	$10,0($4)
	mflo	$3
	mfhi	$9
	daddu	$3,$3,$2
	sltu	$2,$3,$2
	dmultu	$8,$7
	dsubu	$3,$10,$3
	sgtu	$10,$3,$10
	daddu	$2,$2,$10
	sd	$3,0($4)
	daddiu	$4,$4,8
	daddu	$2,$9,$2	C add high product limb and carry from addition

C wind-down phase 0
$LC0:	ld	$10,0($4)
	mflo	$3
	mfhi	$9
	daddu	$3,$3,$2
	sltu	$2,$3,$2
	dsubu	$3,$10,$3
	sgtu	$10,$3,$10
	daddu	$2,$2,$10
	sd	$3,0($4)
	j	$31
	daddu	$2,$9,$2	C add high product limb and carry from addition
EPILOGUE(mpn_submul_1)
