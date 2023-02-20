/*
 * Copyright (c) 2006, G Portokalidis <porto_@users.sourceforge.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Vrije Universiteit nor the names of its 
 *       contributors may be used to endorse or promote products derived from 
 *       this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef CARGOS_LIB_H
#define CARGOS_LIB_H

struct cargos_lib;

/**
 * cargos_lib_t
 *
 * cargos-lib type.
 */
typedef struct cargos_lib cargos_lib_t;

struct cargos_lib_mb;

/**
 * cargos_lib_mb_t
 *
 * cargos-lib memory block type.
 */
typedef struct cargos_lib_mb cargos_lib_mb_t;

struct cargos_lib_pkt;

/**
 * cargos_lib_pkt_t
 *
 * cargos-lib net tracker ethernet packet type.
 */
typedef struct cargos_lib_pkt cargos_lib_pkt_t;


/**
 * cargos_lib_ulong_t
 *
 * cargos-lib unsigned long data type.
 */
typedef union {
	uint32_t val32;		//!< 32 bit unsigned long
	uint64_t val64;		//!< 64 bit unsigned long
} cargos_lib_ulong_t;

/**
 * CARGOS_LIB_REGIDX
 *
 * cargos-lib register aliases.
 */
enum CARGOS_LIB_REGIDX { 
	CARGOS_LIB_EIP = 0,
	CARGOS_LIB_EAX, CARGOS_LIB_ECX, CARGOS_LIB_EDX, CARGOS_LIB_EBX,
	CARGOS_LIB_ESP, CARGOS_LIB_EBP, CARGOS_LIB_ESI, CARGOS_LIB_EDI,
	CARGOS_LIB_R8, CARGOS_LIB_R9, CARGOS_LIB_R10, CARGOS_LIB_R11,
	CARGOS_LIB_R12, CARGOS_LIB_R13, CARGOS_LIB_R14, CARGOS_LIB_R15 
};

/**
 * cargos_lib_regidx_t
 *
 * cargos-lib register data type.
 */
typedef enum CARGOS_LIB_REGIDX cargos_lib_regidx_t;

/** 
 * CARGOS_LIB_ATTACK
 *
 * cargos-lib attack type aliases.
 */
enum CARGOS_LIB_ATTACK {
	CARGOS_LIB_JMP = 0,	//!< Tainted operand to jump instruction
	CARGOS_LIB_P_JMP,	//!< Tainted operand to protected jump instruction
	CARGOS_LIB_TSS, 	//!< EIP will be loaded with tainted data TSS switch
	CARGOS_LIB_CALL,	//!< Tainted operand to call instruction
	CARGOS_LIB_RET,		//!< EIP will be loaded with tainted data in ret instruction
	CARGOS_LIB_CI,		//!< Tainted code will execute
	CARGOS_LIB_R_IRET,	//!< EIP will be loaded with tainted data in real mode iret
	CARGOS_LIB_SYSEXIT,	//!< EIP will be loaded with tainted data in sysexit 
	CARGOS_LIB_SYSRET,	//!< EIP will be loaded with tainted data in sysret
	CARGOS_LIB_R_JMP,	//!< Tainted operand to real mode jump
	CARGOS_LIB_P_CALL,	//!< Tainted operand to protected mode call
	CARGOS_LIB_R_CALL,	//!< Tainted operand to real mode call
	CARGOS_LIB_P_IRET,	//!< EIP  will be loaded with tainted data in protected mode iret
};

/**
 * cargos_lib_attack_t
 *
 * cargos-lib attack type data type.
 */
typedef enum CARGOS_LIB_ATTACK cargos_lib_attack_t;

/**
 * CARGOS_LIB_ADDR
 *
 * cargos-lib memory address type aliases.
 */
enum CARGOS_LIB_ADDR {
	CARGOS_LIB_PHYS = 0,	//!< Physical memory address
	CARGOS_LIB_VIRT		//!< Virtual memory address
};

/**
 * cargos_lib_addr_t
 *
 * cargos-lib memory address type data type.
 */
typedef enum CARGOS_LIB_ADDR cargos_lib_addr_t;

/**
 * CARGOS_LIB_ARCH
 *
 * cargos-lib emulated architecture aliases.
 */
enum CARGOS_LIB_ARCH {
	CARGOS_LIB_I386 = 0,	//!< I386: 8 32 bit registers
	CARGOS_LIB_X86_64	//!< X86_64: 16 64 bit registers
};

/** 
 * cargos_lib_arch_t
 *
 * cargos-lib emulated architecture data-type.
 */
typedef enum CARGOS_LIB_ARCH cargos_lib_arch_t;


cargos_lib_t *cargos_lib_create(void);


void cargos_lib_destroy(cargos_lib_t *inst);

const char *cargos_lib_error(cargos_lib_t *inst);

void cargos_lib_printhex(const unsigned char *buf, size_t len);

void cargos_lib_printalphanum(const unsigned char *buf, size_t len);

void cargos_lib_print_ulong(cargos_lib_t *inst, cargos_lib_ulong_t ulong);

#include <cargos-lib-csi.h>
#include <cargos-lib-mb.h>
#include <cargos-lib-nt.h>

#endif
