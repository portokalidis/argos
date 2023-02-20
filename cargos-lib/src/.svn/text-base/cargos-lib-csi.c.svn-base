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
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#ifdef HAVE_STRING_H
# include <string.h>
#endif
#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif

#include "cargos-lib.h"
#include "cargos-lib-static.h"

#include "debug.h"


// Short csi log headers containing only fixed size fields

struct csi_hdr_fixed {
	uint8_t format;
	uint8_t arch;
	uint16_t type;
	uint32_t ts;
};

struct mb_hdr_fixed {
	uint8_t format;
	uint8_t tainted;
	uint16_t size;
};


static const char *type_strings[] = { "JMP", "P_JMP", "TSS", "CALL", "RET", 
	"CI", "R_IRET", "SYSEXIT", "SYSRET", "R_JMP", "P_CALL", "R_CALL",
	"P_RET" };

static const char archs_string[][7] = { "i386", "x86_64" };



static inline uint16_t correct_endianess16(struct csi_log *csi, uint16_t val)
{
#ifdef WORDS_BIGENDIAN
	if (!csi->bigendian)
#else
	if (csi->bigendian) 
#endif
		return (uint16_t)bswap_16(val);
	return val;
}

static inline uint32_t correct_endianess32(struct csi_log *csi, uint32_t val)
{
#ifdef WORDS_BIGENDIAN
	if (!csi->bigendian) 
#else
	if (csi->bigendian) 
#endif
		return (uint32_t)bswap_32(val);
	return val;
}

static inline uint64_t correct_endianess64(struct csi_log *csi, uint64_t val)
{
#ifdef WORDS_BIGENDIAN
	if (!csi->bigendian) 
#else
	if (csi->bigendian) 
#endif
		return (uint64_t)bswap_64(val);
	return val;
}

static inline cargos_lib_ulong_t 
correct_endianess(struct csi_log *csi, cargos_lib_ulong_t val)
{
#ifdef WORDS_BIGENDIAN
	if (!csi->bigendian)
#else
	if (csi->bigendian)
#endif
		switch (csi->arch) {
		case CARGOS_LIB_I386:
			val.val32 = (uint32_t)bswap_32(val.val32);
			break;
		case CARGOS_LIB_X86_64:
			val.val64 = (uint32_t)bswap_64(val.val64);
			break;
		}
	return val;
}

#define PROCESS_REGS_OP(fname, uname, lname, bytes)			\
static int								\
fname (struct csi_log *csi)						\
{									\
	int i;								\
	for (i = 1; i <= csi->regno; i++) {				\
		if (fread(&csi->reg[i].uname, bytes, 1, csi->fl) != 1)	\
			return -1;					\
		csi->reg[i].uname = lname(csi, csi->reg[i].uname);	\
		dprintf("Header reg[%d]:\t0x%08x\n", i - 1, 		\
				csi->reg[i].uname);			\
	}								\
	for (i = 1; i <= csi->regno; i++) {				\
		if (fread(&csi->rego[i].uname, bytes, 1, csi->fl) != 1)	\
			return -1;					\
		csi->rego[i].uname = lname(csi, csi->rego[i].uname);	\
		dprintf("Header rego[%d]:\t0x%08x\n", i - 1,		\
				csi->rego[i].uname);			\
	}								\
	if (!csi->ntdata) goto eip;					\
	for (i = 1; i <= csi->regno; i++) {				\
		if (fread(csi->regn + i, 4, 1, csi->fl) != 1)		\
			return -1;					\
		csi->regn[i] = correct_endianess32(csi, csi->regn[i]);	\
		dprintf("Header regn[%d]:\t0x%08x\n", i - 1, 		\
				csi->regn[i]);				\
	}								\
eip:									\
	if (fread(&csi->reg[0].uname, bytes, 1, csi->fl) != 1)		\
		return -1;						\
	csi->reg[0].uname = lname(csi, csi->reg[0].uname);		\
	dprintf("Header EIP:\t0x%08x\n", csi->reg[0]);			\
	if (fread(&csi->rego[0].uname, bytes, 1, csi->fl) != 1)		\
		return -1;						\
	csi->rego[0].uname = lname(csi, csi->rego[0].uname);		\
	dprintf("Header EIPo:\t0x%08x\n", csi->rego[0]);		\
	if (!csi->ntdata) goto faulty_eip;					\
	if (fread(csi->regn, 4, 1, csi->fl) != 1)			\
		return -1;						\
	csi->regn[0] = correct_endianess32(csi, csi->regn[0]);		\
	dprintf("Header EIPn:\t0x%08x\n", csi->regn[0]);		\
faulty_eip:								\
	csi->faulty_eip.uname = -1;					\
	if (csi->version < 2)						\
		goto eflags;						\
	if (fread(&csi->faulty_eip.uname, bytes, 1, csi->fl) != 1)	\
		return -1;						\
	csi->faulty_eip.uname = lname(csi, csi->faulty_eip.uname);	\
	dprintf("Header faulty EIP:\t0x%08x\n", csi->faulty_eip);	\
eflags:									\
	if (fread(&csi->eflags, bytes, 1, csi->fl) != 1)		\
		return -1;						\
	csi->eflags = correct_endianess(csi, csi->eflags);		\
	dprintf("Header EFLAGS:\t0x%08x\n", csi->eflags);		\
	return 0;							\
}

PROCESS_REGS_OP(process_regs32, val32, correct_endianess32, 4)

PROCESS_REGS_OP(process_regs64, val64, correct_endianess64, 8)


#define MBLOCK_FIND_OP(fname, uname, xaddr)				     \
static cargos_lib_mb_t *						     \
fname(cargos_lib_t *inst, cargos_lib_ulong_t addr)			     \
{									     \
	cargos_lib_mb_t *mb;						     \
	for (mb = inst->csi->mblist.lh_first; mb != NULL; 		     \
			mb = mb->blocks.le_next) {			     \
		if (addr.uname >= mb->xaddr.uname &&			     \
				addr.uname < (mb->xaddr.uname + mb->size))  \
			return mb;					     \
	}								     \
	return NULL;							     \
}

MBLOCK_FIND_OP(mblock_findp32, val32, paddr)
MBLOCK_FIND_OP(mblock_findv32, val32, vaddr)
MBLOCK_FIND_OP(mblock_findp64, val64, paddr)
MBLOCK_FIND_OP(mblock_findv64, val64, vaddr)

/*
 * Read an unsigned long value from a csi log. 
 *
 * Read an unsigned long value from a csi log. The arch field is used to 
 * determine the size of the field.
 *
 * \param csi Csi log
 * \param ulong Cargos lib unsigned long to store ulong
 *
 * \return 0 on success, or -1 on error
 */
static int freadulong(struct csi_log *csi, cargos_lib_ulong_t *ulong)
{
	int s;
	if (csi->arch == CARGOS_LIB_I386) {
		s = fread(&(ulong->val32), 4, 1, csi->fl);
		return s;
	}
	s =  fread(&ulong->val64, 8, 1, csi->fl);
	return s;
}


/* Process a csi log file header and store it in memory.
 *
 * Process a csi log file header and store it in memory. If the header is
 * incorrect the processing will be interrupted and memory contents will be
 * undefined.
 *
 * \param csi Argos csi log header
 *
 * \return 0 on successful processing, or -1 on error
 */
static int csi_header_process(struct csi_log *csi)
{
	struct csi_hdr_fixed hdr;
	int s;

	// Start with fixed part of log
	if (fread(&hdr, 8, 1, csi->fl) != 1) 
		return -1;
	// Currently it is easy to check valid codes 
	dprintf("Header format:\t0x%02x\n", hdr.format);
	csi->version = CARGOS_LIB_VERSION(hdr.format);
	if (csi->version > 2) 
		return -1;
	csi->ntdata = (CARGOS_LIB_NT(hdr.format))? 0xff : 0;
	csi->bigendian = (CARGOS_LIB_BE(hdr.format))? 0xff : 0;
	hdr.type = correct_endianess16(csi, hdr.type);
	dprintf("Header type:\t0x%02x\n", hdr.type);
	switch (hdr.type) {
	case 0:
		csi->type = CARGOS_LIB_JMP;
		break;
	case 1:
		csi->type = CARGOS_LIB_P_JMP;
		break;
	case 2:
		csi->type = CARGOS_LIB_TSS;
		break;
	case 3:
		csi->type = CARGOS_LIB_CALL;
		break;
	case 4:
		csi->type = CARGOS_LIB_RET;
		break;
	case 5:
		csi->type = CARGOS_LIB_CI;
		break;
	case 6:
		csi->type = CARGOS_LIB_R_IRET;
		break;
	case 7:
		csi->type = CARGOS_LIB_SYSEXIT;
		break;
	case 8:
		csi->type = CARGOS_LIB_SYSRET;
		break;
	case 9:
		csi->type = CARGOS_LIB_R_JMP;
		break;
	case 10:
		csi->type = CARGOS_LIB_P_CALL;
		break;
	case 11:
		csi->type = CARGOS_LIB_R_CALL;
		break;
	case 12:
		csi->type = CARGOS_LIB_P_IRET;
		break;
	default: 
		return -1;
	}
	csi->ts = correct_endianess32(csi, hdr.ts);
	dprintf("Header ts:\t%u\n", csi->ts);
	dprintf("Header arch:\t0x%02x\n", hdr.arch);
	switch (hdr.arch) {
	case 0:
		csi->arch = CARGOS_LIB_I386;
		csi->regno = 8;
		s = process_regs32(csi);
		break;
	case 1:
		csi->arch = CARGOS_LIB_X86_64;
		csi->regno = 16;
		s = process_regs64(csi);
		break;
	default: 
		return -1;
	}
	return (s)? -1 : 0;
}

static void mblocks_destroy(struct csi_log *csi)
{
	struct cargos_lib_mb *mbe;
	while ((mbe = csi->mblist.lh_first)) {
		LIST_REMOVE(mbe, blocks);
		free(mbe);
	}
}

static int process_mblocks(struct cargos_lib *lib)
{
	struct mb_hdr_fixed hdr;
	cargos_lib_mb_t mb, *mbe, *mbp = NULL;
	struct csi_log *csi = lib->csi;
	int sk;

	csi->mbno = 0;
	dprintf("Block #\tFormat\tTainted\tSize\tPADDR\t\tVADDR\n");
	while (1) {
		// First make sure the header is right
		if (fread(&hdr, 4, 1, csi->fl) != 1)
			goto fail;
		mb.version = CARGOS_LIB_VERSION(hdr.format);
		mb.ntdata  = (CARGOS_LIB_NT(hdr.format))? 0xff : 0;
		switch (mb.version) {
		case 0: 
			return 0;
		case 1: 
			break;
		default: 
			return -1;
		}
		mb.tainted = hdr.tainted;
		mb.size = correct_endianess16(csi, hdr.size);
		dprintf("%u\t0x%02x\t%s\t", csi->mbno, mb.version, (mb.tainted)? "YES" : "NO");
		mb.bigendian = csi->bigendian;
		if (freadulong(csi, &(mb.paddr)) != 1)
			goto fail;
		mb.paddr = correct_endianess(csi, mb.paddr);
		if (freadulong(csi, &(mb.vaddr)) != 1)
			goto fail;
		mb.vaddr = correct_endianess(csi, mb.vaddr);
		if (fgetpos(csi->fl, &(mb.pos)) < 0)
			goto fail;
		dprintf("%4hu\t0x%08x\t0x%08x\n", mb.size,
				mb.paddr.val32, mb.vaddr.val32);
		mb.lib = lib;
		// Now allocate a new mb entry and add it to the list
		if (!(mbe = malloc(sizeof(struct cargos_lib_mb))))
			goto fail;
		memcpy(mbe, &mb, sizeof(cargos_lib_mb_t));
		if (mbp) {
			LIST_INSERT_AFTER(mbp, mbe, blocks);
		} else {
			LIST_INSERT_HEAD(&csi->mblist, mbe, blocks);
		}
		mbp = mbe;
		csi->mbno++;
		sk = mb.size;
		if (mb.ntdata) sk *= 5;
		if (fseek(csi->fl, sk, SEEK_CUR) < 0)
			goto fail;
	}
	csi->mbit = csi->mblist.lh_first;
	return 0;

fail:
	mblocks_destroy(csi);
	return -1;
}


/**
 * cargos_lib_csi_open
 * @inst: Library instance.
 * @fn: Csi log filename.
 *
 * Open an Argos csi log and associate it with a library instance. It is
 * required to call this, before using any of the cargos_lib_csi...() 
 * functions.
 *
 * Return value: Returns 0 on success, or -1 on error.
 */
int cargos_lib_csi_open(cargos_lib_t *inst, const char *fn)
{
	if (inst->csi) {
		inst->errstr = strdup(ERRMSG_CSIAOPEN);
		return -1;
	}
	if (!(inst->csi = malloc(sizeof(struct csi_log))))
		return -1; // There is no point to try to allocate an error msg
	if (!(inst->csi->fl = fopen(fn, "r"))) {
		inst->errstr = strdup(ERRMSG_CSIFOPEN);
		goto fail;
	}
	if (csi_header_process(inst->csi) != 0) {
		inst->errstr = strdup(ERRMSG_CSIHDR);
		goto fail;
	}

	// Process memory blocks
	LIST_INIT(&(inst->csi->mblist));
	if (process_mblocks(inst) != 0) {
		inst->errstr = strdup(ERRMSG_CSIMB);
		goto fail;
	}
	return 0;
fail:
	free(inst->csi); inst->csi = NULL;
	return -1;
}

/**
 * cargos_lib_csi_close
 * @inst: Library instance.
 *
 * Close the Argos csi log associated with the library instance and free all
 * allocated memory. You do not have to call this function if you call 
 * @cargos_lib_destroy(). 
 * You will have to call this function if you want to open another csi log 
 * using the same library instance.
 */
void cargos_lib_csi_close(cargos_lib_t *inst)
{
	if (!inst->csi)
		return;
	mblocks_destroy(inst->csi);
	free(inst->csi);
	inst->csi = NULL;
}

/** 
 * cargos_lib_csi_version
 * @inst: Library instance.
 *
 * Return the version of the Argos csi log associated with the instance.
 * 
 * Return value: Returns the version number of the csi log.
 */
int cargos_lib_csi_version(cargos_lib_t *inst)
{
	return inst->csi->version;
}

/**
 * cargos_lib_csi_arch
 * @inst: Library instance.
 *
 * Return the architecture described in the Argos csi log associated with the
 * instance. Available architectures types are: CARGOS_LIB_I386 and
 * CARGOS_LIB_X86_64.
 * 
 * Return value: Returns the architecture described int the csi log.
 */
cargos_lib_arch_t cargos_lib_csi_arch(cargos_lib_t *inst)
{
	return inst->csi->arch;
}

/**
 * cargos_lib_csi_archstring
 * @inst: Library instance.
 *
 * Return a string describing the architecture in the Argos csi log associated 
 * with the instance.
 *
 * Return value: Returns a string describing the architecture in the csi log.
 */
const char *cargos_lib_csi_archstring(cargos_lib_t *inst)
{
	return archs_string[inst->csi->arch];
}

/**
 * cargos_lib_csi_type
 * @inst: Library instance.
 *
 * Return the attack type described in the Argos csi log associated with the
 * instance. Available attack types are: CARGOS_LIB_JMP,
 * CARGOS_LIB_LJMP(deprecated), CARGOS_LIB_TSS,
 * CARGOS_LIB_CALL, CARGOS_LIB_RET, CARGOS_LIB_CI, CARGOS_LIB_IRET,
 * CARGOS_LIB_SYSEXIT, CARGOS_LIB_SYSRET (see also cargos_lib_attack_t).
 * 
 * Return value: Returns the type of the attack described in the csi log.
 */
cargos_lib_attack_t cargos_lib_csi_type(cargos_lib_t *inst)
{
	return inst->csi->type;
}

/**
 * cargos_lib_csi_typestring
 * @inst: Library instance.
 *
 * Return a string describing the attack type in the Argos csi log associated with the 
 * instance.
 *
 * Return value: Returns a string describing the attack in the csi log.
 */
const char *cargos_lib_csi_typestring(cargos_lib_t *inst)
{
	return type_strings[inst->csi->type];
}

/** 
 * cargos_lib_csi_ts
 * @inst: Library instance.
 *
 * Return the timestamp of the Argos csi log associated with the instance.
 * 
 * Return value: Returns a 32 bit timestamp.
 */
uint32_t cargos_lib_csi_ts(cargos_lib_t *inst)
{
	return inst->csi->ts;
}

/**
 * cargos_lib_csi_regs
 * @inst: Library instance.
 *
 * Return the number of resisters in the Argos csi log associated with the 
 * instance.
 * 
 * Return value: Returns the number of registers
 */
unsigned int cargos_lib_csi_regs(cargos_lib_t *inst)
{
	return inst->csi->regno;
}

/**
 * cargos_lib_csi_regv
 * @inst: Library instance.
 * @index: The register index.
 *
 * Return the value of a register in the Argos csi log associtated with the
 * instance. The registers' indices are as follows: EIP = -1,
 * EAX = 0, ECX, EDX, EBX, ESP, EBP, ESI, EDI = 7. 
 * In X86_64 architectures the 8 more general purpose registers are defined as
 * follows: R8 = 8 .. R15 = 15.
 * The macros CARGOS_LIB_EAX, etc can be used instead of an index.
 * 
 * Return value: Returns the value of a resister.
 */
cargos_lib_ulong_t
cargos_lib_csi_regv(cargos_lib_t *inst, cargos_lib_regidx_t index)
{
	return inst->csi->reg[index];
}

/**
 * cargos_lib_csi_rego
 * @inst: Library instance.
 * @index: The register index.
 *
 * Return the memory origin of a register in the Argos csi log associated with
 * the instance. The memory origin represents the physical memory address where
 * the register data originate from. The memory origin address is only present
 * for tainted registers. See also cargos_lib_csi_reg().
 *
 * Return value: Returns the memory origin of a register, or zero if the 
 * register is not tainted.
 */
cargos_lib_ulong_t
cargos_lib_csi_rego(cargos_lib_t *inst, cargos_lib_regidx_t index)
{
	return inst->csi->rego[index];
}

/**
 * cargos_lib_csi_regnidx
 * @inst: Library instance.
 * @index: The register index.
 *
 * Return the network index of a register in the Argos csi log associated with
 * the instance. The network index is valid only for csi logs generated using 
 * a 'net tracker' enabled Argos and tainted registers. It represents the
 * network index of the value in the network trace (usually net_tracker.log)
 * that is responsible for tainting the register.
 * See also cargos_lib_csi_reg().
 *
 * Return value: Returns the network index of a register. Unspecified if the
 * register is not tainted.
 */
uint32_t cargos_lib_csi_regnidx(cargos_lib_t *inst, cargos_lib_regidx_t index)
{
	return inst->csi->regn[index];
}

/**
 * cargos_lib_csi_reg_tainted
 * @inst: Library instance.
 * @index: The register index.
 *
 * Return true if a register in the Argos csi log associated with the instance
 * is tainted. See also cargos_csi_rego().
 * 
 * Return value: Returns 1 if the register is tainted, or zero if otherwise.
 */
int
cargos_lib_csi_reg_tainted(cargos_lib_t *inst, cargos_lib_regidx_t index)
{
	if (index > inst->csi->regno)
		return 0;
	if (inst->csi->arch == CARGOS_LIB_I386)
		return (inst->csi->rego[index].val32)? 1 : 0;
	else
		return (inst->csi->rego[index].val64)? 1 : 0;
}

/** 
 * cargos_lib_csi_eflags
 * @inst: Library instance.
 *
 * Return the value of the EFLAGS register in the Argos csi log associated with
 * the instance.
 *
 * Return value: Returns the value of the EFLAGS register.
 */
cargos_lib_ulong_t cargos_lib_csi_eflags(cargos_lib_t *inst)
{
	return inst->csi->eflags;
}

/** 
 * cargos_lib_csi_feip
 * @inst: Library instance.
 *
 * Return the value of EIP where control was diverted. If the attack was a
 * code injection attack the value is unknown.
 * NOTE: Only valid for argos logs version 2.
 *
 * Return value: Returns the value of EIP for the control diversion instruction.
 */
cargos_lib_ulong_t cargos_lib_csi_feip(cargos_lib_t *inst)
{
	if (inst->csi->version < 2) {
		cargos_lib_ulong_t tmp;
		tmp.val64 = -1;
		return tmp;
	}
	return inst->csi->faulty_eip;
}

/** 
 * cargos_lib_csi_mblocks
 * @inst: Library instance.
 *
 * Return the number of memory blocks in the Argos csi log associated with
 * the instance.
 *
 * Return value: Returns the number of memory blocks in the csi log.
 */
unsigned int cargos_lib_csi_mblocks(cargos_lib_t *inst)
{
	return inst->csi->mbno;
}

/**
 * cargos_lib_csi_mbfirst
 * @inst: Library instance.
 * 
 * Set memory block iteration to return the first memory block at the next 
 * call. You do not have to call this the first time you want to go through the
 * memory blocks list. See also cargos_lib_csi_mbnext().
 */
void cargos_lib_csi_mbfirst(cargos_lib_t *inst)
{
	inst->csi->mbit = inst->csi->mblist.lh_first;
}

/**
 * cargos_lib_csi_mbnext
 * @inst: Library instance.
 *
 * Return the next memory block using the built-in memory block iterator. The
 * user is not required to call argos_lib_csi_mbfirst() before using this
 * function.
 *
 * Return value: Returns the next memory block, or NULL if there are no more
 * blocks.
 */
cargos_lib_mb_t *cargos_lib_csi_mbnext(cargos_lib_t *inst)
{
	cargos_lib_mb_t *mbe = inst->csi->mbit;
	if (mbe == NULL)
		return NULL;
	inst->csi->mbit = mbe->blocks.le_next;
	return mbe;
}

/**
 * cargos_lib_csi_mblock
 * @inst: Library instance.
 * @addr: Memory address.
 * @atype: @addr type.
 *
 * Return the memory block containing a physical or virtual address.
 * The type of the address being looked up is specified by using 
 * CARGOS_LIB_PHYS or CARGOS_LIB_VIRT.
 *
 * Return value: Returns the memory block containing the physical or virtual
 * address, or NULL if no memory block was found.
 */
cargos_lib_mb_t *cargos_lib_csi_mblock(cargos_lib_t *inst, 
		cargos_lib_ulong_t addr, cargos_lib_addr_t atype)
{
	if (inst->csi->arch == CARGOS_LIB_I386)
		switch (atype) {
		case CARGOS_LIB_PHYS:
			return mblock_findp32(inst, addr);
		case CARGOS_LIB_VIRT:
			return mblock_findv32(inst, addr);
		default:
			return NULL;
		}
	switch (atype) {
	case CARGOS_LIB_PHYS:
		return mblock_findp64(inst, addr);
	case CARGOS_LIB_VIRT:
		return mblock_findv64(inst, addr);
	default:
		return NULL;
	}
}

static void regprint_i386(cargos_lib_t *inst)
{
	int i;
	const char regname[][4] = { "EIP", "EAX", "ECX", "EDX", "EBX", "ESP", "EBP",
		"ESI", "EDI" };

	for (i = 1; i < 5; i++)
		printf("%s\t\t", regname[i]);
	printf("\n");
	for (i = 1; i < 5; i++)
		printf(" 0x%08x\t", inst->csi->reg[i].val32);
	printf("\n");
	for (i = 1; i < 5; i++)
		printf("(0x%08x)\t", inst->csi->rego[i].val32);
	printf("\n");
	if (inst->csi->ntdata)
		for (i = 1; i < 5; i++)
			printf("[%10u]\t", inst->csi->regn[i]);
	printf("\n\n");

	for (i = 5; i < 9; i++)
		printf("%s\t\t", regname[i]);
	printf("\n");
	for (i = 5; i < 9; i++)
		printf(" 0x%08x\t", inst->csi->reg[i].val32);
	printf("\n");
	for (i = 5; i < 9; i++)
		printf("(0x%08x)\t", inst->csi->rego[i].val32);
	printf("\n");
	if (inst->csi->ntdata)
		for (i = 5; i < 9; i++)
			printf("[%10u]\t", inst->csi->regn[i]);
	printf("\n\n");
	printf("EIP\t");
	if (inst->csi->version > 1)
		printf("\tFaulty EIP");
	printf("\tEFLAGS\n");
	printf("0x%08x", inst->csi->reg[0].val32);
	if (inst->csi->version > 1)
		printf("\t0x%08x", inst->csi->faulty_eip.val32);
	printf("\t0x%08x\n", inst->csi->eflags.val32);
	printf("(0x%08x)\n", inst->csi->rego[0].val32);
	if (!inst->csi->ntdata)
		return;
	printf("[%u]\n", inst->csi->regn[0]);
}


static void regprint_x86_64(cargos_lib_t *inst)
{
	int i, j;
	const char regname[][4] = { "EAX", "ECX", "EDX", "EBX", "ESP", "EBP",
		"ESI", "EDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14",
		"R15" };

	for (i = 0; i < 8; i++) {
		for (j = 0; j < 2; j++)
			printf("%s\t\t\t", regname[(i + 1) * (j + 1) - 1]);
		printf("\n");
		for (j = 0; j < 2; j++)
			printf("0x%16llx\t", inst->csi->reg[(i + 1) * (j + 1) - 1].val64);
		printf("\n");
		for (j = 0; j < 2; j++)
			printf("0x%16llx\t", inst->csi->rego[(i + 1) * (j + 1) - 1].val64);
		printf("\n");
		if (!inst->csi->ntdata)
			continue;
		for (j = 0; j < 2; j++)
			printf("[%u]\t", inst->csi->regn[(i + 1) * (j + 1) - 1]);
		printf("\n");
	}
	printf("EIP\t\t");
	if (inst->csi->version > 1)
		printf("\tFaulty EIP\t");
	printf("\tEFLAGS\n");
	printf("0x%16llx\t", inst->csi->reg[0].val64);
	if (inst->csi->version > 1)
		printf("0x%16llx", inst->csi->faulty_eip.val64);
	printf("\t0x%16x\n", inst->csi->eflags.val64);
	printf("(0x%16llx)\n", inst->csi->rego[0].val64);
	if (!inst->csi->ntdata)
		return;
	printf("[%u]\n", inst->csi->regn[0]);
}
/*
static void
mbprint32(cargos_lib_t *inst, cargos_lib_mb_t *mb)
{
	uint32_t eip, eipo, mbstart, mbend;

	printf("0x%08x\t0x%08x\t", 
			cargos_lib_mb_addr(mb, CARGOS_LIB_PHYS).val32,
			cargos_lib_mb_addr(mb, CARGOS_LIB_VIRT).val32);

	eip = cargos_lib_csi_regv(inst, CARGOS_LIB_EIP).val32;
	eipo = cargos_lib_csi_rego(inst, CARGOS_LIB_EIP).val32;
	mbstart = cargos_lib_mb_addr(mb, CARGOS_LIB_PHYS).val32;
	mbend = mbstart + cargos_lib_mb_dsize(mb);

	if (eipo >= mbstart && eipo < mbend)
		printf("[E]");

	mbstart = cargos_lib_mb_addr(mb, CARGOS_LIB_VIRT).val32;
	mbend = mbstart + cargos_lib_mb_dsize(mb);

	if (eip >= mbstart && eip < mbend)
		printf(" [S]");

	printf("\n");
}

static void
mbprint64(cargos_lib_t *inst, cargos_lib_mb_t *mb)
{
	uint64_t eip, eipo, mbstart, mbend;

	printf("0x%16x\t0x%16x\t", 
			cargos_lib_mb_addr(mb, CARGOS_LIB_PHYS).val64,
			cargos_lib_mb_addr(mb, CARGOS_LIB_VIRT).val64);

	eip = cargos_lib_csi_regv(inst, CARGOS_LIB_EIP).val64;
	eipo = cargos_lib_csi_rego(inst, CARGOS_LIB_EIP).val64;
	mbstart = cargos_lib_mb_addr(mb, CARGOS_LIB_PHYS).val64;
	mbend = mbstart + cargos_lib_mb_dsize(mb);

	if (eipo >= mbstart && eipo < mbend)
		printf("[E]");

	mbstart = cargos_lib_mb_addr(mb, CARGOS_LIB_VIRT).val64;
	mbend = mbstart + cargos_lib_mb_dsize(mb);

	if (eip >= mbstart && eip < mbend)
		printf(" [S]");

	printf("\n");
}
*/

/**
 * cargos_lib_csi_print_mb
 * @inst: Library instance.
 *
 * Print a list of the memory blocks contained within a csi log.
 * The information printed is aligned in tab separated columns, including a line
 * with string descriptions of the following columns.
 * The fields printed (from left to right) are the following:
 * Block #, block version number, taint-ness flag, size, physicall and virtual
 * address.
 */
void cargos_lib_csi_print_mb(cargos_lib_t *inst)
{
	cargos_lib_mb_t *mb;
	unsigned int n;

	printf("\nBLOCK#\tVERSION\tTAINTED\tSIZE\tPADDR\t\tVADDR\n");
	for (n = 0, mb = inst->csi->mblist.lh_first; mb != NULL; 
			mb = mb->blocks.le_next, n++) {
		printf("%u\t", n);
		cargos_lib_mb_print_hdr(mb);
		printf("\n");
	}
}

/**
 * cargos_lib_csi_print_hdr
 * @inst: Library instance.
 *
 * Print a summary of a csi log header.
 * The information printed include the log's timestamp and version number, the
 * attack's type, the attacked architecture and CPU state at the time of the
 * attack.
 * An example of the printed information is shown below:
 *
 * Net tracker data: YES
 *
 * VERSION         ARCH            TYPE            TIMESTAMP 		
 *
 * 0x01            i386            RET             1160388566			
 * 
 *
 * EAX             ECX             EDX             EBX 
 *
 * 0x00000000      0x006ffd1c      0x7665ff90      0x00000000 
 *
 * (0x00000000)    (0x00000000)    (0x00000000)    (0x00000000)
 *
 * [       747]    [       747]    [       747]    [       747] 
 *
 *
 * ESP             EBP             ESI             EDI 
 *
 * 0x006ff9f8      0x5a634b28      0x00000004      0x006ffa3c 
 *
 * (0x00000000)    (0x040679e4)    (0x00000000)    (0x00000000) 
 *
 * [       747]    [      8545]    [       747]    [       747] 
 *
 *
 * EIP             EFLAGS 
 *
 * 0x773242e0      0x00000202 
 *
 * (0x040679e8) 
 *
 * [8553]
 *
 * The information printed for each register include the value of the register
 * 0x773242e0, the RAM address where the contents of this register were loaded
 * from (0x040679e8), and an index to the net tracker log pointing to a possible
 * location of this data in that log.
 */
void cargos_lib_csi_print_hdr(cargos_lib_t *inst)
{
	printf("Net tracker data: %s\n\n", (inst->csi->ntdata)? "YES" : "NO");
	printf("VERSION\t\tARCH\t\tTYPE\t\tTIMESTAMP\n");
	printf("0x%02x\t\t%s\t\t%s\t\t%u\n\n",
			cargos_lib_csi_version(inst),
			cargos_lib_csi_archstring(inst),
			cargos_lib_csi_typestring(inst),
			cargos_lib_csi_ts(inst));

	switch (cargos_lib_csi_arch(inst)) {
	case CARGOS_LIB_I386:
		regprint_i386(inst);
		break;
	case CARGOS_LIB_X86_64:
		regprint_x86_64(inst);
		break;
	default:
		printf("!!!Unknown architecture type!!!\n");
		return;
	}
}

/**
 * cargos_lib_csi_print_hdr
 * @inst: Library instance.
 *
 * Return whether the csi log, also, includes net tracker information.
 *
 * Return value: Returns true if the log contains net tracker information.
 */
int cargos_lib_csi_has_nt(cargos_lib_t *inst)
{
	return inst->csi->ntdata;
}
