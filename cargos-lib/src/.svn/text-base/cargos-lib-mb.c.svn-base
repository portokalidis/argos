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
#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
# include <string.h>
#endif

#include "cargos-lib.h"
#include "cargos-lib-static.h"

/**
 * cargos_lib_mb_version
 * @mb: Memory block.
 *
 * Return the version number of a memory block.
 *
 * Return value: Returns the memory block's version number.
 */
unsigned char cargos_lib_mb_version(cargos_lib_mb_t *mb)
{
	return mb->version;
}

/**
 * cargos_lib_mb_tainted
 * @mb: Memory block.
 *
 * Return whether a memory block is tainted.
 *
 * Return value: Returns true if the memory block is tainted.
 */
unsigned int cargos_lib_mb_tainted(cargos_lib_mb_t *mb)
{
	return mb->tainted;
}

/**
 * cargos_lib_mb_dsize
 * @mb: Memory block.
 *
 * Return the size of a memory block. The size does not actually represent the
 * amount of data stored within the log, but the size of the block as it would
 * in RAM at the emulated system.
 *
 * Return value: Returns the size of the memory block.
 */
unsigned int cargos_lib_mb_dsize(cargos_lib_mb_t *mb)
{
	return mb->size;
}

/**
 * cargos_lib_mb_has_nt
 * @mb: Memory block.
 *
 * Return whether a memory block has net tracker data. The user should call this
 * function for every memory block, before calling any function that access's
 * net tracker data. If the csi log does not contain net tracker data
 * (determined by @cargos_lib_csi_has_nt()), then this function will always 
 * return false.
 *
 * Return value: Returns true if the memory block contains net tracker data.
 */
int cargos_lib_mb_has_nt(cargos_lib_mb_t *mb)
{
	return mb->ntdata;
}

/**
 * cargos_lib_mb_nsize
 * @mb: Memory block.
 *
 * Return the size of net tracker data present for a memory block.
 * The user can call this function before allocating a buffer to read net
 * tracker data from the log.
 *
 * Return value: Returns the size of net tracker data in the memory block. In
 * case no net tracker data are present, 0 is returned.
 */
unsigned int cargos_lib_mb_nsize(cargos_lib_mb_t *mb)
{
	if (mb->ntdata)
		return (4 * mb->size);
	return 0;
}

/**
 * cargos_lib_mb_addr
 * @mb: Memory block.
 * @atype: Memory address type
 *
 * Return the starting memory address of the memory block. @atype specifies
 * whether the physical (CARGOS_LIB_PHYS), or virtual (CARGOS_LIB_VIRT) address
 * of the block is returned.
 *
 * Return value: Returns the starting memory address of the memory block.
 */ 
cargos_lib_ulong_t cargos_lib_mb_addr(cargos_lib_mb_t *mb, cargos_lib_addr_t atype)
{
	switch (atype) {
	case CARGOS_LIB_PHYS:
		return mb->paddr;
	case CARGOS_LIB_VIRT:
		return mb->vaddr;
	default:
		return (cargos_lib_ulong_t)(uint64_t)0;
	}
}

/**
 * cargos_lib_mb_data
 * @mb: Memory block.
 * @buf: Character array buffer to store memory block data.
 * @len: The length of @buf.
 *
 * Read data for memory block @mb into the character array @buf. This function
 * reads as many as @len bytes from the memory block.
 *
 * Return value: Returns the number of bytes read from the log file for the
 * specified memory block, or -1 on error.
 */ 
int cargos_lib_mb_data(cargos_lib_mb_t *mb, unsigned char *buf, size_t len)
{
	if (fsetpos(mb->lib->csi->fl, &mb->pos) != 0) {
		mb->lib->errstr = strdup(ERRMSG_MBREAD);
		return -1;
	}
	if (len > mb->size)
		len = mb->size;
	if (fread(buf, len, 1, mb->lib->csi->fl) != 1) {
		mb->lib->errstr = strdup(ERRMSG_MBREAD);
		return -1;
	}
	return (int)len;
}

/**
 * cargos_lib_mb_ndata
 * @mb: Memory block.
 * @buf: 32bit unsigned integer array to store net tracker data.
 * @len: The length of the array @buf.
 *
 *
 * Read net tracker data for memory block @mb into the array @buf. 
 * This function reads as many as @len 32 bit integers from the memory block.
 *
 * Return value: Returns the number of net tracker integers read from the log 
 * file for the specified memory block, or -1 on error.
 */
int cargos_lib_mb_ndata(cargos_lib_mb_t *mb, uint32_t *buf, size_t len)
{
	int i;

	if (!mb->ntdata) {
		mb->lib->errstr = strdup(ERRMSG_MBNONT);
		return -1;
	}
	if (len > cargos_lib_mb_nsize(mb))
		len = cargos_lib_mb_nsize(mb);
	if (fsetpos(mb->lib->csi->fl, &mb->pos) != 0) {
		mb->lib->errstr = strdup(ERRMSG_MBREAD);
		return -1;
	}
	if (fseek(mb->lib->csi->fl, mb->size, SEEK_CUR) != 0) {
		mb->lib->errstr = strdup(ERRMSG_MBREAD);
		return -1;
	}
	if (fread(buf, len, 1, mb->lib->csi->fl) != 1) {
		mb->lib->errstr = strdup(ERRMSG_MBREAD);
		return -1;
	}

#ifdef WORDS_BIGENDIAN
	if (!mb->bigendian)
#else
	if (mb->bigendian)
#endif
		for (i = 0; i < len; i++)
			buf[i] = bswap_32(buf[i]);
	return (int)len;
}

/**
 * cargos_lib_mb_print_hdr
 * @mb: Memory block.
 *
 * Print a informative summary for a memory block. The information printed are
 * separated by tabs and are (from left to right) the following:
 * Block version number, taint-ness flag, size of block, starting physicall and
 * virtual address.
 */
void cargos_lib_mb_print_hdr(cargos_lib_mb_t *mb)
{
	printf("0x%02x\t%s\t%4u\t0x",
			cargos_lib_mb_version(mb),
			(cargos_lib_mb_tainted(mb))? "YES":"NO",
			cargos_lib_mb_dsize(mb));
	cargos_lib_print_ulong(mb->lib, cargos_lib_mb_addr(mb,
				CARGOS_LIB_PHYS));
	printf("\t0x");
	cargos_lib_print_ulong(mb->lib, cargos_lib_mb_addr(mb,
				CARGOS_LIB_VIRT));
}

