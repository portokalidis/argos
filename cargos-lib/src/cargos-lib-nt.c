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

#include "debug.h"



static int
nt_next_ethpkt(struct cargos_lib *inst, uint32_t idx)
{
	uint16_t ethlen;
	struct cargos_lib_pkt *ef;
	struct nt_log *nt = inst->nt;

	switch (fread(&ethlen, 2, 1, nt->fl)) {
	case 1:
		if (!(ef = malloc(sizeof(struct cargos_lib_pkt))))
			return -1;
		GET_LENDIAN16(ef->size, ethlen);
		if (fgetpos(nt->fl, &(ef->pos)) < 0) {
			free(ef);
			return -1;
		}
		ef->lib = inst;
		ef->index = idx;
		ef->num = nt->ethpkts + 1;
		TAILQ_INSERT_TAIL(&nt->framelist, ef, frames);
		if (fseek(nt->fl, ef->size, SEEK_CUR) != 0)
			return -1;
		return ef->size;
	case 0:
		return 0;
	default:
		return -1;
	}
}

static int process_ntlog(struct cargos_lib *inst)
{
	int e;
	struct nt_log *nt = inst->nt;

	while ((e = nt_next_ethpkt(inst, nt->bytes))) {
		nt->bytes += e;
		nt->ethpkts++;
	}

	if (e == 0)
		return 0;
	return -1;
}

/**
 * cargos_lib_csi_open
 * @inst: Library instance.
 * @fn: Net tracker log filename.
 *
 * Open an Argos net tracker log and associate it with a library instance. 
 * It is required to call this, before using any of the cargos_lib_nt...() 
 * functions.
 *
 * Return value: Returns 0 on success, or -1 on error.
 */

int cargos_lib_nt_open(cargos_lib_t *inst, const char *fn)
{
	if (inst->nt) {
		inst->errstr = strdup(ERRMSG_NTAOPEN);
		return -1;
	}
	if (!(inst->nt = malloc(sizeof(struct nt_log))))
		return -1; // There is no point to try to allocate an error msg
	inst->nt->ethpkts = 0;
	inst->nt->bytes = 0;
	TAILQ_INIT(&inst->nt->framelist);
	if (!(inst->nt->fl = fopen(fn, "r"))) {
		inst->errstr = strdup(ERRMSG_NTFOPEN);
		goto fail;
	}
	if (process_ntlog(inst) != 0) {
		inst->errstr = strdup(ERRMSG_NTLOG);
		goto fail;
	}
	return 0;
fail:
	free(inst->nt); inst->nt = NULL;
	return -1;

}

/**
 * cargos_lib_csi_close
 * @inst: Library instance.
 *
 * Close the Argos net tracker log associated with the library instance and free
 * all allocated memory. You need to call this function before calling
 * cargos_lib_csi_close().
 */
void cargos_lib_nt_close(cargos_lib_t *inst)
{
	cargos_lib_pkt_t *pkt;

	if (!inst->nt)
		return;
	while ((pkt = inst->nt->framelist.tqh_first)) {
		TAILQ_REMOVE(&inst->nt->framelist, pkt, frames);
		free(pkt);
	}
	free(inst->nt); 
	inst->nt = NULL;
}

/** 
 * cargos_lib_nt_ethpkts
 * @inst: Library instance.
 *
 * Return the number of ethernet packets within the net tracker log associated
 * with a library instance.
 * Return value: Returns the number of ethernet packets within the net tracker 
 * log.
 */
unsigned int cargos_lib_nt_ethpkts(cargos_lib_t *inst)
{
	return inst->nt->ethpkts;
}

/**
 * cargos_lib_nt_bytes
 * @inst: Library instance.
 *
 * Return the number of network data bytes within the net tracker log
 * associated with a library instance.
 *
 * Return value: Returns the number of network data bytes within the net 
 * tracker log.
 */
uint32_t cargos_lib_nt_bytes(cargos_lib_t *inst)
{
	return inst->nt->bytes;
}

/**
 * cargos_lib_nt_pkt
 * @inst: Library instance.
 * @index: The network index to look for.
 *
 * Look for an ethernet frame in a net tracker log associated with a library
 * instance. 
 *
 * It is important to note that network indices supplied by Argos are accurate
 * to the byte. This means that a network index of 32 for a register, in reality
 * implies that the 4 bytes loaded to the register could be anywhere between
 * index 0 and index 64 in the net tracker log. This is because of some
 * information loss due to some instructions that handle 8 or 16 bytes at once.
 *
 * Return value: Returns the ethernet frame containing the index, or NULL if 
 * the index does not exist.
 */
cargos_lib_pkt_t *cargos_lib_nt_pkt(cargos_lib_t *inst, uint32_t index)
{
	struct cargos_lib_pkt *efp;
	uint32_t cur = 0;

	for (efp = inst->nt->framelist.tqh_first; efp != NULL; efp =
			efp->frames.tqe_next)
	{
		if  (index >= cur && index < (cur + efp->size))
			return efp;
		cur += efp->size;
	}
	return NULL;
}

/** 
 * cargos_lib_pkt_size
 * @pkt: Ethernet frame packet.
 *
 * Return the size of an ethernet frame.
 *
 * Return value: Returns the size of the ethernet frame.
 */
uint16_t cargos_lib_pkt_size(cargos_lib_pkt_t *pkt)
{
	return pkt->size;
}

/** 
 * cargos_lib_pkt_num
 * @pkt: Ethernet frame packet.
 *
 * Return the sequence number of an ethernet frame.
 *
 * Return value: Returns the sequence number of the ethernet frame.
 */
unsigned int cargos_lib_pkt_num(cargos_lib_pkt_t *pkt)
{
	return pkt->num;
}

/** 
 * cargos_lib_pkt_idx
 * @pkt: Ethernet frame packet.
 *
 * Return the starting index of an ethernet frame in the net tracker log.
 *
 * Return value: Returns the index of the ethernet frame.
 */
uint32_t cargos_lib_pkt_idx(cargos_lib_pkt_t *pkt)
{
	return pkt->index;
}

/**
 * cargos_lib_pkt_data
 * @pkt: Ethernet frame packet.
 * @buf: Character array buffer to store ethernet frame data.
 * @len: The length of @buf.
 *
 * Read an ethernet frame's data from a net tracker log.
 *
 * Return value: Returns the number of bytes read into @buf, or -1 on error.
 */
int cargos_lib_pkt_data(cargos_lib_pkt_t *pkt, unsigned char *buf, size_t len)
{
	if (fsetpos(pkt->lib->nt->fl, &pkt->pos) != 0) {
		pkt->lib->errstr = strdup(ERRMSG_NTREAD);
		return -1;
	}
	if (len > pkt->size)
		len = pkt->size;
	if (fread(buf, len, 1, pkt->lib->nt->fl) != 1) {
		pkt->lib->errstr = strdup(ERRMSG_NTREAD);
		return -1;
	}
	return (int)len;
}

/** 
 * cargos_lib_pkt_print_hdr
 * @pkt: Ethernet frame packet.
 *
 * Print an informative summary for an ethernet frame's header.
 * The information printed is separated by a tabs, and include the starting index
 * of the frame and its size.
 */
void cargos_lib_pkt_print_hdr(cargos_lib_pkt_t *pkt)
{
	printf("%u\t%hu", pkt->index, pkt->size);
}

/** 
 * cargos_lib_nt_print
 * @inst: Library instance.
 *
 * Print an informative summary for all ethernet frames in a  net tracker log.
 * The information printed is aligned in columns separated by tabs, and include
 * the frame number, starting index, and size of each packet.
 * A descriptive header is printed on top of every column.
 */
void cargos_lib_nt_print(cargos_lib_t *inst)
{
	cargos_lib_pkt_t *pkt;
	int i;

	printf("No\tIndex\tSize\n");
	for (i = 0, pkt = inst->nt->framelist.tqh_first; pkt; pkt =
			pkt->frames.tqe_next, i++) {
		printf("%d\t", i);
		cargos_lib_pkt_print_hdr(pkt);
		putchar('\n');
	}
}
