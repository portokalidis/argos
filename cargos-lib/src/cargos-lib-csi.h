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
#ifndef ARGOS_LIB_CSI_H
#define ARGOS_LIB_CSI_H

int cargos_lib_csi_open(cargos_lib_t *inst, const char *fn);

void cargos_lib_csi_close(cargos_lib_t *inst);

inline int cargos_lib_csi_version(cargos_lib_t *inst);

inline cargos_lib_arch_t cargos_lib_csi_arch(cargos_lib_t *inst);

inline const char *cargos_lib_csi_archstring(cargos_lib_t *inst);

inline cargos_lib_attack_t cargos_lib_csi_type(cargos_lib_t *inst);

inline const char *cargos_lib_csi_typestring(cargos_lib_t *inst);

inline uint32_t cargos_lib_csi_ts(cargos_lib_t *inst);

inline unsigned int cargos_lib_csi_regs(cargos_lib_t *inst);

inline cargos_lib_ulong_t cargos_lib_csi_regv(cargos_lib_t *inst, 
		cargos_lib_regidx_t index);

inline cargos_lib_ulong_t cargos_lib_csi_rego(cargos_lib_t *inst, 
		cargos_lib_regidx_t index);

inline uint32_t 
cargos_lib_csi_regnidx(cargos_lib_t *inst, cargos_lib_regidx_t index);

int cargos_lib_csi_reg_tainted(cargos_lib_t *inst, cargos_lib_regidx_t index);

inline cargos_lib_ulong_t cargos_lib_csi_eflags(cargos_lib_t *inst);

inline cargos_lib_ulong_t cargos_lib_csi_feip(cargos_lib_t *inst);

inline unsigned int cargos_lib_csi_mblocks(cargos_lib_t *inst);

inline void cargos_lib_csi_mbfirst(cargos_lib_t *inst);

inline cargos_lib_mb_t *cargos_lib_csi_mbnext(cargos_lib_t *inst);

cargos_lib_mb_t *cargos_lib_csi_mblock(cargos_lib_t *inst, 
		cargos_lib_ulong_t addr, cargos_lib_addr_t atype);


/** Print the header of a csi log
 *
 * \param inst Cargos library instance
 */
void cargos_lib_csi_print_hdr(cargos_lib_t *inst);


/** Print the headers of a csi log's memory blocks
 *
 * \param inst Cargos library instance
 */
void cargos_lib_csi_print_mb(cargos_lib_t *inst);



/** Checks whether a csi log has net tracker information
 *
 * \param inst Cargos library instance
 * \return True if the csi log contains net tracker information
 */
inline int cargos_lib_csi_has_nt(cargos_lib_t *inst);

#endif
