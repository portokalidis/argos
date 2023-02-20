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
#ifndef CARGOS_LIB_NT_H
#define CARGOS_LIB_NT_H

int cargos_lib_nt_open(cargos_lib_t *inst, const char *fn);

void cargos_lib_nt_close(cargos_lib_t *inst);

inline unsigned int cargos_lib_nt_ethpkts(cargos_lib_t *inst);

inline uint32_t cargos_lib_nt_bytes(cargos_lib_t *inst);

cargos_lib_pkt_t *cargos_lib_nt_pkt(cargos_lib_t *inst, uint32_t index);

inline uint16_t cargos_lib_pkt_size(cargos_lib_pkt_t *pkt);

inline unsigned int cargos_lib_pkt_num(cargos_lib_pkt_t *pkt);

inline uint32_t cargos_lib_pkt_idx(cargos_lib_pkt_t *pkt);

int cargos_lib_pkt_data(cargos_lib_pkt_t *pkt, unsigned char *buf, size_t len);

void cargos_lib_pkt_print_hdr(cargos_lib_pkt_t *pkt);

void cargos_lib_nt_print(cargos_lib_t *inst);

#endif
