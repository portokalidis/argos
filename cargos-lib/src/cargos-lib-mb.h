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
#ifndef CARGOS_LIB_MB_H
#define CARGOS_LIB_MB_H

inline unsigned char cargos_lib_mb_version(cargos_lib_mb_t *mb);

inline unsigned int cargos_lib_mb_tainted(cargos_lib_mb_t *mb);

inline unsigned int cargos_lib_mb_dsize(cargos_lib_mb_t *mb);

inline unsigned int cargos_lib_mb_nsize(cargos_lib_mb_t *mb);

cargos_lib_ulong_t 
cargos_lib_mb_addr(cargos_lib_mb_t *mb, cargos_lib_addr_t atype);

int cargos_lib_mb_data(cargos_lib_mb_t *mb, unsigned char *buf, size_t len);

int cargos_lib_mb_ndata(cargos_lib_mb_t *mb, uint32_t *buf, size_t len);

void cargos_lib_mb_print_hdr(cargos_lib_mb_t *mb);

inline int cargos_lib_mb_has_nt(cargos_lib_mb_t *mb);

#endif
