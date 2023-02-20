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
#include <ctype.h>

#include "cargos-lib.h"
#include "cargos-lib-static.h"


/**
 * cargos_lib_create
 *
 * Create a new library instance.
 *
 * Return value: Returns newly allocated library instance.
 **/
cargos_lib_t * cargos_lib_create(void)
{
	return calloc(1, sizeof(struct cargos_lib));
}

/**
 * cargos_lib_destroy
 * @lib: Library instance.
 *
 * Destroy a library instance.
 **/
void cargos_lib_destroy(cargos_lib_t *lib)
{
	cargos_lib_csi_close(lib);
	cargos_lib_nt_close(lib);
	if (lib->errstr) 
		free((char *)lib->errstr);
	free(lib);
}

/**
 * cargos_lib_error
 * @lib: Library instance.
 *
 * Returns a description of the lib error
 *
 * Return value: Returns a string description of the last error.
 **/
const char *cargos_lib_error(cargos_lib_t *lib)
{
	return lib->errstr;
}

/**
 * cargos_lib_print_ulong
 * @lib: Library instance.
 * @ulong: cargos library unsigned long.
 *
 * Print @ulong to stdout.
 **/
void cargos_lib_print_ulong(cargos_lib_t *lib, cargos_lib_ulong_t ulong)
{
	if (!lib->csi) 
		return;
	switch (lib->csi->arch) {
	case CARGOS_LIB_I386:
		printf("%08x", ulong.val32);
		break;
	case CARGOS_LIB_X86_64:
		printf("%16llx", ulong.val64);
		break;
	}
}


#define CARGOS_LIB_TERMWIDTH 77

#define ismchar(c) (isalnum(c) && c != '>' && c != '<')

// Change line if terminal is filled up.
static inline void
breakline(int *l, int n)
{
	if ((*l + n) > CARGOS_LIB_TERMWIDTH) {
		printf("\n");
		*l = 0;
	} else 
		*l += n;
}

/**
 * cargos_lib_printhex
 * @buf: A byte buffer
 * @len: Length of @buf
 *
 * Prints the contents of @buf in hexadecimal format.
 */
void
cargos_lib_printhex(const unsigned char *buf, size_t len)
{
	int i, l;
	for (l = i = 0; i < len; i++) {
		if (l > CARGOS_LIB_TERMWIDTH) {
			printf("\n");
			l = 0;
		}
		printf("%02X ", buf[i]);
		l += 3;
	}
	printf("\n");
}

/**
 * cargos_lib_printalphanum
 * @buf: A byte buffer
 * @len: Length of @buf
 *
 * Prints the contents of buf in mixed hexadecimal and alphanumeric format. A
 * byte is printed in alphanumeric depending on the resulst of isalpha().
 * Characters greater '>' and lesser '<' than are always printed as hex.
 */
void
cargos_lib_printalphanum(const unsigned char *buf, size_t len)
{
	int i = 0;

	for (i = 0; i < len; i++)
		printf("%c", (isalnum(buf[i]))? buf[i] : '.');
	printf("\n");
}
