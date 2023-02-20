/* Copyright (c) 2006, Georgios Portokalidis
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above
      copyright notice, this list of conditions and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.
    * Neither the name of the Vrije Universiteit nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
   FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
   COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
   INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
   STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
   OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif
#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#ifdef HAVE_UNISTD
# include <unistd.h>
#endif
#include <stdio.h>

#include <cargos-lib.h>

static char *o_logfn = NULL;
static int o_verbosity = 0;
static int o_binary = 0;
static int o_mode = 0;
static char *o_ntlogfn = NULL;
static long o_addr;

static void
print_version(const char *name)
{
	printf("%s v%s Copyright(c) G Portokalidis\n\n", name, VERSION);
}

static void
print_usage(const char *name)
{
	printf("Usage:\n");
	printf("%s [options] logfile [NTlogfile]\n\n", name);
	printf("Options:\n");
	printf("  -e,  --exploit     Print the memory block of the exploit\n");
	printf("  -n,  --ent         Print net tracker data for the exploit"
			" memory block\n");
	printf("  -t,  --target      Print the memory block of the "
			"jump target\n");
	printf("  -j,  --tnt         Print net tracker data for the jump target"
			" memory block\n");
	printf("  -E,  --eframe      Print exploit ethernet frame\n");
	printf("  -b,  --binary      Print data in binary instead of hex\n");
	printf("  -V,  --vaddr addr  Print memory block starting at virtual address addr\n");
	printf("  -P,  --paddr addr  Print memory block starting at physical address addr\n");
	printf("  -h,  --help        Print this message and exit\n");
	printf("  -v,  --verbose     Be verbose\n");
	printf("\n");
}

static void
parse_arguments(int argc, char **argv)
{
	int c;
	const char opstring[] = "vhentjEV:P:b";
#ifdef HAVE_GETOPT_LONG
	const struct option longopts[] = {
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{ "exploit", no_argument, NULL, 'e' },
		{ "ent", no_argument, NULL, 'n' },
		{ "target", no_argument, NULL, 't' },
		{ "tnt", no_argument, NULL, 'j' },
		{ "eframe", no_argument, NULL, 'E' },
		{ "vblock", required_argument, NULL, 'V' },
		{ "pblock", required_argument, NULL, 'P' },
		{ "binary", no_argument, NULL, 'b' },
		{ NULL, 0, NULL, 0 },
	};

	while ((c = getopt_long(argc, argv, opstring, longopts, NULL)) >= 0)
#else
	while ((c = getopt(argc, argv, opstring)) >= 0)
#endif
	{
		switch (c)
		{
		case 'b':
			o_binary = 1;
			break;
		case 'V':
			o_mode = 6;
			o_addr = strtol(optarg, NULL, 16);
			break;
		case 'P':
			o_mode = 7;
			o_addr = strtol(optarg, NULL, 16);
			break;
		case 'E':
			o_mode = 5;
			break;
		case 'j':
			o_mode = 4;
			break;
		case 't':
			o_mode = 3;
			break;
		case 'n':
			o_mode = 2;
			break;
		case 'e':
			o_mode = 1;
			break;
		case 'v':
			o_verbosity = 1;
			break;
		case 'h':
			print_version(argv[0]);
			print_usage(argv[0]);
			exit(0);
		default:
			fprintf(stderr, "Unknown option\n\n");
			print_usage(argv[0]);
			exit(1);
		}
	}
	if (optind >= argc)
	{
		fprintf(stderr, "Log file unspecified\n\n");
		print_usage(argv[0]);
		exit(1);
	}
	o_logfn = argv[optind];
	if (++optind < argc)
		o_ntlogfn = argv[optind];
}

static void
print_data(void *buf, int len)
{
	if (o_binary) {
		fwrite(buf, 1, len, stdout);
		fflush(stdout);
	} else {
		cargos_lib_printhex(buf, len);
	}
}

static void
print_exploit(cargos_lib_t *calib)
{
	cargos_lib_mb_t *mb;
	unsigned char *buf;

	mb = cargos_lib_csi_mblock(calib, 
			cargos_lib_csi_rego(calib, CARGOS_LIB_EIP),
			CARGOS_LIB_PHYS);
	if (!mb)
	{
		printf("Memory block containing exploit not found!\n\n");
		return;
	}
	if (!(buf = malloc(cargos_lib_mb_dsize(mb))))
	{
		perror("Could not get memory block");
		return;
	}
	if (cargos_lib_mb_data(mb, buf, cargos_lib_mb_dsize(mb)) < 0)
	{
		fprintf(stderr, "%s\n", cargos_lib_error(calib));
		return;
	}
	printf("Header: ");
	cargos_lib_mb_print_hdr(mb);
	puts("\n\n");

	print_data(buf, cargos_lib_mb_dsize(mb));
}

static void
print_exploitn(cargos_lib_t *calib)
{
	cargos_lib_mb_t *mb;
	uint32_t *buf;
	int i;

	if (!cargos_lib_csi_has_nt(calib))
	{
		printf("Log file does not contain net tracker"
				"information!\n\n");
		return;
	}

	mb = cargos_lib_csi_mblock(calib, 
			cargos_lib_csi_rego(calib, CARGOS_LIB_EIP),
			CARGOS_LIB_PHYS);
	if (!cargos_lib_mb_has_nt(mb))
	{
		printf("Memory block does not contain net tracker"
				"information!\n\n");
		return;
	}
	if (!mb)
	{
		printf("Memory block containing exploit not found!\n\n");
		return;
	}
	if (!(buf = malloc(cargos_lib_mb_nsize(mb))))
	{
		perror("Could not get memory block");
		return;
	}
	if (cargos_lib_mb_ndata(mb, buf, cargos_lib_mb_nsize(mb)) < 0)
	{
		fprintf(stderr, "%s\n", cargos_lib_error(calib));
		return;
	}
	printf("Header: ");
	cargos_lib_mb_print_hdr(mb);
	printf("\nNT data:\n");
	for (i = 0; i < (cargos_lib_mb_nsize(mb) / 4); i++)
	{
		printf("%10u ", buf[i]);
		if (((i + 1) % 7) == 0)
			putchar('\n');
	}
	printf("\n");
}


static void
print_target(cargos_lib_t *calib)
{
	cargos_lib_mb_t *mb;
	unsigned char *buf;

	mb = cargos_lib_csi_mblock(calib, 
			cargos_lib_csi_regv(calib, CARGOS_LIB_EIP),
			CARGOS_LIB_VIRT);
	if (!mb)
	{
		printf("Memory block containing jump target not found!\n\n");
		return;
	}
	if (!(buf = malloc(cargos_lib_mb_dsize(mb))))
	{
		perror("Could not get memory block");
		return;
	}
	if (cargos_lib_mb_data(mb, buf, cargos_lib_mb_dsize(mb)) < 0)
	{
		fprintf(stderr, "%s\n", cargos_lib_error(calib));
		return;
	}
	printf("Header: ");
	cargos_lib_mb_print_hdr(mb);
	puts("\n\n");
	print_data(buf, cargos_lib_mb_dsize(mb));
}

static void
print_addr(cargos_lib_t *calib, long addr, int physical)
{
	int l;
	cargos_lib_mb_t *mb;
	char buf[4096];
	cargos_lib_ulong_t caddr;

	caddr.val32 = addr;
	mb = cargos_lib_csi_mblock(calib, caddr,
			(physical)? CARGOS_LIB_PHYS : CARGOS_LIB_VIRT);
	if (mb == NULL) {
		printf("Memory block 0x%08ld not found!\n\n", caddr.val32);
		return;
	}

	l = cargos_lib_mb_dsize(mb);
	if (l > 4096)
		l = 4096;
	if (cargos_lib_mb_data(mb, buf, l) < 0) {
		fprintf(stderr, "%s\n", cargos_lib_error(calib));
		return;
	}
	print_data(buf, l);
}

static void
print_targetn(cargos_lib_t *calib)
{
	cargos_lib_mb_t *mb;
	uint32_t *buf;
	int i;

	if (!cargos_lib_csi_has_nt(calib))
	{
		printf("Log file does not contain net tracker"
				"information!\n\n");
		return;
	}

	mb = cargos_lib_csi_mblock(calib, 
			cargos_lib_csi_regv(calib, CARGOS_LIB_EIP),
			CARGOS_LIB_VIRT);
	if (!cargos_lib_mb_has_nt(mb))
	{
		printf("Memory block does not contain net tracker"
				" information!\n\n");
		return;
	}
	if (!mb)
	{
		printf("Memory block containing jump target not found!\n\n");
		return;
	}
	if (!(buf = malloc(cargos_lib_mb_nsize(mb))))
	{
		perror("Could not get memory block");
		return;
	}
	if (cargos_lib_mb_ndata(mb, buf, cargos_lib_mb_nsize(mb)) < 0)
	{
		fprintf(stderr, "%s\n", cargos_lib_error(calib));
		return;
	}
	printf("Header: ");
	cargos_lib_mb_print_hdr(mb);
	printf("\nNT data:\n");
	for (i = 0; i < (cargos_lib_mb_nsize(mb) / 4); i++)
	{
		printf("%10u ", buf[i]);
		if (((i + 1) % 7) == 0)
			putchar('\n');
	}
	printf("\n");
}

static void
print_eframe(cargos_lib_t *calib)
{
	unsigned char buf[4096 * 16];
	int l;
	cargos_lib_pkt_t *pkt;

	if (!o_ntlogfn)
	{
		fprintf(stderr, "Net tracker log unspecified!\n");
		return;
	}
	if (!(pkt = cargos_lib_nt_pkt(calib, cargos_lib_csi_regnidx(calib,
						CARGOS_LIB_EIP))))
	{
		printf("No ethernet frame for this EIP!\n");
		return;
	}
	if ((l = cargos_lib_pkt_data(pkt, buf, 4096 * 16)) < 0)
	{
		fprintf(stderr, "%s\n", cargos_lib_error(calib));
		return;
	}
	if (o_verbosity > 0)
		cargos_lib_nt_print(calib);
	printf("\nSequence number(total %u): %u", cargos_lib_nt_ethpkts(calib),
			cargos_lib_pkt_num(pkt));
	printf("\nHeader(Index Length):\n");
	cargos_lib_pkt_print_hdr(pkt);
	puts("\n\n");
	print_data(buf, cargos_lib_pkt_size(pkt));
}



int
main(int argc, char **argv)
{
	cargos_lib_t *calib;

	//print_version(argv[0]);
	parse_arguments(argc, argv);


	if (!(calib = cargos_lib_create()))
	{
		perror("Could not allocate log instance");
		return -1;
	}
	if (cargos_lib_csi_open(calib, o_logfn) != 0)
	{
		fprintf(stderr, "%s\n", cargos_lib_error(calib));
		goto ret;
	}
	if (o_ntlogfn)
		if (cargos_lib_nt_open(calib, o_ntlogfn) != 0)
		{
			fprintf(stderr, "%s\n", cargos_lib_error(calib));
			goto ret;
		}

	switch (o_mode)
	{
	case 1:
		print_exploit(calib);
		break;
	case 2:
		print_exploitn(calib);
		break;
	case 3:
		print_target(calib);
		break;
	case 4:
		print_targetn(calib);
		break;
	case 5:
		print_eframe(calib);
		break;
	case 6:
		print_addr(calib, o_addr, 0);
		break;
	case 7:
		print_addr(calib, o_addr, 1);
		break;
	case 0:
	default:
		cargos_lib_csi_print_hdr(calib);
		if (o_verbosity > 0)
			cargos_lib_csi_print_mb(calib);
		break;
	}
ret:
	cargos_lib_destroy(calib);
	return 0;
}
