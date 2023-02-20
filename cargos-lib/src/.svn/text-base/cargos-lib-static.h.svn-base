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
#ifndef CARGOS_LIB_STATIC_H
#define CARGOS_LIB_STATIC_H

#include <sys/queue.h>
#include <byteswap.h>

#ifndef HAVE_STRDUP
# define strdup(str)	strcpy(malloc(strlen(str) + 1), str)
#endif

LIST_HEAD(mblist_head, cargos_lib_mb);

//! \internal Generic Argos csi log header 
struct csi_log {
	FILE *fl;			//!< Csi log file reference
	unsigned char version;		//!< File version code
	char ntdata;			//!< Log contains net tracker data flag
	char bigendian;			//!< Log data in big endian format flag
	cargos_lib_arch_t arch;		//!< Architecture described by file
	cargos_lib_attack_t type;	//!< Type described by file
	uint32_t ts;			//!< File timestamp
	unsigned int regno;		//!< Number of registers
	cargos_lib_ulong_t reg[17];	//!< Register values (incl. EIP, old_EIP)
	cargos_lib_ulong_t rego[17];	//!< Reg. memory origins (incl. EIP)
	cargos_lib_ulong_t faulty_eip;  //!< EIP where fault occured
	uint32_t regn[17];		//!< Reg. network indices (incl. EIP)
	cargos_lib_ulong_t eflags;	//!< EFLAGS value
	unsigned int mbno;		//!< Number of memory blocks
	struct cargos_lib_mb *mbit;	//!< Memory blocks list iterator
	struct mblist_head mblist; 	//!< Memory blocks list
};

TAILQ_HEAD(framelist_head, cargos_lib_pkt);

//!  \internal Generic net tracker log header
struct nt_log {
	FILE *fl;			//!< Net tracker log file reference
	unsigned int ethpkts;		//!< Number of ethernet packet in log
	uint32_t bytes;			//!< Number of data bytes in log
	struct framelist_head framelist;//!< Ethernet frames list
};

//! \internal Cargos library instance 
struct cargos_lib {
	struct csi_log *csi;	//!< Csi log
	struct nt_log *nt;	//!< Net tracker log
	const char *errstr;	//!< Last error message
};

//! \internal Cargos memory block structure 
struct cargos_lib_mb {
	unsigned char version;		//!< Version code
	char ntdata;			//!< Block contains net tracker data flag
	char bigendian;			//!< Block data in big endian format flag
	unsigned char tainted;		//!< Taintness flag
	uint16_t size;			//!< Size of RAM data
	cargos_lib_ulong_t paddr,	//!< Physical address of block
			   vaddr;	//!< Virtual address of block
	fpos_t pos;			//!< Position of block in file
	struct cargos_lib *lib;		//!< Reference to library we are bound
	LIST_ENTRY(cargos_lib_mb) blocks;
};

//! \internal Cargos ethernet frame structure 
struct cargos_lib_pkt {
	uint16_t size;			//!< Size of frame
	unsigned int num;		//!< Packet number
	uint32_t index;			//!< Index of frame
	fpos_t pos;			//!< Position of frame in file
	struct cargos_lib *lib;		//!< Reference to library we are bound
	TAILQ_ENTRY(cargos_lib_pkt) frames;
};


//! Format code log version bit mask
#define CARGOS_LIB_VERSION_MASK 63U

//! Extract the log version from the format code f
#define CARGOS_LIB_VERSION(f) ((f) & CARGOS_LIB_VERSION_MASK)

//! Format code net tracker bit mask
#define CARGOS_LIB_NT_MASK 128U

//! True if the format code indicates that net tracker data are present
#define CARGOS_LIB_NT(f) ((f) & CARGOS_LIB_NT_MASK)

//! Format code host is big endian bit mask
#define CARGOS_LIB_BE_MASK 64U

//! True if the format code indicates that host data are in big endian
#define CARGOS_LIB_BE(f) ((f) & CARGOS_LIB_BE_MASK)


#ifdef WORDS_BIGENDIAN
# define GET_LENDIAN16(y, x) 	(y) = (uint16_t)bswap_116nt6(x)
#else
# define GET_LENDIAN16(y, x)	(y) = (x)
#endif


#define ERRMSG_CSIAOPEN "A csi log has already been opened for this instance"
#define ERRMSG_CSIFOPEN "Could not open the csi log file. Check that is "\
	"exists and that you have read permissions"
#define ERRMSG_CSIHDR "The csi log header could not be parsed, file could be "\
	"corrupted"
#define ERRMSG_CSIMB "The csi log memory blocks could not be parsed, file "\
	"could be corrupted"
#define ERRMSG_MBREAD "Could not read memory block contents from csi file"
#define ERRMSG_MBNOMEM "Could not allocate memory to process memory block"
#define ERRMSG_MBNONT "Could not return netword indeces, because memory "\
	"block does not containt such information"
#define ERRMSG_NTAOPEN "A net tracker log has already been opened for this "\
	"instance"
#define ERRMSG_NTFOPEN "Could not open the net tracker log file. Check that "\
	"is exists and that you have read permissions"
#define ERRMSG_NTLOG "The net tracker log could not be parsed, file could be "\
	"corrupted"
#define ERRMSG_NTREAD "Could not read ethernet frame from net tracker file"

#endif
