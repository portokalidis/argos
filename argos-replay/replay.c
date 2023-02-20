#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/mman.h>		/* for definitions used in mmap */
#include <sys/select.h>
#include <sys/time.h>		/* for struct timezone and struct timeval  */
#include <sys/stat.h>

#include <termios.h>
#include <time.h>		
#include <poll.h>		/* for definition of pollfd */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <signal.h>
#include <dlfcn.h>
#include <aio.h>
#include <inttypes.h>

#include "replay.h"

/* Prototypes */
void my_init(void);
void my_fini(void);
void init_library_calls(void);


/* Global variables */
char *open_files[1024];		/* filesnames of opened files. used for debug and aio_read64 */
int actual_ro_image_fd;		/* fd at which vm image is opened. */
int vm_image_fd = -1;		/* fd at which qemu believes vm image is opened */

sc_info *cur_sc;		
sc_info buf[SC_INFO_SZ];	/* array to store syscall information */
int sc_ptr;			/* index into sc_info */
int sc_max = SC_INFO_SZ;	/* indicates the last element of sc_info that contains valid data */

int logfile_fd = -1;		/* fd of logfile */
FILE *debugfile;		/* where debugging info is sent (typically stderr) */
FILE *timingfile;
char logfile_name[] = "sc_info.bin";	/* name of logfile */

/* accounting */
unsigned int num_records = 0;
unsigned int total_bytes_saved = 0;
unsigned int total_bytes_aioread = 0;
unsigned int payloads[NUMBER_OF_CALLS+1];
unsigned int numcalls[NUMBER_OF_CALLS+1];

#if 0 
#define CHECK			if (strcmp(__FUNCTION__, sc_names[sc->number])) { \
					fprintf(stderr, "captured %s(), expected %s()\n",\
						__FUNCTION__, sc_names[sc->number]); exit(1); \
				} 
#endif

#define CHECK

#define UNUSED_FUNCTION		error("Prohibited function '%s()' at %s:%d", __FUNCTION__, __FILE__, __LINE__);


#define ENTRY(fmt,arg...)	do {\
					dump("%s(", __FUNCTION__); \
					dump(fmt, arg); \
				}while(0)



#define RETURN(n)		do {\
					num_records++; \
					numcalls[sc->number]++; \
					payloads[sc->number] += sc->len; \
					errno = sc->err; \
					dump(")= 0x%x\n", (n)); \
					return n;\
				}while(0)

#define MIN(a,b)		((a)<(b)?(a):(b))


#define dump(fmt, args...) 
//#define dump(fmt, args...) real_dump(fmt, args)
void real_dump(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(debugfile, fmt, ap);
	va_end(ap);
	
	fflush(debugfile);
}

void debug(const char *fmt, ...)
{
	va_list ap;
	fprintf(stderr, "[+] ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}
void error(const char *fmt, ...)
{
	va_list ap;
	fprintf(stderr, "[-] ");
	va_start(ap,fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");

	my_fini();
}
void failed_syscall(const char *fmt, ...)
{
	int err = errno;
	fprintf(stderr, "[-] ");
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, ": %s\n", strerror(err));

	my_fini();
}

/*************************************************************************
 *
 *                 MEMORY MANAGEMENT 
 * 
 *************************************************************************/
static size_t mem_size = 10485760; /* length of reserved memory (10m) */
static size_t mem_free; /* keeps track of amount of free mem */
static void *mem_base; /* base address of reserved memory */
static void *mem_end;  /* end address of reserved memeory */
static void *mem_ptr;  /* current marker of memory part in use */

static inline void *alloc(size_t size)
{
	void *ret;
	if (mem_free < size) {
		return NULL; /* return null, let caller choose to free up
				memory or bail */
	}

	ret = mem_ptr;

	/* bookkeeping */
	mem_ptr += size;
	mem_free = mem_end - mem_ptr;

	return ret;
}

static inline void dealloc(void *ptr, size_t len)
{
	/* noop */
}


/*************************************************************************
 *
 *                 ROUTINES FOR LOGGING SYSTEM CALL INFO
 * 
 *************************************************************************/
#ifdef CAPTURE
static void sc_info_serialize()
{
	/* Write the contents of buf to 'fd'. Typically the buffer is 
	 * written out once its full (sc_ptr == SC_INFO_SZ), but
	 * it is also called once the program exits. In all cases
	 * sc_ptr points to the last valid entry 
	 */
	int res, n;

	assert(logfile_name != NULL);

	for (n = 0; n < sc_ptr; n++) {
		res = real_write(logfile_fd, (char *)&buf[n], sizeof(sc_info));
		if (res < 0) {
			failed_syscall("write %s failed: ", logfile_name);
		}
		assert(res == sizeof(sc_info));

		/* ALso write out the data pointer if it exists */
		if (buf[n].len > 0) {

			res = real_write(logfile_fd, buf[n].ptr, buf[n].len);
			if (res < 0) 
				failed_syscall("write %d bytes to %s failed: ", 
					       buf[n].len, logfile_name);
			assert(res == buf[n].len);
		}

		if (buf[n].ptr) {
			dealloc(buf[n].ptr, buf[n].len);
		}
	}
	sc_ptr = 0;
	mem_ptr=  mem_base;
	mem_free = mem_size;
}
#endif

#ifdef PLAYBACK
static int sc_info_unserialize()
{
	/* Read at most SC_INFO_SZ entries from 'fd'. Return the number of 
	 * actual records read.  Records are stored in buf, from buf[0] 
	 * upto buf[SC_INFO_SZ-1].
	 *
	 * DO NOT CALL THIS FUNCTION DIRECTLY - entry point is in
	 * sc_info_next() and that function adjusts internal state
	 * based on sc_info_unserialize()'s return value.
	 */
	int res, n;
	sc_info *prev;
	int bytes_done;

	assert(logfile_name != NULL);

	sc_ptr = 0;
	prev = NULL;

	/* clear memory area */
	mem_ptr = mem_base;
	mem_free = mem_size;

	for (n = 0; n < SC_INFO_SZ; n++) {

		/* Read in entry from file */
		res = real_read(logfile_fd, (char *)&buf[n], sizeof(sc_info));
		if (res < 0)
			failed_syscall("reading %s failed: ", logfile_name);
		

		/* Reached end of file, return #records read. */
		if (res == 0) {
			return n;
		}
		assert(res == sizeof(sc_info));
		
		/* read data-ptr if it exists */
		if (buf[n].len > 0) {

			buf[n].ptr = alloc(buf[n].len);

			/* If allocation failed, our buffer is full. Return the records that 
			 * we read. If this happens to be 0 records, bail out, as this means the
			 * buffer we have allocated isnt large enough for this single record
			 */
			if (buf[n].ptr == NULL) {
				if (n == 0){
					error("Buffer not big enough for record.");
				} else {
					/* Place the filepointer back to the beginning of this record */
					res = real_lseek64(logfile_fd, -(sizeof(sc_info)), SEEK_CUR);
					if (res == (off_t)-1)
						failed_syscall("lseek");
				}
				return n;
			}

			/* Allocation was succesful, read in the data block from the file */
			bytes_done = 0;
			do { 
				res = real_read(logfile_fd, buf[n].ptr + bytes_done, buf[n].len - bytes_done);
				if (res < 0 && errno == EINTR) continue;
				if (res < 0) failed_syscall("read");
				if (res == 0) { debug("no data available, sleeping 1s"); sleep(1); }
				bytes_done += res;
			} while (bytes_done != buf[n].len);
		}
	}

	return SC_INFO_SZ;
}
#endif

static sc_info *sc_info_next()
{
	static time_t t;

	/* data is stored in a fixed size buffer. If we have reached the
	 * end of this buffer, we need to flush it (in case we're recording,
	 * or refill it (in case we're replaying)
	 *
	 * sc_max is used to indicate the end of the buffer. It's typically
	 * SC_INFO_SZ, but during playbackm at the end of the file there 
	 * might be less records.
	 */

#ifdef CAPTURE
	/* We have reached the last entry in our buffer- flush it */
	if (sc_ptr == sc_max) {
		sc_info_serialize(); 
	}
#endif

#ifdef PLAYBACK
	/* If the buffer has not been filled yet, or if we have processed
	 * the last element, refill our array of sc_info structures. */
	if (sc_ptr == 0 || sc_ptr == sc_max)  {
		/* sc_max is the number of records read. It will 
		 * typically be SC_INFO_MAX, but might be less
		 * if we read the last few records from the file 
		 */
		do {
			sc_max = sc_info_unserialize();
			if (sc_max == 0)  {
				debug("Out of captured instructions: sleeping 1s");
				sleep(1);
			}
		} while (sc_max == 0);
	}
#endif

	cur_sc = &buf[sc_ptr];

#ifdef CAPTURE
	/* Set up default values for our systemcall */
	cur_sc->number = 0;
	cur_sc->result = -1;
	cur_sc->err = ENOSYS; /* function not implemented */
	cur_sc->len = 0;
	cur_sc->ptr = NULL;
#endif

#ifdef PLAYBACK
	/* If the systemcall number is not set, this means the 
	 * capture run was aborted while executing a systemcall
	 */
	if (cur_sc->number == 0){ 
		error("interrupted system call");
	}
#endif


	sc_ptr++;
	return cur_sc;
}

/*************************************************************************
 *
 *                 CONSTRUCTOR / DESTRUCTOR
 * 
 *************************************************************************/
struct termios savetty;
void my_sigint_hnd(int signal)
{
	/* Ctrl-C hook. If Ctrl-C is pressed, present the user with 
	 * some statistics on the VM execution.
	 *
	 * TODO: Pass through Ctrl-C to virtual machine? Currently its
	 * impossible to interrupt jobs within the virtual machine...
	 */
	int t1,t2,t3;

	int i;
	unsigned int overhead = num_records * sizeof(sc_info)/(1024*1024);

	debug("");
	debug("*** Interrupt ***");
	debug("");

	t1=t2=t3=0;
	for (i = 1; i<NUMBER_OF_CALLS; i++) {
		if (payloads[i] > payloads[t1]) {
			t3=t2;
			t2=t1;
			t1=i;
		}
		else if (payloads[i] > payloads[t2]) {
			t3=t2;
			t2=i;
		}
		else if (payloads[i] > payloads[t3]) {
			t3 = i;
		}
	}
	debug("syscalls by payload:");
	debug("1:  %s(%d) - %dmb",  sc_names[t1], numcalls[t1], payloads[t1]/(1024*1024));
	debug("2:  %s(%d) - %dmb",  sc_names[t2], numcalls[t2], payloads[t2]/(1024*1024));
	debug("3:  %s(%d) - %dmb",  sc_names[t3], numcalls[t2], payloads[t3]/(1024*1024));
	debug("");
	debug("Records: %d (%dmb)", num_records, overhead);
	debug("");
	debug("Total bytes in log due to aio_read: %dmb", total_bytes_aioread/(1024*1024));
	debug("Total bytes in saved due to readonly image: %dmb", total_bytes_saved/(1024*1024));

	/* XXX - find way to send Ctrl-C to VM */
}
void __attribute__ ((destructor)) my_fini(void)
{
	/* Debug */
	my_sigint_hnd(0);

	debug("Execution finished");

	/* Restore tty */
	tcsetattr(0, TCSANOW, &savetty);

#ifdef CAPTURE
	sc_info_serialize();
	debug("Flushed capture data to disk");
#endif
	_exit(0);
}

void my_sigquit_hnd(int signal)
{
	debug("Ctrl-\\ captured. Aborting");
	my_fini();
}

void my_atexit()
{
	debug("Program execution finished.");
	my_fini();
}

void __attribute__ ((constructor)) my_init(void)
{
	/* Clear out accounting data */
	int i;
	for (i=0;i<NUMBER_OF_CALLS;i++){
		payloads[i] = 0;
		numcalls[i] = 0;
	}
	/* initialize file outputs - if fd 4 is available, log to there
	 * This facilitates logging when the program is started with
	 * $ programname 4> debugfile
	 */
	logfile_fd = -1;
	debugfile = fdopen(4, "w");
	if (!debugfile) {
		debugfile = stderr;
	} else {
		debug("File descriptor 4 opened for log output");
	}

	timingfile = fdopen(5, "w");

	/* save tty */
	tcgetattr(0, &savetty);

	/* Initialize pointers to functions */
	init_library_calls();

	/* initialize memory block */
	mem_base = malloc(mem_size);
	if (!mem_base) error("Unable to allocate %d bytes of memory", mem_size);
	mem_ptr = mem_base;
	mem_end = (mem_base+mem_size) -1;
	mem_free = mem_end - mem_base;

	/* hello world */
#ifdef CAPTURE
	debug("Preload 0.2 - Capturing execution");
	logfile_fd = real_open64(logfile_name, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR|S_IWUSR);
#endif
#ifdef PLAYBACK
	debug("Preload 0.2 - Playback execution");
	logfile_fd = real_open64(logfile_name, O_RDONLY);
#endif
	if (logfile_fd < 0) failed_syscall("Opening '%s' failed: ", logfile_name);
	/* Register exit hooks */
	if ( atexit(my_atexit) ) {
		perror("error setting up exit handler");
		_exit(0);
	}
	if ( real_signal(SIGINT, my_sigint_hnd) ) {
		perror("Error setting up Ctrl-C hook");
		_exit(0);
	}
	if ( real_signal(SIGQUIT, my_sigquit_hnd) ) {
		perror("Error setting up Ctrl-\\ hook");
		_exit(0);
	}
}



/*************************************************************************
 *
 *                 DEBUG
 * 
 *************************************************************************/

FILE *fopen64(const char *path, const char *mode)
{
	FILE* (*real_fopen)(const char *, const char *) = dlsym(RTLD_NEXT, "fopen64");
	return real_fopen(path, mode);
}
FILE *fopen(const char *path, const char *mode)
{
	FILE* (*real_fopen)(const char *, const char *) = dlsym(RTLD_NEXT, "fopen");
	return real_fopen(path, mode);
}

/*************************************************************************
 *
 *                 OVERLOADED SYSTEM CALLS 
 * 
 *************************************************************************/

int select(int nfds, fd_set *read, fd_set *write, fd_set *excp, struct timeval *tv)
{
	ENTRY("%d, ... ,  {%d, %d})", nfds, tv->tv_sec, tv->tv_usec);

	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result = real_select(nfds, read, write, excp, tv);
	sc->err = errno;
	sc->number = SELECT_NR;

	/* Save arguments - ptr will contain |read|write|excp|tv|, in order 
	 *
	 * Abuse 'fd' to keep track of which fields are filled in.
	 * 0x1: read has a value
	 * 0x2: write has a value
	 * 0x4: excp has a value 
	 * 0x8: tv has a value 
	 */
	sc->len = 0;
	/* allocate enough room, we might not need it */
	sc->ptr = alloc(3*sizeof(fd_set) + sizeof(struct timeval));

	if (read) {
		sc->len += sizeof(fd_set);
		memcpy(sc->ptr, read, sizeof(fd_set));
		sc->fd |= 0x1;
	}

	if (write) {
		sc->len += sizeof(fd_set);
		memcpy(sc->ptr + sc->len, write, sizeof(fd_set));
		sc->fd |= 0x2;
	}

	if (excp) {
		sc->len += sizeof(fd_set);
		memcpy(sc->ptr + sc->len, excp, sizeof(fd_set));
		sc->fd |= 0x4;
	}

	if (tv) {
		sc->len += sizeof(struct timeval);
		memcpy(sc->ptr + sc->len, tv, sizeof(struct timeval));
		sc->fd |= 0x8;
	}
#endif

#ifdef PLAYBACK
	CHECK;
	
	/* restore arguments */
	if (sc->result > 0)  {
		int len_read = 0; /* offset into sc->ptr to keep track of which bits we
				     have read already */
		if (read) {
			if (sc->fd & 0x1) {
				sc->fd &= ~0x1;
				memcpy(read, sc->ptr, sizeof(fd_set));
				len_read += sizeof(fd_set);
			} else {
				error("playback select() provided readset but none captured");
			}
		}
		
		if (write) {
			if (sc->fd & 0x2) {
				sc->fd &= ~0x2;
				memcpy(write, sc->ptr + len_read, sizeof(fd_set));
				len_read += sizeof(fd_set);
			} else {
				error("playback select() provided writeset but none captured");
			}
		}
		 
		if (excp) {
			if(sc->fd & 0x4) {
				sc->fd &= ~0x4;
				memcpy(excp, sc->ptr + len_read, sizeof(fd_set));
				len_read += sizeof(fd_set);
			} else {
				error("playback select() provided writeset but none captured");
			}
		}
		
		if (tv)  {
			if(sc->fd & 0x8) {
				sc->fd &= ~0x8;
				memcpy(tv, sc->ptr + len_read, sizeof(fd_set));
			} else {
				error("playback select() provided timeval but none captured");
			}
		}

		if (sc->fd) {
			error("select() called with less arguments than stored");
		}
	}
#endif

	RETURN(sc->result);
}

/*************************************************************************
 *
 *                 ASYNCHRONOUS IO - fake with synchronous IO
 * 
 *************************************************************************/
int aio_read64(struct aiocb64 *aiocbp)
{
	/* The first file that is read by aio_read is the virtual machine image. Under
	 * normal operations, this file is read-only. (qemu is started with the -snapshot
	 * option). All changes to the actual filesystem are made to a temporary file 
	 * like /tmp/vl.xxxxx. For performance and storage optimizations, we omit data 
	 * that is read from the read-only VM-file from the capture log. The data from it
	 * can be reconstructed during playback by simply opening the file again and 
	 * reading the same bytes.
	 *
	 * It should be noted that aio_read is also used to read from the aforementioned
	 * temporary file. Therefore we cannot simply override *all* reads made by aio_read.
	 * We store the file descriptor of the VM image file, and only overload reads
	 * from that file.
	 */

	if (vm_image_fd < 0) {
		vm_image_fd = aiocbp->aio_fildes;

#ifdef CAPTURE
		/* capture: the fd of the disk image is the fd we already opened */
		actual_ro_image_fd = vm_image_fd;
#endif
#ifdef PLAYBACK
		/* playback: the fd of the disk image is not yet available - open it first */
		actual_ro_image_fd = real_open64(open_files[vm_image_fd], O_RDONLY);
		if (actual_ro_image_fd < 0) failed_syscall("open");
#endif
	}

	/* perform a read on the read-only disk image */
	if (aiocbp->aio_fildes == vm_image_fd) {
		if (real_lseek64(actual_ro_image_fd, aiocbp->aio_offset, SEEK_SET) == (off64_t)-1) 
			failed_syscall("aio_read64: lseek");
		aiocbp->__return_value = real_read(actual_ro_image_fd, (char*)aiocbp->aio_buf, aiocbp->aio_nbytes);
		aiocbp->__error_code == errno;
		total_bytes_saved += aiocbp->aio_nbytes;
	}

	/* Perform a read on any other device, using the overloaded functions
	 * to capture results */
	else {
		if (lseek64(aiocbp->aio_fildes, aiocbp->aio_offset, SEEK_SET) == (off64_t)-1) 
			failed_syscall("aio_read64: lseek64 (%d) ", errno);
		aiocbp->__return_value = read(aiocbp->aio_fildes, (char *)aiocbp->aio_buf, aiocbp->aio_nbytes);
		aiocbp->__error_code = errno;
		total_bytes_aioread += aiocbp->aio_nbytes;
	}

	return 0; 
}

int aio_read(struct aiocb *aiocbp)
{
	UNUSED_FUNCTION;
	if (lseek(aiocbp->aio_fildes, aiocbp->aio_offset, SEEK_SET) == (off_t)-1) 
		error("lseek in aio_read failed");
	aiocbp->__return_value = read(aiocbp->aio_fildes, (char *)aiocbp->aio_buf, aiocbp->aio_nbytes);
	aiocbp->__error_code = errno;

	return 0; 
}

int aio_write64(struct aiocb64 *aiocbp)
{
	if (lseek64(aiocbp->aio_fildes, aiocbp->aio_offset, SEEK_SET) < 0) 
		error("lseek64 in aio_write failed");

	aiocbp->__return_value = write(aiocbp->aio_fildes, (char *)aiocbp->aio_buf, aiocbp->aio_nbytes);
	aiocbp->__error_code = errno;

	return 0; 
}

int aio_write(struct aiocb *aiocbp)
{
	UNUSED_FUNCTION;
	if (lseek(aiocbp->aio_fildes, aiocbp->aio_offset, SEEK_SET) < 0) 
		error("lseek in aio_write failed");

	aiocbp->__return_value = write(aiocbp->aio_fildes, (char *)aiocbp->aio_buf, aiocbp->aio_nbytes);
	aiocbp->__error_code = errno;

	return 0; 
}

ssize_t aio_return64(struct aiocb64 *aiocbp)
{
	if (aiocbp->__return_value < 0)  {
		return -(aiocbp->__error_code); 
	}

	return aiocbp->__return_value;
}

ssize_t aio_return(struct aiocb *aiocbp)
{
	UNUSED_FUNCTION;
	if (aiocbp->__return_value < 0)  {
		return -(aiocbp->__error_code); 
	}

	return aiocbp->__return_value;
}

int aio_error64(const struct aiocb64 *aiocbp)
{
	if (aiocbp->__return_value < 0) {
		return -(aiocbp->__error_code);
	}

	return 0;
}

int aio_error(const struct aiocb *aiocbp)
{
	UNUSED_FUNCTION;
	if (aiocbp->__return_value < 0) {
		return -(aiocbp->__error_code);
	}

	return 0;
}

int aio_cancel64(int fd, struct aiocb64 *aiocbp)
{
	UNUSED_FUNCTION;
	return AIO_CANCELED;
}

void aio_init(const struct aioinit *init)
{
}


/*************************************************************************
 *
 *                 OPEN / CLOSE
 * 
 *************************************************************************/

int open64(const char *pathname, int flags, ...)
{
	ENTRY("%s, %d", pathname, flags);

	sc_info *sc;
	va_list ap;
	mode_t mode = 0;

	sc = sc_info_next();


	if (flags & O_CREAT) {
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}


#ifdef CAPTURE
	sc->result = real_open64(pathname, flags, mode);
	sc->err = errno;
	sc->number = OPEN64_NR;
	sc->fd2 = flags; 		/* Store flags in fd2. This is used later on
					   to ensure that playback is called with the 
					   same flags */
#endif

#ifdef PLAYBACK
	CHECK;
	
	if (sc->fd2 != flags) {
		error("open: capture flags: 0x%x. playback flags: 0x%x. Abort.", sc->fd2, flags);
	}
#endif

	/* Store the name of the opened file */
	open_files[sc->result] = strndup(pathname, 100);

	RETURN(sc->result);
}

int open(const char *pathname, int flags, ...)
{
	va_list ap;
	mode_t mode = 0;

	if (flags & O_CREAT) {
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}

	return open64(pathname, flags, mode);
}

int creat(const char *pathname, mode_t mode)
{
	return open(pathname, mode, O_CREAT|O_WRONLY|O_TRUNC);
}

int creat64(const char *pathname, mode_t mode)
{
	return open(pathname, mode, O_CREAT|O_WRONLY|O_TRUNC);
}

void *mmap64(void *start, size_t len, int prot, int flags, int fd, off64_t off)
{
	void *res = real_mmap64(start, len, prot, flags, fd, off);

	if (prot & PROT_WRITE && fd > 0)  {
		debug("mmap64(start=0x%x, len=%d, prot=%d, flags=%d, %d, off=%d) = 0x%x (erno:%d)",
	      start, len, prot, flags, fd, off, res, errno);
	}

	return res;
}

void *mmap(void *start, size_t len, int prot, int flags, int fd, off_t off)
{
	UNUSED_FUNCTION;

	void* (*real_mmap)(void*, size_t, int, int, int, off_t) = dlsym(RTLD_NEXT, "mmap");
	void *res = real_mmap(start, len, prot, flags, fd, off);

	debug("mmap(start=0x%x, len=%d, prot=%d, flags=%d, %d, off=%d) = 0x%x (erno:%d)",
	      start, len, prot, flags, fd, off, res, errno);

	return res;
}

int close(int fd)
{
	ENTRY("%d", fd);

	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result = real_close(fd);
	sc->err = errno;
	sc->number = CLOSE_NR;
	sc->fd = fd;
#endif

#ifdef PLAYBACK
	CHECK;

	if (sc->fd != fd) 
		error("stored close(%d) got close(%d)", sc->fd, fd);

#endif

	/* File no longer opened */
	free(open_files[fd]); 
	open_files[fd] = NULL;

	RETURN(sc->result);
}


int mkstemp64(char *template)
{
	return mkstemp(template);
}

int mkstemp(char *template)
{
	ENTRY("%s", template);

	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result = real_mkstemp(template);
	sc->err = errno;
	sc->number = MKSTEMP_NR;
#endif

#ifdef PLAYBACK
	CHECK;
#endif

	RETURN(sc->result);
}


/*************************************************************************
 *
 *                 READ
 * 
 *************************************************************************/
ssize_t read(int fd, void* buf, size_t count)
{
	ENTRY("%d, ... , %d", fd, count);

	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result = real_read(fd, buf, count);
	sc->fd = fd;
	sc->err = errno;
	sc->number = READ_NR;

	if (sc->result > 0) {
		sc->ptr = alloc(sc->result);
		sc->len = sc->result;
		memcpy(sc->ptr, buf, sc->len);
	}

#endif

#ifdef PLAYBACK
	CHECK;

	if (sc->fd != fd) 
		error("read from fd %d, saved read from fd %d", fd, sc->fd);

	if (sc->result > 0)  {
		memcpy(buf, sc->ptr, sc->result);
	}
#endif

	RETURN(sc->result);
}


ssize_t readv(int fd, const struct iovec *iov, int iovcnt)
{
	ENTRY("%d, ...,  %d", fd, iovcnt);

	sc_info *sc = sc_info_next();
	int i = 0;
	ssize_t bytes_done = 0, bytes_todo;

#ifdef CAPTURE
	sc->result = real_readv(fd, iov, iovcnt);
	sc->err = errno;
	sc->number = READV_NR;

	/* Save arguments */
	sc->len = sc->result;
	sc->ptr = alloc(sc->len);

	if (sc->result > 0) {
		bytes_todo = sc->result;
		while (bytes_done < sc->len) {
			memcpy(sc->ptr + bytes_done, iov[i].iov_base, 
			       MIN(iov[i].iov_len, bytes_todo));
			bytes_done += iov[i].iov_len;
			bytes_todo -= iov[i].iov_len;
			i++;
		}
	}
#endif

#ifdef PLAYBACK
	CHECK;

	if (sc->result > 0) {
		bytes_todo = sc->result;
		while (bytes_done < sc->len) {
			memcpy(iov[i].iov_base, sc->ptr + bytes_done, 
			       MIN(iov[i].iov_len, bytes_todo));
			bytes_done += iov[i].iov_len;
			bytes_todo -= iov[i].iov_len;
			i++;
		}
	}
#endif

	RETURN(sc->result);
}


/*************************************************************************
 *
 *                 WRITE
 * 
 *************************************************************************/
ssize_t write(int fd, __const void *buf, size_t count)
{
	ENTRY("%d, ... , %d", fd, count);


	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result = real_write(fd, buf, count);
	sc->err = errno;
	sc->number = WRITE_NR;
	sc->fd = fd;
#endif

#ifdef PLAYBACK
	CHECK;

	if (sc->fd != fd) {
		error("replaying write() to wrong fd: Saved %d, actual %d", sc->fd, fd);
	}

	/* Only replay writes to stout/stderr */
	if (fd == 0){ 
		error("Write to stdin?");
	}

	if (fd <= 2)  {
		real_write(fd, buf, count);
	}
#endif

	RETURN(sc->result);

}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
	ENTRY("%d, ... , %d", fd, iovcnt);

	int i = 0;
	ssize_t bytes_done = 0, bytes_todo;
	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result = real_writev(fd, iov, iovcnt);
	sc->err = errno;
	sc->number = WRITEV_NR;

	if (sc->result > 0) {
		bytes_todo = sc->result;
		sc->ptr = alloc(sc->result);
		sc->len = sc->result;

		while (bytes_done != sc->result) {
			memcpy(sc->ptr + bytes_done, iov[i].iov_base, 
			       MIN(iov[i].iov_len, bytes_todo));
			bytes_done += iov[i].iov_len;
			bytes_todo -= iov[i].iov_len;
			i++;
		}
	}
#endif

#ifdef PLAYBACK
	CHECK;

	if (sc->result > 0) {
		bytes_todo = sc->result;
		while (bytes_done < sc->len) {
			memcpy(sc->ptr + bytes_done, iov[i].iov_base, 
			       MIN(iov[i].iov_len, bytes_todo));
			bytes_done += iov[i].iov_len;
			bytes_todo -= iov[i].iov_len;
			i++;
		}
	}
#endif

	RETURN(sc->result);
}

/******************************************************************************
 *
 * 		OTHER FILE OPERATIONS
 *
 *****************************************************************************/

int fcntl(int fd, int cmd, ...)
{
	ENTRY("%d, %d, ...", fd, cmd);

	va_list ap;
	sc_info *sc = sc_info_next();

	va_start(ap, cmd);

#ifdef CAPTURE
	long arg;
	sc->number = FCNTL_NR;
	sc->fd = cmd; /* abuse 'fd' to store fcntl-suboperation */

	switch(cmd) {
	case F_GETFD:
	case F_GETFL:
		/* Simple fcntls, just store the result */
		sc->result = real_fcntl(fd, cmd);
		sc->err = errno;
		break;
	case F_SETFD:
	case F_SETFL:
		arg = va_arg(ap, long);
		sc->result = real_fcntl(fd, cmd, arg);
		sc->err = errno;
		break;

	default:
		error("unhandled fcntl %d", cmd);
	}
#endif
#ifdef PLAYBACK
	CHECK;
	if (sc->fd != cmd) 
		error("Caught different fcntl operation during playback (%d instead of %d)",
		      cmd, sc->fd);

	switch(cmd) {
	case F_SETFL:
	case F_SETFD:
	case F_GETFD:
	case F_GETFL:
		/* Simple fcntls, no extra work needed */
		break;
	default:
		error("unhandled fcntl %x", cmd);
	}
#endif

	RETURN(sc->result);
}

int ioctl(int d, int request, ...)
{
	void *ptr;
	va_list ap;
	va_start(ap, request);
	ptr = va_arg(ap, void*);
	va_end(ap);

	ENTRY("%d, %d, ... ", d, request);

	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	/* XXX - allow all ioctl's? */
	sc->result = real_ioctl(d, request, ptr);
	sc->err = errno;
	sc->number = IOCTL_NR;
#endif
#ifdef PLAYBACK
	CHECK;
#endif

	switch (request) {
	case 1074025674: // TUNSETIFF
		break;
	default:
		error("unhandled IOCTL %d", request, d);
	}

	RETURN(sc->result);
}


off64_t lseek64(int fd, off64_t offset, int whence)
{
	ENTRY("%d, %d, %d", fd, offset, whence);

	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result = (int64_t)real_lseek64(fd, offset, whence);
	sc->err = errno;
	sc->number = LSEEK64_NR;
#endif

#ifdef PLAYBACK
	CHECK;
#endif

	RETURN((off64_t)sc->result);
}

off_t lseek(int fd, off_t offset, int whence)
{
	UNUSED_FUNCTION;

	ENTRY("%d, %d, %d", fd, offset, whence);

	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result = real_lseek64(fd, offset, whence);
	sc->err = errno;
	sc->number = LSEEK64_NR;
#endif

#ifdef PLAYBACK
	CHECK;
#endif

	RETURN(sc->result);
}

/******************************************************************************
 *
 * 		SOCKET OPERATIONS
 *
 *****************************************************************************/
int socket(int domain, int type, int protocol)
{
	ENTRY("%d, %d, %d", domain, type, protocol);

	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result = real_socket(domain, type, protocol);
	sc->err = errno;
	sc->number = SOCKET_NR;
#endif

#ifdef PLAYBACK
	CHECK;
#endif

	RETURN(sc->result);
}

int bind(int fd, const struct sockaddr *addr, socklen_t len) 
{
	ENTRY("%d, ... , %d", fd, len);

	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result =  real_bind(fd, addr, len);
	sc->err = errno;
	sc->number = BIND_NR;
#endif

#ifdef PLAYBACK
	CHECK;
#endif

	RETURN(sc->result);
}

int connect(int fd, const struct sockaddr *addr, socklen_t len)
{
	ENTRY("%d, ..., %d", fd, len);

	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result = real_connect(fd, addr, len);
	sc->err = errno;
	sc->number = CONNECT_NR;
#endif

#ifdef PLAYBACK
	CHECK;
#endif

	RETURN(sc->result);
}

int listen(int fd, int n)
{
	ENTRY("%d, %d", fd, n);

	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result = real_listen(fd, n);
	sc->err = errno;
	sc->number = LISTEN_NR;
#endif

#ifdef PLAYBACK
	CHECK;
#endif

	RETURN(sc->result);
}

int accept(int fd, struct sockaddr *addr, socklen_t *len)
{
	ENTRY("%d, ...)", fd);

	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result = real_accept(fd, addr, len);
	sc->err = errno;
	sc->number = ACCEPT_NR;
#endif

#ifdef PLAYBACK
	CHECK;
#endif

	RETURN(sc->result);
}

int getsockname(int fd, struct sockaddr *addr, socklen_t *len)
{
	ENTRY("%d, ...)", fd);

	sc_info *sc = sc_info_next();

#ifdef CAPTURE

	sc->result =  real_getsockname(fd, addr, len);
	sc->err = errno;
	sc->number = GETSOCKNAME_NR;

	/* save arguments */
	sc->len = (int)*len;
	sc->ptr = alloc(sc->len);
	memcpy(sc->ptr, addr, sc->len);
#endif 

#ifdef PLAYBACK
	CHECK;

	/* restore arguments */
	*len = sc->len;
	memcpy(addr, sc->ptr, sc->len);
#endif

	RETURN(sc->result);
}

int getpeername (int s, struct sockaddr *addr, socklen_t *len)
{
	ENTRY("%d, ...", s);

	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result = real_getpeername(s, addr, len);
	sc->err = errno;
	sc->number = GETPEERNAME_NR;

	/* save arguments */
	sc->len = *len;
	sc->ptr = alloc(sc->len);
	memcpy(sc->ptr, addr, sc->len);
#endif
#ifdef PLAYBACK
	CHECK;

	/* restore arguments */
	*len = sc->len;
	memcpy(addr, sc->ptr, sc->len);
#endif

	RETURN(sc->result);
}

int socketpair(int d, int type, int protocol, int sv[2])
{
	UNUSED_FUNCTION;

	ENTRY("%d, %d, %d, ... ", d, type, protocol);

	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result = real_socketpair(d, type, protocol, sv);
	sc->err = errno;
	sc->number = SOCKETPAIR_NR;

	/* save arguments */
	sc->fd = sv[0];
	sc->fd2 = sv[1];
#endif
#ifdef PLAYBACK
	CHECK;

	/* restore arguments */
	sv[0] = sc->fd;
	sv[1] = sc->fd2;
#endif

	RETURN(sc->result);
}

ssize_t send(int s, const void *buf, size_t len, int flags)
{
	ENTRY("%d, .., %d, %d", s, len, flags);

	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result =  real_send(s, buf, len, flags);
	sc->err = errno;
	sc->number = SEND_NR;
#endif
#ifdef PLAYBACK
	CHECK;
#endif

	RETURN(sc->result);
}

ssize_t recv(int s, void *buf, size_t len, int flags)
{
	ENTRY("%d, ... , %d, %d", s, len, flags);

	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result = real_recv(s, buf, len, flags);
	sc->err = errno;
	sc->number = RECV_NR;

	/* Save arguments */
	sc->len = sc->result;
	sc->ptr = alloc(sc->len);
	memcpy(sc->ptr, buf, sc->len);
#endif
#ifdef PLAYBACK
	CHECK;

	/* restore arguments */
	memcpy(buf, sc->ptr, sc->len);
#endif

	RETURN(sc->result);
}

ssize_t sendto(int s, const void *buf, size_t len, int flags, const struct sockaddr *to, socklen_t tolen)
{
	ENTRY("%d, ... , %d, %d, ... , %d", s, len, flags, tolen);

	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result = real_sendto(s, buf, len, flags, to, tolen);
	sc->err = errno;
	sc->number = SENDTO_NR;
#endif
#ifdef PLAYBACK
	CHECK;
#endif

	RETURN(sc->result);
}

ssize_t recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen)
{
	ENTRY("%d, ... , %d, %d, ...)", s, len, flags);

	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result = real_recvfrom(s, buf, len, flags, from, fromlen);
	sc->err = errno;
	sc->number = RECVFROM_NR;

	/* save arguments - NOTE: hackery here. We must store two arbitrary sized data
	 *                  blocks here (buf and from). All this data must be availalbe
	 *                  in 'ptr' so it can be serialized (see sc_info_serialize).
	 *
	 *                  We concatenate the two data blobs in 'ptr', with struct sockaddr 
	 *                  *from first. Note that the result of the call (stored
	 *                  in sc->result) indicates the size of buf, and we abuse the 'fd' 
	 *                  field to store the size of the sockaddr. (socklen_t *fromlen).
	 */
	sc->len = *fromlen;
	sc->fd = *fromlen;

	if (sc->result > 0) 
		sc->len += sc->result; /* allocate size for 'buf' as well, if it exists */

	sc->ptr = alloc(sc->len);
	memcpy(sc->ptr, from, sc->fd); 

	/* only store contents of buf if the call actually returned data */
	if (sc->result > 0)
		memcpy(sc->ptr + sc->fd, buf, sc->result);
#endif

#ifdef PLAYBACK
	CHECK;

	/* Restore arguments - NOTE: hackery here, see above */
	memcpy(from, sc->ptr, sc->fd);

	/* Only restore contents of buf if it was actually there */
	if (sc->result > 0)
		memcpy(buf, sc->ptr + sc->fd, sc->result);
#endif

	RETURN(sc->result);

}

int shutdown(int s, int how)
{
	ENTRY("%d, %d", s, how);
	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result = real_shutdown(s, how);
	sc->err = errno;
	sc->number = SHUTDOWN_NR;
#endif

#ifdef PLAYBACK
	CHECK;

	if (sc->fd != s)
		error("supplied argument to shutdown() not correct (saved: %d, stored: %d)",
		      sc->fd, s);
#endif

	RETURN(sc->result);
}

int setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen)
{
	ENTRY("%d, %d, %d, ... , %d", s, level, optname, optlen);

	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result = real_setsockopt(s, level, optname, optval, optlen);
	sc->err = errno;
	sc->number = SETSOCKOPT_NR;
#endif

#ifdef PLAYBACK
	CHECK;
#endif

	RETURN(sc->result);
}

int getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen)
{
	ENTRY("%d, %d, %d",  level, optname, optval);

	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result = real_getsockopt(s, level, optname, optval, optlen);
	sc->err = errno;
	sc->number = GETSOCKOPT_NR;

	/* save arguments */
	sc->len = *optlen;
	sc->ptr = alloc(sc->len);
	memcpy(sc->ptr, optval, sc->len);
#endif
#ifdef PLAYBACK
	CHECK;

	/* restore arguments */
	*optlen = sc->len;
	memcpy(optval, sc->ptr, sc->len);
#endif

	RETURN(sc->result);
}

ssize_t sendmsg(int s, const struct msghdr *msg, int flags)
{
	ENTRY("%d, ... , %d", s, flags);

	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result = real_sendmsg(s, msg, flags);
	sc->err = errno;
	sc->number = SENDMSG_NR;
#endif
#ifdef PLAYBACK
	CHECK;
#endif

	RETURN(sc->result);
}

ssize_t recvmsg(int s, struct msghdr *msg, int flags)
{
	ENTRY("%d, ... , %d", s, flags);

	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result = real_recvmsg(s, msg, flags);
	sc->err = errno;
	sc->number = RECVMSG_NR;

	/* save arguments */
	sc->len = sizeof(struct msghdr);
	sc->ptr = alloc(sc->len);
	memcpy(sc->ptr, msg, sc->len);
#endif

#ifdef PLAYBACK
	CHECK;

	/* restore argument */
	memcpy(msg, sc->ptr, sc->len);
#endif

	RETURN(sc->result);
}


/******************************************************************************
 *
 * 		FILE-DESCRIPTOR YIELDING CALLS
 *
 ******************************************************************************/
int pipe(int fd[2])
{
	UNUSED_FUNCTION;
	ENTRY("%s", "...");

	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result = real_pipe(fd);
	sc->err = errno;
	sc->number = PIPE_NR;

	/* save arguments */
	sc->fd = fd[0];
	sc->fd2 = fd[1];
#endif
#ifdef PLAYBACK
	CHECK;

	/* restore arguments */
	fd[0] = sc->fd;
	fd[1] = sc->fd2;
#endif

	RETURN(sc->result);
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	ENTRY("...,  %d, %d", nfds, timeout);
	int i;
	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result = real_poll(fds, nfds, timeout);
	sc->err = errno;
	sc->number = POLL_NR;

	sc->fd = nfds; /* abuse fd to store number of fds */
	sc->len = (nfds * sizeof(struct pollfd));
	sc->ptr = alloc(sc->len);

	for(i=0; i<nfds; i++)
		memcpy(sc->ptr + (i*sizeof(struct pollfd)), (void*)(fds+i), sizeof(struct pollfd));
#endif
#ifdef PLAYBACK
	CHECK;
	if (nfds != sc->fd)
		error("Invalid number of pollfd's during playback (%d instead of %d)",
		      nfds, sc->fd);

	for(i=0; i<nfds;i++)
		memcpy((void*)(fds+i), sc->ptr + (i*sizeof(struct pollfd)), sizeof(struct pollfd));
#endif

	RETURN(sc->result);
}


/*******************************************************************************
 *
 * 		TIME-RELATED SYSTEM CALLS
 *
 *******************************************************************************/

time_t time(time_t *t)
{
	ENTRY("%s", "...");

	sc_info *sc = sc_info_next();
#ifdef CAPTURE
	time_t result;

	sc->err = errno;
	sc->len = sizeof(time_t);
	sc->ptr = alloc(sc->len);

	result = real_time(t);
	sc->number = TIME_NR;
	memcpy(sc->ptr, &result, sizeof(time_t));
#endif
#ifdef PLAYBACK
	CHECK;

	if (t) {
		memcpy(t, sc->ptr, sizeof(time_t));
	}
#endif

	//RETURN(*((time_t*)(sc->ptr));
	dump("0x%ld (errno: %d)\n", *((time_t*)(sc->ptr)) , sc->err); 
	errno = sc->err; 
	return *((time_t*)(sc->ptr));
}

int timer_create(clockid_t clockid, 
		 struct sigevent *evp,
		 timer_t *timerid) 
{
	ENTRY("%d,...", clockid);

	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result = real_timer_create(clockid, evp, timerid);
	sc->err = errno;
	sc->number = TIMER_CREATE_NR;

	sc->len = sizeof(struct sigevent) + sizeof(timer_t);
	sc->ptr = alloc(sc->len);
	sc->fd = 0;

	if (evp) {
		sc->fd |= 0x1;
		memcpy(sc->ptr, evp, sizeof(struct sigevent));
	}
	if (timerid) {
		sc->fd |= 0x2;
		memcpy(sc->ptr + sizeof(struct sigevent), timerid, sizeof(timer_t));
	}
#endif
#ifdef PLAYBACK
	CHECK; 

	if (sc->fd & 0x1) {
		if (evp) {
			sc->fd &= ~0x1;
			memcpy(evp, sc->ptr, sizeof(struct sigevent));
		} else {
			error("timer_create: stored 'sigevent' info, not requested during playback");
		}
	}
	if (sc->fd & 0x2) {
		if (timerid) {
			sc->fd &= ~0x2;
			memcpy(timerid, sc->ptr + sizeof(struct sigevent), sizeof(timer_t));
		} else {
			error("timer_create: stored 'timerid' info, not requested during playback");
		}
	}
	if (sc->fd) {
		error("timer_create: Invalid flag set");
	}
#endif

	RETURN(sc->result);
}

int timer_delete(timer_t timerid)
{
	ENTRY("%d", timerid);

	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result = real_timer_delete(timerid);
	sc->err = errno;
	sc->number = TIMER_DELETE_NR;
#endif
#ifdef PLAYBACK
	CHECK;
#endif
	RETURN(sc->result);
}

int timer_gettime(timer_t timerid, struct itimerspec *value)
{
	ENTRY("%d", timerid);
	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result = real_timer_gettime(timerid, value);
	sc->err = errno;
	sc->number= TIMER_GETTIME_NR;
	sc->len = 0;

	if (value) {
		sc->len = sizeof(struct itimerspec);
		sc->ptr = alloc(sc->len);
		memcpy(sc->ptr, value, sizeof(struct itimerspec));
	}
#endif

#ifdef PLAYBACK
	CHECK;

	if (sc->len && value) {
		memcpy(value, sc->ptr, sizeof(struct itimerspec));
	} else if (sc->len || value){ 
		error("timer_getttime: argument mismatch");
	} 
#endif
	RETURN(sc->result);
}

int timer_settime(timer_t timerid, 
		  int flags,
		  const struct itimerspec *value,
		  struct itimerspec *ovalue) 
{
	ENTRY("%d, %d, ...", timerid, flags);
	sc_info *sc = sc_info_next();
	
#ifdef CAPTURE
	sc->result = real_timer_settime(timerid, flags, value, ovalue);
	sc->err = errno;
	sc->number = TIMER_SETTIME_NR;
	sc->len = 0;

	if (ovalue) {
		sc->len = sizeof(struct itimerspec);
		sc->ptr = alloc(sc->len);
		memcpy(sc->ptr, ovalue, sizeof(struct itimerspec));
	}
#endif
#ifdef PLAYBACK
	CHECK;

	if (sc->len && ovalue) {
		memcpy(ovalue, sc->ptr, sizeof(struct itimerspec));
	} else if (sc->len || ovalue) {
		error("timer_settime: argument mismatch");
	}
#endif

	RETURN(sc->result);
}

int clock_gettime(clockid_t clk_id, struct timespec *tp)
{
	ENTRY("%d, ... ", clk_id);

	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result = real_clock_gettime(clk_id, tp);
	sc->err = errno;
	sc->number = CLOCK_GETTIME_NR;

	sc->len = 0;	
	if (tp) {
		sc->len = sizeof(struct timespec);
		sc->ptr = alloc(sc->len);
		memcpy(sc->ptr, tp, sizeof(struct timespec));
	}
#endif
#ifdef PLAYBACK
	CHECK;
	
	if (sc->len && tp) {
		memcpy(tp, sc->ptr, sizeof(struct timespec));
	} else if (sc->len && !tp) {
		error("clock_gettime: stored timespec info but not requested during playback");
	} else if (!sc->len && tp) {
		error("clock_gettime: No stored timespec but requested during playback nonetheless");
	}
#endif
	
	RETURN(sc->result);
}

int gettimeofday(struct timeval *tv, struct timezone *tz)
{
	ENTRY("%s", "...");

	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	sc->result = real_gettimeofday(tv, tz);
	sc->err = errno;
	sc->number = GETTIMEOFDAY_NR;

	/* Save the structures in sc->ptr */
	sc->len = sizeof(struct timeval) + sizeof(struct timezone);
	sc->ptr = alloc(sc->len);
	sc->fd = 0;

	if (tv) { /* Abuse 'fd' fields to indicate wether 'tv' and 'tz' 
		     have a meaningful value */
		sc->fd |= 0x1 ;
		memcpy(sc->ptr, tv, sizeof(struct timeval));
	}
	if (tz) {
		sc->fd |= 0x2;
		memcpy(sc->ptr+sizeof(struct timeval), tz, sizeof(struct timezone));
	}
#endif
#ifdef PLAYBACK
	CHECK;

	if(sc->fd & 0x1)  {
		if (tv) {
			sc->fd &= ~0x1;
			memcpy(tv, sc->ptr, sizeof(struct timeval));
		} else {
			error("gettimeofday 'timeval' struct stored but not requested");
		}
	}

	if (sc->fd & 0x2)  {
		if (tz) {
			sc->fd &= ~0x2;
			memcpy(tz, sc->ptr + sizeof(struct timeval), sizeof(struct timezone));
		} else {
			error("gettimeofday 'timezone' struct stored but not requested");
		}
	}

	if (sc->fd) 
		error("gettimeofday call mismatch: fd : %d",sc->fd);

#endif

	RETURN(sc->result);
}


int64_t replay_deterministic_get_real_ticks(void)
{
	int64_t val;
	ENTRY("%s", "...");

	sc_info *sc = sc_info_next();

#ifdef CAPTURE
	asm volatile ("rdtsc" : "=A" (val));
	sc->number = RDTSC_NR;
	sc->result = val;
#endif

#ifdef PLAYBACK
	if (sc->number != RDTSC_NR)
		error("not expected rdtsc call");

	val = sc->result;
#endif

	//RETURN((int64_t)val);
	dump("%" PRId64 "\n", val); 
	return val;
}

/*******************************************************************************
 *
 * 		NOT IMPLEMENTED SYSTEM CALLS
 *
 *******************************************************************************/
int epoll_create(int size)
{
	error("epoll_create");
	exit(1);/*notreached*/
}

int dup(int oldfd)
{
	error("dup");
	exit(1);/*notreached*/
}

int dup2(int oldfd, int newfd)
{
	error("dup2");
	exit(1);/*notreached*/
}

FILE *freopen(const char *path, const char *mode, FILE *stream)
{
	error("freopen");
	exit(1);
}

int fcloseall(void)
{
	error("%s!", __FUNCTION__);
	exit(1);
}

int ftruncate(int fd, off_t len)
{
	error("%s!", __FUNCTION__);
	exit(1);
}

pid_t waitpid(pid_t pid, int *status, int options)
{
	error("%s!", __FUNCTION__);
	exit(1);
}

int execvp(const char* file, char* const argv[])
{
	error("execvp");
	exit(1); /*notreached*/
}
int execv(const char* file, char* const argv[])
{
	error("execv");
	exit(1); /*notreached*/
}

int openat(int dirfd, const char *pathname, int flags, ...)
{
	error("openat");
	exit(1);/*notreached*/
}

FILE *tmpfile64(void)
{
	error("tmpfile");
	exit(1);/*notreached*/
}

FILE *tmpfile(void)
{
	error("tmpfile");
	exit(1);/*notreached*/
};

int fgetc(FILE *stream)
{
	error("fgetc");
	exit(1);
}

ssize_t pread(int fd, void *buf, size_t count, off_t offset)
{
	error("pread");
	exit(1);/*notreached*/
}

int getitimer(__itimer_which_t which, struct itimerval *val)
{
	error("setitimer");
	exit(1);
}

int setitimer(__itimer_which_t which, const struct itimerval *val, struct itimerval *ovalue)
{
	error("getitimer");
	exit(1);
}

ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset)
{
	error("pwrite");
	exit(1);/*notreached*/
}

int lstat64(const char *path, struct stat64 *buf)
{
	error("lstat64");
	exit(1);
}

/*******************************************************************************
 *
 * 		SIGNALS
 *
 *******************************************************************************/
/* All signal actions are quietly dropped. This can be done because
 * the program that this library attaces too (qemu-notimers) is
 * adjusted to no longer depend on signals 
 *
 * Overloading various signal functions is simpler than removing the signal-
 * handling code from qemu-notimers.
 */
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
	return 0;
}

int sigemptyset(sigset_t *set)
{
	return 0;
}

int sigaddset(sigset_t *set, int signum)
{
	return 0;
}

int sigfillset(sigset_t *set)
{
	return 0;
}

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
	return 0;
}

int sigwait(const sigset_t *set, int *sig)
{
	return 0;
}

sighandler_t signal(int signum, sighandler_t handler)
{
	return 0;
}


/*******************************************************************************
 *
 * 		UTILITY 
 *
 *******************************************************************************/

/* This macro takes the name of a function as an argument, and
 * generates the code for 'real_function', which can be used
 * to call the real version of the system call. This interface
 * is exported by replay.h, so applications who want to call
 * overloaded functions without them being captured or replayed
 * can use these. Furthermore, the real_* functions are used 
 * internally during capture to obtain the required inputs.
 *
 * TODO: seems the exported 'real_<function>' functions
 * do not work currently.
 */
#define BUILD_FUNCTION(n)		do { \
						real_##n = dlsym(RTLD_NEXT,  #n ); \
						if (!real_##n) error("dlsym(%s) failed", #n);\
					} while(0)


void init_library_calls()		
{
	BUILD_FUNCTION(accept);
	BUILD_FUNCTION(bind);
	BUILD_FUNCTION(clock_gettime);
	BUILD_FUNCTION(close);
	BUILD_FUNCTION(connect);
	BUILD_FUNCTION(fcntl);
	BUILD_FUNCTION(getpeername);
	BUILD_FUNCTION(getsockname);
	BUILD_FUNCTION(getsockopt);
	BUILD_FUNCTION(gettimeofday);
	BUILD_FUNCTION(ioctl);
	BUILD_FUNCTION(listen);
	BUILD_FUNCTION(lseek64);
	BUILD_FUNCTION(mkstemp);
	BUILD_FUNCTION(mmap64);
	BUILD_FUNCTION(open64);
	BUILD_FUNCTION(pipe);
	BUILD_FUNCTION(poll);
	BUILD_FUNCTION(read);
	BUILD_FUNCTION(readv);
	BUILD_FUNCTION(recv);
	BUILD_FUNCTION(recvfrom);
	BUILD_FUNCTION(recvmsg);
	BUILD_FUNCTION(select);
	BUILD_FUNCTION(send);
	BUILD_FUNCTION(sendmsg);
	BUILD_FUNCTION(sendto);
	BUILD_FUNCTION(setsockopt);
	BUILD_FUNCTION(signal);
	BUILD_FUNCTION(shutdown);
	BUILD_FUNCTION(socket);
	BUILD_FUNCTION(socketpair);
	BUILD_FUNCTION(time);
	BUILD_FUNCTION(timer_create);
	BUILD_FUNCTION(timer_delete);
	BUILD_FUNCTION(timer_gettime);
	BUILD_FUNCTION(timer_settime);
	BUILD_FUNCTION(write);
	BUILD_FUNCTION(writev);
}
