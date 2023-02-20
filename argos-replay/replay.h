#ifndef _REPLAY_H_
#define _REPLAY_H_

#define SC_INFO_SZ 200

/* 
 * Definition of the global datastructure. This structure contains 
 * enough information about systemcalls so that they can be replayed
 * later on.
 *
 * Generic structure is to store the number of the call in 'number', 
 * the returned value (generally an int) in 'result', and the errno
 * value at the time of return in 'err'. (We save errno even if the
 * function did not set it, since the calling program might depend
 * (wrongly) on its value.
 *
 * Any other information needed to be saved is copied in a (separately
 * allocated) buffer pointed at by 'ptr'. The size of this buffer is
 * noted in 'len'.
 */
typedef struct sc_info_t {
	int number;
	int64_t result;
	int err;

	void *ptr;
	int len;

	int fd;
	int fd2;
} sc_info;


/* Map number to name */
const char *sc_names[] = 
{
	"restart-syscall",
	"accept",
	"bind",
	"clock_gettime",
	"close",
	"connect",
	"fcntl",
	"getpeername",
	"getsockname",
	"getsockopt",
	"gettimeofday",
	"ioctl",
	"listen",
	"lseek64",
	"mkstmp",
	"mmap64",
	"open64",
	"pipe",
	"poll",
	"read",
	"readv",
	"recvfrom",
	"recv",
	"recvmsg",
	"select",
	"send",
	"sendmsg",
	"sendto",
	"setsockopt",
	"signal",
	"shutdown",
	"socket",
	"socketpair",
	"time",
	"timer_create",
	"timer_delete",
	"timer_gettime",
	"timer_settime",
	"write",
	"writev",
	"rdtsc",
};


#define  ACCEPT_NR		1
#define  BIND_NR		2
#define  CLOCK_GETTIME_NR	3
#define  CLOSE_NR		4
#define  CONNECT_NR		5
#define  FCNTL_NR		6
#define  GETPEERNAME_NR		7
#define  GETSOCKNAME_NR		8
#define  GETSOCKOPT_NR		9
#define  GETTIMEOFDAY_NR	10
#define  IOCTL_NR		11
#define  LISTEN_NR		12
#define  LSEEK64_NR		13
#define  MKSTEMP_NR		14
#define  MMAP64_NR		15
#define  OPEN64_NR		16
#define  PIPE_NR		17
#define  POLL_NR		18
#define  READ_NR		19
#define  READV_NR		20
#define  RECVFROM_NR		21
#define  RECV_NR		22
#define  RECVMSG_NR		23
#define  SELECT_NR		24
#define  SEND_NR		25
#define  SENDMSG_NR		26
#define  SENDTO_NR		27
#define  SETSOCKOPT_NR		28
#define  SIGNAL_NR		29
#define  SHUTDOWN_NR		30
#define  SOCKET_NR		31
#define  SOCKETPAIR_NR		32
#define  TIME_NR		33
#define  TIMER_CREATE_NR	34
#define  TIMER_DELETE_NR	35
#define  TIMER_GETTIME_NR	36
#define  TIMER_SETTIME_NR	37
#define  WRITE_NR		38
#define  WRITEV_NR		39
#define  RDTSC_NR		40

#define  NUMBER_OF_CALLS	40

/* Export access to real versions of overloaded functions */
int	(*real_accept)		(int,struct sockaddr *,socklen_t*);
int 	(*real_bind)		(int,const struct sockaddr *,socklen_t);
int 	(*real_clock_gettime)	(clockid_t, struct timespec *);
int 	(*real_close)		(int);
int 	(*real_connect)		(int,const struct sockaddr *,socklen_t);
int 	(*real_fcntl)		(int, int, ...);
int 	(*real_getpeername)	(int,struct sockaddr *,socklen_t *);
int 	(*real_getsockname)	(int,struct sockaddr *, socklen_t *);
int 	(*real_getsockopt)	(int,int,int,void*, socklen_t *);
int 	(*real_gettimeofday)	(struct timeval*, struct timezone*);
int 	(*real_ioctl)		(int, int, ...);
int 	(*real_listen)		(int,int);
off64_t	(*real_lseek64)		(int, off64_t, int);
int 	(*real_mkstemp)		(char *);
void* 	(*real_mmap64)		(void*, size_t, int, int, int, off64_t);
int 	(*real_open64)		(const char*, int, ...);
int 	(*real_pipe)		(int[]);
int 	(*real_poll)		(struct pollfd*, nfds_t, int);
ssize_t (*real_read)		(int, char*, size_t);
ssize_t (*real_readv)		(int, const struct iovec*, int);
ssize_t (*real_recvfrom)	(int,void *,size_t, int, struct sockaddr *, socklen_t *);
ssize_t (*real_recv)		(int,void*,size_t,int);
int 	(*real_recvmsg)		(int,struct msghdr *,int);
int 	(*real_select)		(int, fd_set*, fd_set*, fd_set*, struct timeval *);
ssize_t (*real_send)		(int,const void*,size_t,int);
int 	(*real_sendmsg)		(int,const struct msghdr *, int);
ssize_t (*real_sendto)		(int,const void*,size_t,int, const struct sockaddr *, socklen_t);
int 	(*real_setsockopt)	(int,int,int,const void*, socklen_t);
sighandler_t (*real_signal)	(int signum, sighandler_t handler);
int 	(*real_shutdown)	(int,int);
int 	(*real_socket)		(int,int,int);
int 	(*real_socketpair)	(int,int,int,int[]);
time_t 	(*real_time)		(time_t *);
int 	(*real_timer_create)	(clockid_t, struct sigevent *, timer_t *);
int 	(*real_timer_delete)	(timer_t);
int 	(*real_timer_gettime)	(timer_t, struct itimerspec*);
int 	(*real_timer_settime)	(timer_t, int, const struct itimerspec*, struct itimerspec*);
ssize_t (*real_write)		(int, const void*, size_t);
ssize_t (*real_writev)		(int, const struct iovec*, int);

#endif /* _REPLAY_H_ */
