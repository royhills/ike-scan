/* Includes */
#include <stdarg.h>
#include <netinet/in.h>
#include <sys/time.h>
#include "isakmp.h"

/* Defines */

#define MAXLINE 255			/* Max line length for input files */
#define MAXUDP 65507			/* Max UDP data size = 64k - 20 - 8 */
#define DEFAULT_SELECT_TIMEOUT 10	/* Default select timeout in ms */
#define DEFAULT_BACKOFF_FACTOR 1.5	/* Default timout backoff factor */
#define DEFAULT_RETRY 3			/* Default number of retries */
#define DEFAULT_TIMEOUT 500		/* Default per-host timeout in ms */
#define DEFAULT_INTERVAL 25		/* Default delay between packets (ms) */
#define DEFAULT_SOURCE_PORT 500		/* Default UDP source port */
#define DEFAULT_DEST_PORT 500		/* Default UDP destination port */
#define DEFAULT_LIFETIME 28800		/* Default lifetime in seconds */
#define DEFAULT_AUTH_METHOD 1		/* Default authentication method */

/* Structures */
struct host_entry {
   struct host_entry *prev;	/* Previous pointer */
   struct host_entry *next;	/* Next pointer */
   int n;			/* Ordinal number for this entry */
   struct in_addr addr;		/* Host IP address */
   u_char live;			/* Set when awaiting response */
   struct timeval last_send_time; /* Time when last packet sent to this addr */
   unsigned timeout;		/* Timeout for this host */
   unsigned num_sent;		/* Number of packets sent */
   unsigned num_recv;		/* Number of packets received */
   u_int32_t icookie[COOKIE_SIZE];	/* IKE Initiator cookie */
};

/* Functions */

void err_sys(const char *, ...);
void warn_sys(const char *, ...);
void err_msg(const char *, ...);
void warn_msg(const char *, ...);
void info_syslog(const char *, ...);
void err_print(int, int, const char *, va_list);
char *cpystr(char *string);
void usage(void);
void add_host(char *);
void send_packet(int, struct host_entry *);
int recvfrom_wto(int, char *, int, struct sockaddr *, int);
void remove_host(struct host_entry *);
unsigned long timeval_diff(struct timeval *, struct timeval *);
void initialise_ike_packet(void);
struct host_entry *find_host_by_ip(struct host_entry *, struct in_addr *);
void display_packet(int, char *, struct host_entry *);
