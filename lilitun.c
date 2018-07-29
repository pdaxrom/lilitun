/**************************************************************************
 * simpletun.c                                                            *
 *                                                                        *
 * A simplistic, simple-minded, naive tunnelling program using tun/tap    *
 * interfaces and TCP. DO NOT USE THIS PROGRAM FOR SERIOUS PURPOSES.      *
 *                                                                        *
 * You have been warned.                                                  *
 *                                                                        *
 * (C) 2010 Davide Brini.                                                 *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for learning     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
 *************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <pthread.h>
#include <signal.h>
#include <syslog.h>
#include "aes.h"
#include "lilitun.h"
#include "http.h"
#include "utils.h"
#include "getrandom.h"
#include "conn-tunnel.h"

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define CLIENT 0
#define SERVER 1
#define PORT 80

char *progname;

char server_id[6] = "lilith";
char client_id[6] = "htilil";

aes_context aes_ctx;
uint8 aes_key[256];

/*

 */

void dump16(char *ptr)
{
    int i;
    char tmp[128];

    memset(tmp, ' ', sizeof(tmp));
    tmp[127] = 0;

    for (i = 0; i < 16; i++) {
//      syslog(LOG_DEBUG, "%02X ", (unsigned char)ptr[i]);
	snprintf(&tmp[i * 3], 4, "%02X ", (unsigned char)ptr[i]);
	tmp[49 + i] = (ptr[i] >= 32) ? ptr[i] : '.';
    }
    tmp[48] = ' ';
    tmp[65] = 0;
    syslog(LOG_DEBUG, "DUMP16: %s\n", tmp);
}

void dump_SrcDst(char *p)
{
    uint8_t *ptr = (uint8_t *)p;
    syslog(LOG_DEBUG, "Packet: Src: %d.%d.%d.%d Dst: %d.%d.%d.%d\n", ptr[12], ptr[13], ptr[14], ptr[15], ptr[16], ptr[17], ptr[18], ptr[19]);
}

/**************************************************************************
 * init_aes: AES key initialization                                       *
 **************************************************************************/
int init_aes(char *keyfile)
{
    FILE *inf = fopen(keyfile, "rb");
    if (inf) {
	int size = fread(aes_key, 1, sizeof(aes_key), inf);
	if ((size != 16) && (size != 24) && (size != 32)) {
	    syslog(LOG_ERR, "Key must be 16, 24 or 32 bytes! AES disabled.\n");
	    fclose(inf);
	    return 0;
	}
	fclose(inf);
	aes_set_key(&aes_ctx, aes_key, size * 8);
	syslog(LOG_INFO, "Use AES-%d.\n", size * 8);
    } else {
	syslog(LOG_ERR, "Can't open key file! AES disabled.\n");
	return 0;
    }
    return 1;
}

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            must reserve enough space in *dev.                          *
 **************************************************************************/
int tun_alloc(char *dev, int flags)
{

    struct ifreq ifr;
    int fd, err;
    char *clonedev = "/dev/net/tun";

    if ((fd = open(clonedev, O_RDWR)) < 0) {
	syslog(LOG_ERR, "Opening /dev/net/tun (%s)\n", strerror(errno));
	return fd;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags;

    if (*dev) {
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
	syslog(LOG_ERR, "ioctl(TUNSETIFF) (%s)\n", strerror(errno));
	close(fd);
	return err;
    }

    strcpy(dev, ifr.ifr_name);

    return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n)
{

    int nread;

    if ((nread = read(fd, buf, n)) < 0) {
	syslog(LOG_ERR, "Reading data (%s)\n", strerror(errno));
    }
    return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n)
{

    int nwrite;

    if ((nwrite = write(fd, buf, n)) < 0) {
	syslog(LOG_ERR, "Writing data (%s)\n", strerror(errno));
    }
    return nwrite;
}

/**************************************************************************
 * server_thread:                                                       *
 **************************************************************************/
static void *server_thread(void *arg)
{
    server_arg *sarg = (server_arg *) arg;
    int connection_is_alive = 1;

    pthread_detach(pthread_self());

    if (generate_session_key(sarg) < 0) {
	connection_is_alive = 0;
    }

    while (connection_is_alive) {
	char header[2048];
	char h_method[16];
	char h_url[256];
	char h_spec[16];

	int nread = cread(sarg->net_fd, header, sizeof(header));
	if (nread <= 0) {
	    syslog(LOG_ERR, "[%s] No more data read in server_thread (%s)\n", sarg->client_ip, strerror(errno));
	    break;
	}
	if (sarg->debug) {
	    syslog(LOG_DEBUG, "[%s] HTTP read: [\n%s\n]\n", sarg->client_ip, header);
	}

	header_get_method(header, h_method, sizeof(h_method));
	header_get_url(header, h_url, sizeof(h_url));
	header_get_spec(header, h_spec, sizeof(h_spec));

	syslog(LOG_INFO, "[%s] METHOD: '%s' URL: '%s' SPEC: '%s'\n", sarg->client_ip, h_method, h_url, h_spec);

	if (!strcmp(h_method, "GET") || !strcmp(h_method, "HEAD")) {
	    char *path;
	    char *file_path;
	    char *tmp_path;
	    struct stat sb;
	    int head_only = (!strcmp(h_method, "HEAD")) ? 1 : 0;

	    path = url_get_path(h_url, NULL, 0);

	    tmp_path = malloc(strlen(sarg->web_prefix) + 5 + strlen(path) + 1);	// prefix + "/www/" + path + '\0'
	    tmp_path[0] = 0;

	    strcat(tmp_path, sarg->web_prefix);
	    strcat(tmp_path, "/www/");
	    strcat(tmp_path, path);

	    file_path = realpath(tmp_path, NULL);

	    free(tmp_path);
	    free(path);

	    if (file_path) {
		if (stat(file_path, &sb) == -1) {
		    syslog(LOG_ERR, "[%s] %s %d: stat() (%s)\n", sarg->client_ip, __FILE__, __LINE__, strerror(errno));
		} else {
		    if ((sb.st_mode & S_IFMT) == S_IFDIR) {
			char *tmp = realloc(file_path, strlen(file_path) + 11);	// file_path + "/index.html"
			if (tmp) {
			    file_path = tmp;
			} else {
			    syslog(LOG_ERR, "[%s] %s %d: Not enought memory for file_path realloc()?\n", sarg->client_ip,
				   __FILE__, __LINE__);
			}
			strcat(file_path, "/index.html");
		    }
		}
		tmp_path = realpath(file_path, NULL);
		free(file_path);
		file_path = tmp_path;
	    }

	    if (file_path && !strncmp(file_path, sarg->web_prefix, strlen(sarg->web_prefix))) {
		syslog(LOG_INFO, "[%s] File found: %s\n", sarg->client_ip, file_path);
		send_file(sarg, file_path, head_only);
		if (file_path) {
		    free(file_path);
		}
	    } else {
		syslog(LOG_INFO, "[%s] File not found\n", sarg->client_ip);
		send_error(sarg, 404, "Not found");
		if (file_path) {
		    free(file_path);
		}
	    }
	} else if (!strcmp(h_method, "CONNECT")) {
	    server_tunnel(sarg, h_url);
	    break;
	} else {
	    syslog(LOG_INFO, "[%s] http error: Not Implemented\n", sarg->client_ip);
	    send_error(sarg, 501, "Not Implemented");
	    break;
	}
    }

    free_session_key(sarg);

    close(sarg->net_fd);
    close(sarg->tap_fd);

    syslog(LOG_INFO, "[%s] Server thread finished!\n", sarg->client_ip);

    pthread_mutex_destroy(&sarg->mutex_net_write);
    free(sarg->client_ip);
    free(sarg);

    return arg;
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-k <keyfile>] [-u|-a] [-w /path/to/www] [-n <webserver name>] [-d] [-e]\n", progname);
    fprintf(stderr, "%s -h\n", progname);
    fprintf(stderr, "\n");
    fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
    fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
    fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
    fprintf(stderr, "-k <keyfile>: aes key 16, 24 or 32 bytes\n");
    fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
    fprintf(stderr, "-w: path to web directories (/opt/lilitun by default)\n");
    fprintf(stderr, "-n: web server name (Apache/2.4.18 (Ubuntu) by default)\n");
    fprintf(stderr, "-d: outputs debug information while running\n");
    fprintf(stderr, "-e: print syslog messages to stderr\n");
    fprintf(stderr, "-h: prints this help text\n");
    exit(1);
}

int main(int argc, char *argv[])
{

    int option;
    int flags = IFF_TUN;
    char if_name[IFNAMSIZ] = "";
    struct sockaddr_in local, remote;
    char remote_ip[16] = "";	/* dotted quad IP string */
    unsigned short int port = PORT;
    int sock_fd, net_fd, optval = 1;
    socklen_t remotelen;
    int cliserv = -1;		/* must be specified on cmd line */
    int use_aes = 0;
    int debug = 0;
    int use_stderr = 0;
    char *web_prefix = "/opt/lilitun";
    char *server_name = "Apache/2.4.18 (Ubuntu)";

    progname = argv[0];

    openlog("lilitun", LOG_PID, LOG_DAEMON);

    /* Check command line options */
    while ((option = getopt(argc, argv, "i:sc:p:k:w:n:uahde")) > 0) {
	switch (option) {
	case 'd':
	    debug = 1;
	    break;
	case 'h':
	    usage();
	    break;
	case 'i':
	    strncpy(if_name, optarg, IFNAMSIZ - 1);
	    break;
	case 's':
	    cliserv = SERVER;
	    break;
	case 'c':
	    cliserv = CLIENT;
	    strncpy(remote_ip, optarg, 15);
	    break;
	case 'p':
	    port = atoi(optarg);
	    break;
	case 'u':
	    flags = IFF_TUN;
	    break;
	case 'a':
	    flags = IFF_TAP;
	    break;
	case 'k':
	    use_aes = init_aes(optarg);
	    break;
	case 'w':
	    web_prefix = optarg;
	    break;
	case 'n':
	    server_name = optarg;
	    break;
	case 'e':
	    use_stderr = 1;
	    break;
	default:
	    fprintf(stderr, "Unknown option %c\n", option);
	    usage();
	}
    }

    argv += optind;
    argc -= optind;

    if (argc > 0) {
	if (!use_stderr) {
	    fprintf(stderr, "Too many options!\n");
	}
	syslog(LOG_ERR, "Too many options!\n");
	usage();
    }

    if (*if_name == '\0') {
	if (!use_stderr) {
	    fprintf(stderr, "Must specify interface name!\n");
	}
	syslog(LOG_ERR, "Must specify interface name!\n");
	usage();
    } else if (cliserv < 0) {
	if (!use_stderr) {
	    fprintf(stderr, "Must specify client or server mode!\n");
	}
	syslog(LOG_ERR, "Must specify client or server mode!\n");
	usage();
    } else if ((cliserv == CLIENT) && (*remote_ip == '\0')) {
	if (!use_stderr) {
	    fprintf(stderr, "Must specify server address!\n");
	}
	syslog(LOG_ERR, "Must specify server address!\n");
	usage();
    }

    /* Ignore PIPE signal and return EPIPE error */
    signal(SIGPIPE, SIG_IGN);

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	syslog(LOG_ERR, "Can not create socket (%s)\n", strerror(errno));
	exit(1);
    }

    if (cliserv == CLIENT) {
	/* assign the destination address */
	memset(&remote, 0, sizeof(remote));
	remote.sin_family = AF_INET;
	remote.sin_addr.s_addr = inet_addr(remote_ip);
	remote.sin_port = htons(port);

	/* connection request */
	if (connect(sock_fd, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
	    syslog(LOG_ERR, "Can not connect to server (%s)\n", strerror(errno));
	    exit(1);
	}

	net_fd = sock_fd;
	syslog(LOG_INFO, "Connected to server %s\n", inet_ntoa(remote.sin_addr));

	server_arg *sarg = malloc(sizeof(server_arg));
	sarg->net_fd = net_fd;
	sarg->tap_if_name = if_name;
	sarg->tap_flags = flags;
	sarg->use_aes = use_aes;
	sarg->aes_ctx = &aes_ctx;
	sarg->server_name = server_name;
	sarg->web_prefix = web_prefix;
	sarg->debug = debug;
	sarg->mode = cliserv;
	sarg->ping_time = 10;
	pthread_mutex_init(&sarg->mutex_net_write, NULL);

	if (use_aes) {
	    client_tunnel(sarg);
	} else {
	    syslog(LOG_ERR, "Only secure connection enabled!\n");
	}

	pthread_mutex_destroy(&sarg->mutex_net_write);

	close(sarg->tap_fd);

	free(sarg);
    } else {
	/* avoid EADDRINUSE error on bind() */
	if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0) {
	    syslog(LOG_ERR, "Can not set socket options (%s)\n", strerror(errno));
	    exit(1);
	}

	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = htonl(INADDR_ANY);
	local.sin_port = htons(port);
	if (bind(sock_fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
	    syslog(LOG_ERR, "Bind error (%s)\n", strerror(errno));
	    exit(1);
	}

	if (listen(sock_fd, 5) < 0) {
	    syslog(LOG_ERR, "Listen error (%s)\n", strerror(errno));
	    exit(1);
	}

	while (1) {
	    pthread_t tid;
	    server_arg *sarg;

	    /* wait for connection request */
	    remotelen = sizeof(remote);
	    memset(&remote, 0, remotelen);
	    if ((net_fd = accept(sock_fd, (struct sockaddr *)&remote, &remotelen)) < 0) {
		syslog(LOG_ERR, "Accept error (%s)\n", strerror(errno));
		exit(1);
	    }

	    syslog(LOG_INFO, "Client connected from %s\n", inet_ntoa(remote.sin_addr));

	    sarg = malloc(sizeof(server_arg));
	    sarg->net_fd = net_fd;
	    sarg->tap_if_name = if_name;
	    sarg->tap_flags = flags;
	    sarg->use_aes = use_aes;
	    sarg->aes_ctx = &aes_ctx;
	    sarg->client_ip = strdup(inet_ntoa(remote.sin_addr));
	    sarg->server_name = server_name;
	    sarg->web_prefix = web_prefix;
	    sarg->debug = debug;
	    sarg->mode = cliserv;
	    sarg->ping_time = 10;
	    pthread_mutex_init(&sarg->mutex_net_write, NULL);

	    if (pthread_create(&tid, NULL, &server_thread, (void *)sarg) != 0) {
		pthread_mutex_destroy(&sarg->mutex_net_write);
		free(sarg->client_ip);
		free(sarg);
		syslog(LOG_ERR, "Can not create server thread\n");
	    }
	}
    }

    return 0;
}
