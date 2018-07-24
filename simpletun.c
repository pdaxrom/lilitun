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
#include "lilitun.h"
#include "aes.h"
#include "http.h"
#include "utils.h"

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000
#define CLIENT 0
#define SERVER 1
#define PORT 55555

int debug;
char *progname;

aes_context aes_ctx;
uint8 aes_key[256];
//uint32 aes_key_size;

char server_id[16] = "lilithvpn 1.0   ";
char client_id[16] = "   0.1 npvhtilil";

/**************************************************************************
 * init_aes: AES key initialization                                       *
 **************************************************************************/
int init_aes(char *keyfile)
{
    FILE *inf = fopen(keyfile, "rb");
    if (inf) {
	int size = fread(aes_key, 1, sizeof(aes_key), inf);
	if ((size != 16) && (size != 24) && (size != 32)) {
	    fprintf(stderr, "Key must be 16, 24 or 32 bytes! AES disabled.\n");
	    return 0;
	}
	fclose(inf);
//      aes_key_size = size;
	aes_set_key(&aes_ctx, aes_key, size * 8);
	fprintf(stderr, "Use AES-%d.\n", size * 8);
    } else {
	fprintf(stderr, "Can't open key file! AES disabled.\n");
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
	perror("Opening /dev/net/tun");
	return fd;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags;

    if (*dev) {
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
	perror("ioctl(TUNSETIFF)");
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
	perror("Reading data");
	exit(1);
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
	perror("Writing data");
	exit(1);
    }
    return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts them into "buf".     *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n)
{

    int nread, left = n;

    while (left > 0) {
	if ((nread = cread(fd, buf, left)) == 0) {
	    return 0;
	} else {
	    left -= nread;
	    buf += nread;
	}
    }
    return n;
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...)
{

    va_list argp;

    if (debug) {
	va_start(argp, msg);
	vfprintf(stderr, msg, argp);
	va_end(argp);
    }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...)
{

    va_list argp;

    va_start(argp, msg);
    vfprintf(stderr, msg, argp);
    va_end(argp);
}

/**************************************************************************
 * connection_loop:                                                       *
 **************************************************************************/
int connection_loop(int net_fd, int tap_fd, int use_aes)
{
    int maxfd;
    uint16_t nread, nwrite, plength;
    char buffer[((BUFSIZE - 1) / 16 + 1) * 16];
    char aes_buffer[((BUFSIZE - 1) / 16 + 1) * 16];
    unsigned long int tap2net = 0, net2tap = 0;

    /* use select() to handle two descriptors at once */
    maxfd = (tap_fd > net_fd) ? tap_fd : net_fd;

    while (1) {
	int ret;
	fd_set rd_set;

	FD_ZERO(&rd_set);
	FD_SET(tap_fd, &rd_set);
	FD_SET(net_fd, &rd_set);

	ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

	if (ret < 0 && errno == EINTR) {
	    continue;
	}

	if (ret < 0) {
	    perror("select()");
	    return 1;
	}

	if (FD_ISSET(tap_fd, &rd_set)) {
	    /* data from tun/tap: just read it and write it to the network */

	    nread = cread(tap_fd, buffer, BUFSIZE);

	    tap2net++;
	    do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n",
		     tap2net, nread);

	    /* write length + packet */
	    plength = htons(nread);
	    nwrite = cwrite(net_fd, (char *)&plength, sizeof(plength));

	    if (use_aes) {
		int i;
		int nread_aligned = ((nread - 1) / 16 + 1) * 16;
		if (nread < nread_aligned) {
		    memset(buffer + nread, 0, nread_aligned - nread);
		}
		for (i = 0; i < nread_aligned; i += 16) {
		    aes_encrypt(&aes_ctx, (uint8 *) buffer + i,
				(uint8 *) aes_buffer + i);
		}
		nwrite = cwrite(net_fd, aes_buffer, nread_aligned);
	    } else {
		nwrite = cwrite(net_fd, buffer, nread);
	    }

	    do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net,
		     nwrite);
	}

	if (FD_ISSET(net_fd, &rd_set)) {
	    int nread_aligned;
	    /* data from the network: read it, and write it to the tun/tap interface. 
	     * We need to read the length first, and then the packet */

	    /* Read length */
	    nread = read_n(net_fd, (char *)&plength, sizeof(plength));
	    if (nread == 0) {
		/* ctrl-c at the other end */
		break;
	    }

	    net2tap++;

	    nread = ntohs(plength);

	    if (use_aes) {
		nread_aligned = ((nread - 1) / 16 + 1) * 16;
	    }

	    /* read packet */
	    nread = read_n(net_fd, buffer, use_aes ? nread_aligned : nread);
	    do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap,
		     nread);

	    if (use_aes) {
		int i;
		for (i = 0; i < nread_aligned; i += 16) {
		    aes_decrypt(&aes_ctx, (uint8 *) buffer + i,
				(uint8 *) aes_buffer + i);
		}
		nwrite = cwrite(tap_fd, aes_buffer, ntohs(plength));
	    } else {
		/* now buffer[] contains a full packet or frame, write it into the tun/tap interface */
		nwrite = cwrite(tap_fd, buffer, nread);
	    }
	    do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n",
		     net2tap, nwrite);
	}
    }

    return 0;
}

/**************************************************************************
 * server_thread:                                                       *
 **************************************************************************/
static void *server_thread(void *arg)
{
    server_arg *sarg = (server_arg *) arg;

    pthread_detach(pthread_self());

    while (1) {
	char header[2048];
	char h_method[16];
	char h_url[256];
	char h_spec[16];

	int nread = cread(sarg->net_fd, header, sizeof(header));
	do_debug("HTTP read: [\n%s\n]\n", header);

	header_get_method(header, h_method, sizeof(h_method));
	header_get_url(header, h_url, sizeof(h_url));
	header_get_spec(header, h_spec, sizeof(h_spec));
	do_debug("METHOD: '%s'\nURL: '%s'\nSPEC: '%s'\n\n", h_method, h_url, h_spec);

	if (!strcmp(h_method, "GET")) {
	    char *path;
	    char *file_path;
	    char *tmp_path;
	    struct stat sb;

	    path = url_get_path(h_url, NULL, 0);

	    tmp_path = malloc(strlen(sarg->web_prefix) + 5 + strlen(path) + 1); // prefix + "/www/" + path + '\0'
	    tmp_path[0] = 0;

	    strcat(tmp_path, sarg->web_prefix);
	    strcat(tmp_path, "/www/");
	    strcat(tmp_path, path);

	    file_path = realpath(tmp_path, NULL);

	    free(tmp_path);
	    free(path);

	    if (file_path) {
		if (stat(file_path, &sb) == -1) {
		    do_debug("stat(file_path) error!");
		} else {
		    if ((sb.st_mode & S_IFMT) == S_IFDIR) {
			file_path = realloc(file_path, strlen(file_path) + 11); // file_path + "/index.html"
			strcat(file_path, "/index.html");
		    }
		}
		tmp_path = realpath(file_path, NULL);
		free(file_path);
		file_path = tmp_path;
	    }

	    if (file_path && !strncmp(file_path, sarg->web_prefix, strlen(sarg->web_prefix))) {
		char *mime;
		do_debug("File found: %s\n", file_path);
		send_file(sarg, file_path, &mime);
		do_debug("mime -> %s\n", mime);
#if 0
		if (!strncmp(mime, "image/", 6) ||
		    !strncmp(mime, "audio/", 6) ||
		    !strncmp(mime, "video/", 6)) {
		    char tmp[16];
		    int nsent;
		    do_debug("Advertise VPN server.\n");
		    aes_encrypt(&aes_ctx, (uint8_t *)server_id, (uint8_t *) tmp);
		    if ((nsent = cwrite(sarg->net_fd, tmp, 16)) == 16) {
			char tmp_dec[16];
			int nread;
			do_debug("Sent Advert.\n");
			if ((nread = cread(sarg->net_fd, tmp, 16)) == 16) {
			    do_debug("Got answer, decoding.\n");
			    aes_decrypt(&aes_ctx, (uint8_t *)tmp, (uint8_t *)tmp_dec);
			    tmp_dec[15] = 0;
			    do_debug("ANSWER: %s\n", tmp_dec);
			} else {
			    do_debug("Seems connection is closed (%d)!\n", nread);
			}
		    } else {
			do_debug("Seems connection is closed (%d)!\n", nsent);
		    }
		}
#endif
	    } else {
		do_debug("File is not found\n");
		send_error(sarg, 404, "Not found");
	    }
	    if (file_path) {
		free(file_path);
	    }
	} else {
	    send_error(sarg, 501, "Not Implemented");
	}
	break;
    }

    //connection_loop(sarg->net_fd, sarg->tap_fd, sarg->use_aes);

    close(sarg->net_fd);

    free(sarg);

    do_debug("Server thread finished!\n");

    return arg;
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr,
	    "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n",
	    progname);
    fprintf(stderr, "%s -h\n", progname);
    fprintf(stderr, "\n");
    fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
    fprintf(stderr,
	    "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
    fprintf(stderr,
	    "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
    fprintf(stderr, "-k <keyfile>: aes key 16, 24 or 32 bytes\n");
    fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
    fprintf(stderr, "-d: outputs debug information while running\n");
    fprintf(stderr, "-h: prints this help text\n");
    exit(1);
}

int main(int argc, char *argv[])
{

    int tap_fd, option;
    int flags = IFF_TUN;
    char if_name[IFNAMSIZ] = "";
    struct sockaddr_in local, remote;
    char remote_ip[16] = "";	/* dotted quad IP string */
    unsigned short int port = PORT;
    int sock_fd, net_fd, optval = 1;
    socklen_t remotelen;
    int cliserv = -1;		/* must be specified on cmd line */
    int use_aes = 0;
    char *web_prefix = "/opt/lilith/www";

    progname = argv[0];

    /* Check command line options */
    while ((option = getopt(argc, argv, "i:sc:p:k:w:uahd")) > 0) {
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
	default:
	    my_err("Unknown option %c\n", option);
	    usage();
	}
    }

    argv += optind;
    argc -= optind;

    if (argc > 0) {
	my_err("Too many options!\n");
	usage();
    }

    if (*if_name == '\0') {
	my_err("Must specify interface name!\n");
	usage();
    } else if (cliserv < 0) {
	my_err("Must specify client or server mode!\n");
	usage();
    } else if ((cliserv == CLIENT) && (*remote_ip == '\0')) {
	my_err("Must specify server address!\n");
	usage();
    }

    /* initialize tun/tap interface */
    if ((tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0) {
	my_err("Error connecting to tun/tap interface %s!\n", if_name);
	exit(1);
    }

    do_debug("Successfully connected to interface %s\n", if_name);

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	perror("socket()");
	exit(1);
    }

    if (cliserv == CLIENT) {
	/* Client, try to connect to server */

	/* assign the destination address */
	memset(&remote, 0, sizeof(remote));
	remote.sin_family = AF_INET;
	remote.sin_addr.s_addr = inet_addr(remote_ip);
	remote.sin_port = htons(port);

	/* connection request */
	if (connect(sock_fd, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
	    perror("connect()");
	    exit(1);
	}

	net_fd = sock_fd;
	do_debug("CLIENT: Connected to server %s\n",
		 inet_ntoa(remote.sin_addr));

	connection_loop(net_fd, tap_fd, use_aes);

    } else {
	/* Server, wait for connections */

	/* avoid EADDRINUSE error on bind() */
	if (setsockopt
	    (sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval,
	     sizeof(optval)) < 0) {
	    perror("setsockopt()");
	    exit(1);
	}

	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = htonl(INADDR_ANY);
	local.sin_port = htons(port);
	if (bind(sock_fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
	    perror("bind()");
	    exit(1);
	}

	if (listen(sock_fd, 5) < 0) {
	    perror("listen()");
	    exit(1);
	}

	while (1) {
	    pthread_t tid;
	    server_arg *sarg;
	    /* wait for connection request */
	    remotelen = sizeof(remote);
	    memset(&remote, 0, remotelen);
	    if ((net_fd = accept(sock_fd, (struct sockaddr *)&remote, &remotelen)) < 0) {
		perror("accept()");
		exit(1);
	    }

	    do_debug("SERVER: Client connected from %s\n",
		 inet_ntoa(remote.sin_addr));

	    sarg = malloc(sizeof(server_arg));
	    sarg->net_fd = net_fd;
	    sarg->tap_fd = tap_fd;
	    sarg->use_aes = use_aes;
	    sarg->web_prefix = web_prefix;

	    if (pthread_create(&tid, NULL, (void *) &server_thread, (void *) sarg) != 0) {
		free(sarg);
		fprintf(stderr, "pthread_create(server_thread)\n");
	    }
	}
    }

    return 0;
}
