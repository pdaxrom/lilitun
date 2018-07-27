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
#include "lilitun.h"
#include "aes.h"
#include "http.h"
#include "utils.h"
#include "getrandom.h"

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2048
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
 * read_n: ensures we read exactly n bytes, and puts them into "buf".     *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n)
{

    int nread, left = n;

    while (left > 0) {
	if ((nread = cread(fd, buf, left)) > 0) {
	    left -= nread;
	    buf += nread;
	} else {
	    return nread;
	}
    }
    return n;
}

/**************************************************************************
 * tap2net:                                                               *
 **************************************************************************/
static int tap2net(server_arg * sarg)
{
    int16_t nread, nwrite, nread_aligned;
    char buffer[((BUFSIZE - 1) / 16 + 1) * 16];
    char aes_buffer[((BUFSIZE - 1) / 16 + 1) * 16];
    uint16_t *plength = (uint16_t *) buffer;

    nread = cread(sarg->tap_fd, buffer + sizeof(*plength), BUFSIZE);
    if (nread <= 0) {
	syslog(LOG_ERR, "Error read from tun (%s)\n", strerror(errno));
	return -1;
    }

    if (sarg->debug) {
	syslog(LOG_DEBUG, "TAP2NET: Read %d bytes from the tap interface\n", nread);
    }

    nread += sizeof(*plength);

    if (sarg->debug) {
	syslog(LOG_DEBUG, "TAP2NET: Packet size = %d\n", nread);
    }

    /* write length + packet */
    *plength = htons(nread);

    if (sarg->use_aes) {
	int i;
	nread_aligned = ((nread - 1) / 16 + 1) * 16;
	if (nread < nread_aligned) {
	    memset(buffer + nread, 0, nread_aligned - nread);
	}
	for (i = 0; i < nread_aligned; i += 16) {
	    aes_encrypt(&aes_ctx, (uint8 *) buffer + i, (uint8 *) aes_buffer + i);
	}

	if (sarg->debug) {
	    syslog(LOG_DEBUG, "TAP2NET: Packet size aligned = %d\n", nread_aligned);
	}
    }


    pthread_mutex_lock(&sarg->mutex_net_write);

    nwrite = cwrite(sarg->net_fd, sarg->use_aes ? aes_buffer : buffer, sarg->use_aes ? nread_aligned : nread);

    pthread_mutex_unlock(&sarg->mutex_net_write);

    if (nwrite != (sarg->use_aes ? nread_aligned : nread)) {
	syslog(LOG_ERR, "tap2net_loop(): error write buffer (%s)\n", strerror(errno));
	return -1;
    }


    if (sarg->debug) {
	syslog(LOG_DEBUG, "TAP2NET: Written %d bytes to the network\n", nwrite);
    }

    return nwrite;
}

/**************************************************************************
 * net2tap:                                                               *
 **************************************************************************/
static int net2tap(server_arg * sarg)
{
    int16_t nread, nwrite, nread_aligned;
    char aes_buffer[((BUFSIZE - 1) / 16 + 1) * 16];
    uint16_t *plength;

    /* data from the network: read it, and write it to the tun/tap interface. 
     * We need to read the length first, and then the packet */

    if (!sarg->rbuffer) {
	sarg->rbuffer_size = ((BUFSIZE - 1) / 16 + 1) * 16;
	sarg->rbuffer = malloc(sarg->rbuffer_size);
	sarg->rbuffered = 0;
    }

    if (sarg->use_aes) {
	plength = (uint16_t *) aes_buffer;
    } else {
	plength = (uint16_t *) sarg->rbuffer;
    }

    if (sarg->debug) {
	syslog(LOG_DEBUG, "net2tap(): buffered %d bytes\n", sarg->rbuffered);
    }

    while (sarg->rbuffered < (sarg->use_aes ? 16 : sizeof(*plength))) {
	nread = cread(sarg->net_fd, sarg->rbuffer + sarg->rbuffered, sarg->rbuffer_size - sarg->rbuffered);
	if (nread <= 0) {
	    syslog(LOG_ERR, "net2tap(): can't read from net_fd (%s)\n", strerror(errno));
	    return -1;
	}

	if (sarg->debug) {
	    syslog(LOG_INFO, "net2tap(): read in buffer+%d %d bytes\n", sarg->rbuffered, nread);
	}

	sarg->rbuffered += nread;
    }

    if (sarg->use_aes) {
	aes_decrypt(&aes_ctx, (uint8_t *) sarg->rbuffer, (uint8_t *) aes_buffer);
    }

    if (ntohs(*plength) == 0xffff) {
	syslog(LOG_INFO, "Ping packet received\n");
	if (sarg->use_aes) {
	    nread_aligned = 16;
	} else {
	    nread = sizeof(*plength);
	}
	nwrite = 0;
    } else {
	nread = ntohs(*plength);

	if (sarg->debug) {
	    syslog(LOG_DEBUG, "NET2TAP: Packet size = %d\n", nread);
	}

	if (sarg->use_aes) {
	    nread_aligned = ((nread - 1) / 16 + 1) * 16;

	    if (sarg->debug) {
		syslog(LOG_DEBUG, "NET2TAP: Packet size aligned = %d\n", nread_aligned);
	    }
	}

	while (sarg->rbuffered < (sarg->use_aes ? nread_aligned : nread)) {
	    int len = cread(sarg->net_fd, sarg->rbuffer + sarg->rbuffered, sarg->rbuffer_size - sarg->rbuffered);

	    if (len <= 0) {
		syslog(LOG_ERR, "net2tap(): can't read from net_fd (%s)\n", strerror(errno));
		return -1;
	    }

	    sarg->rbuffered += len;
	}

	if (sarg->debug) {
	    syslog(LOG_DEBUG, "NET2TAP: Buffered %d bytes from the network\n", sarg->rbuffered);
	}

	if (sarg->use_aes) {
	    int i;
	    for (i = 16; i < nread_aligned; i += 16) {
		aes_decrypt(&aes_ctx, (uint8 *) sarg->rbuffer + i, (uint8 *) aes_buffer + i);
	    }
	    nwrite = cwrite(sarg->tap_fd, aes_buffer + sizeof(*plength), nread - sizeof(*plength));
	} else {
	    /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */
	    nwrite = cwrite(sarg->tap_fd, sarg->rbuffer + sizeof(*plength), nread - sizeof(*plength));
	}

	if (nwrite != nread - sizeof(*plength)) {
	    syslog(LOG_ERR, "net2tap(): error write buffer (%s)\n", strerror(errno));
	    return -1;
	}

    }

    sarg->rbuffered -= (sarg->use_aes ? nread_aligned : nread);

    if (sarg->rbuffered > 0) {
	memcpy(sarg->rbuffer, sarg->rbuffer + (sarg->use_aes ? nread_aligned : nread), sarg->rbuffered);
    }

    if (sarg->debug) {
	syslog(LOG_DEBUG, "NET2TAP: Written %d bytes to the tap interface\n", nwrite);
    }

    return nwrite;
}

/**************************************************************************
 * send_ping(): send ping to another side                                 *
 **************************************************************************/
static int send_ping(server_arg * sarg)
{
    int nwrite, nlen;
    char buffer[16], aes_buffer[16];
    uint16_t *plength = (uint16_t *) buffer;

    memset(buffer, 0, sizeof(buffer));

    *plength = 0xffff;

    if (sarg->use_aes) {
	nlen = sizeof(aes_buffer);
	aes_encrypt(&aes_ctx, (uint8_t *) buffer, (uint8_t *) aes_buffer);
    } else {
	nlen = sizeof(*plength);
    }

    pthread_mutex_lock(&sarg->mutex_net_write);

    nwrite = cwrite(sarg->net_fd, sarg->use_aes ? aes_buffer : buffer, nlen);

    pthread_mutex_unlock(&sarg->mutex_net_write);

    if (nwrite != nlen) {
	syslog(LOG_ERR, "Error sending ping (%s)\n", strerror(errno));
	return -1;
    }

    return nwrite;
}

/**************************************************************************
 * tap2net_loop:                                                          *
 **************************************************************************/
static void *tap2net_thread(void *arg)
{
    server_arg *sarg = (server_arg *) arg;

    unsigned long int total = 0;

    while (sarg->vpn_is_alive) {
	int ret;
	fd_set rfds;
	struct timeval tv;

	tv.tv_sec = sarg->ping_time;
	tv.tv_usec = 0;

	FD_ZERO(&rfds);
	FD_SET(sarg->tap_fd, &rfds);

	ret = select(sarg->tap_fd + 1, &rfds, NULL, NULL, &tv);

	if (ret < 0 && errno == EINTR) {
	    continue;
	}

	if (ret < 0) {
	    syslog(LOG_ERR, "Select error (%s)\n", strerror(errno));
	    break;
	}

	if (!ret) {
	    if (sarg->debug) {
		syslog(LOG_DEBUG, "Select tap_fd timeout, continue\n");
	    }
	    continue;
	}

	if (FD_ISSET(sarg->tap_fd, &rfds)) {
	    int len = tap2net(sarg);

	    if (len < 0) {
		break;
	    }

	    total += len;
	}
    }

    syslog(LOG_INFO, "Total written to network: %lu\n", total);

    sarg->vpn_is_alive = 0;

    return NULL;
}

/**************************************************************************
 * tap2net_loop:                                                       *
 **************************************************************************/
static void *net2tap_thread(void *arg)
{
    server_arg *sarg = (server_arg *) arg;
    unsigned long int total = 0;
    int ping_sent = 0;
    struct timespec wd_old;

    if (clock_gettime(CLOCK_MONOTONIC, &wd_old) == -1) {
	syslog(LOG_ERR, "Clock gettime\n");
	return 0;
    }

    sarg->rbuffer = NULL;

    while (sarg->vpn_is_alive) {
	int ret;
	fd_set rfds;
	struct timeval tv;
	struct timespec wd_current;

	tv.tv_sec = sarg->ping_time;
	tv.tv_usec = 0;

	FD_ZERO(&rfds);
	FD_SET(sarg->net_fd, &rfds);

	ret = select(sarg->net_fd + 1, &rfds, NULL, NULL, &tv);

	if (ret < 0 && errno == EINTR) {
	    continue;
	}

	if (ret < 0) {
	    syslog(LOG_ERR, "Select error (%s)\n", strerror(errno));
	    break;
	}

	if (clock_gettime(CLOCK_MONOTONIC, &wd_current) == -1) {
	    syslog(LOG_ERR, "Clock gettime\n");
	    break;
	}

	if (wd_current.tv_sec - wd_old.tv_sec >= sarg->ping_time) {
	    wd_old = wd_current;
	    // timeout
	    if (ping_sent == 3) {
		syslog(LOG_INFO, "Ping sent 3 times, no reply, connection timeout.\n");
		break;
	    }
	    syslog(LOG_INFO, "Send ping\n");
	    if (send_ping(sarg) < 0) {
		break;
	    }
	    ping_sent++;
	}

	if (!ret) {
	    if (sarg->debug) {
		syslog(LOG_DEBUG, "Select net_fd timeout, continue\n");
	    }
	    continue;
	}


	if (FD_ISSET(sarg->net_fd, &rfds)) {
	    int len = net2tap(sarg);

	    if (len < 0) {
		break;
	    }

	    total += len;
	    ping_sent = 0;
	    if (len > 0) {
		wd_old = wd_current;
	    } else {
		syslog(LOG_INFO, "Ping packet.");
	    }
	}
    }

    syslog(LOG_INFO, "Total written from network: %lu\n", total);

    if (sarg->rbuffer) {
	free(sarg->rbuffer);
    }

    sarg->vpn_is_alive = 0;

    return NULL;
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

	if (!strcmp(h_method, "GET")) {
	    char *path;
	    char *file_path;
	    char *tmp_path;
	    struct stat sb;

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
		send_file(sarg, file_path);
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
	    if (!strcmp(h_url, "/") && sarg->use_aes) {
		syslog(LOG_INFO, "[%s] CONNECT to: %s\n", sarg->client_ip, h_url);
		char *resp = http_response_begin(200, "OK");
		http_response_end(resp);

		if (cwrite(sarg->net_fd, resp, strlen(resp)) != strlen(resp)) {
		    free(resp);
		    break;
		}
		free(resp);

		char tmp[16];
		char aes_tmp[sizeof(tmp)];
		char session_id[sizeof(tmp) - sizeof(server_id)];
		memcpy(tmp, server_id, sizeof(server_id));
		if (my_getrandom(tmp + sizeof(server_id), sizeof(tmp) - sizeof(server_id), 0) == -1) {
		    syslog(LOG_ERR, "[%s] getrandom (%s)\n", sarg->client_ip, strerror(errno));
		    break;
		}
		// Store random key as session id
		memcpy(session_id, tmp + sizeof(server_id), sizeof(session_id));

		if (sarg->debug) {
		    dump16(tmp);
		}

		aes_encrypt(&aes_ctx, (uint8_t *) tmp, (uint8_t *) aes_tmp);

		if (sarg->debug) {
		    dump16(aes_tmp);
		}

		if (cwrite(sarg->net_fd, aes_tmp, sizeof(aes_tmp)) != sizeof(aes_tmp)) {
		    break;
		}

		nread = cread(sarg->net_fd, aes_tmp, sizeof(aes_tmp));
		if (nread <= 0) {
		    syslog(LOG_INFO, "[%s] no data read for client_id\n", sarg->client_ip);
		    break;
		}

		if (sarg->debug) {
		    dump16(aes_tmp);
		}

		aes_decrypt(&aes_ctx, (uint8_t *) aes_tmp, (uint8_t *) tmp);

		if (sarg->debug) {
		    dump16(tmp);
		}

		if (!strncmp(tmp, client_id, sizeof(client_id)) &&
		    !memcmp(tmp + sizeof(server_id), session_id, sizeof(session_id))) {
		    pthread_t net2tap_tid;
		    pthread_t tap2net_tid;

		    syslog(LOG_INFO, "[%s] Start VPN connection\n", sarg->client_ip);

		    sarg->vpn_is_alive = 1;

		    if (pthread_create(&net2tap_tid, NULL, &net2tap_thread, (void *)sarg) != 0) {
			syslog(LOG_ERR, "[%s] pthread_create(net2tap_thread) (%s)\n", sarg->client_ip, strerror(errno));
		    } else if (pthread_create(&tap2net_tid, NULL, &tap2net_thread, (void *)sarg) != 0) {
			syslog(LOG_ERR, "[%s] pthread_create(tap2net_thread) (%s)\n", sarg->client_ip, strerror(errno));
		    } else {
			(void)pthread_join(net2tap_tid, NULL);
			(void)pthread_join(tap2net_tid, NULL);
		    }
		    syslog(LOG_INFO, "[%s] VPN connection finished\n", sarg->client_ip);
		} else {
		    syslog(LOG_INFO, "[%s] wrong client_id or session_id, connection closed\n", sarg->client_ip);
		}
	    } else {
		syslog(LOG_INFO, "[%s] http error: Forbidden\n", sarg->client_ip);
		send_error(sarg, 403, "Forbidden");
	    }
	    break;
	} else {
	    syslog(LOG_INFO, "[%s] http error: Not Implemented\n", sarg->client_ip);
	    send_error(sarg, 501, "Not Implemented");
	    break;
	}
    }

    close(sarg->net_fd);

    syslog(LOG_INFO, "[%s] Server thread finished!\n", sarg->client_ip);

    pthread_mutex_destroy(&sarg->mutex_net_write);
    free(sarg->client_ip);
    free(sarg);

    return arg;
}

/**************************************************************************
 * client_connection:                                                       *
 **************************************************************************/
static int client_connection(server_arg * sarg)
{
    char header[2048];
    char h_method[16];
    char h_url[256];
    char h_spec[16];
    static char *req = "CONNECT / HTTP/1.1\n\n";

    if (cwrite(sarg->net_fd, req, strlen(req)) != strlen(req)) {
	syslog(LOG_ERR, "Can not send data in client_connection (%s)\n", strerror(errno));
	return 1;
    }

    int nread = cread(sarg->net_fd, header, sizeof(header));
    if (nread <= 0) {
	syslog(LOG_ERR, "No data read in client_connection (%s)\n", strerror(errno));
	return 1;
    }

    if (sarg->debug) {
	syslog(LOG_DEBUG, "HTTP read: [\n%s\n]\n", header);
    }

    header_get_method(header, h_method, sizeof(h_method));
    header_get_url(header, h_url, sizeof(h_url));
    header_get_spec(header, h_spec, sizeof(h_spec));

    syslog(LOG_INFO, "RESPONSE: '%s' STATUS: '%s' MESSAGE: '%s'\n", h_method, h_url, h_spec);

    if (!strcmp(h_method, "HTTP/1.1") && !strcmp(h_url, "200") && !strcmp(h_spec, "OK")) {
	char tmp[16];
	char aes_tmp[16];

	char *ptr = strstr(header, "\n\n");
	if (!ptr) {
	    syslog(LOG_ERR, "Incomplete response header\n");
	    return 1;
	}

	ptr += 2;
	int received = nread - (ptr - header);

	if (received < 16) {
	    nread = cread(sarg->net_fd, aes_tmp, sizeof(aes_tmp) - received);
	    if (nread <= 0) {
		syslog(LOG_ERR, "no data read in client_connection (%s)\n", strerror(errno));
		return 1;
	    }
	} else {
	    memcpy(aes_tmp, ptr, 16);
	}

	if (sarg->debug) {
	    dump16(aes_tmp);
	}

	aes_decrypt(&aes_ctx, (uint8_t *) aes_tmp, (uint8_t *) tmp);

	if (sarg->debug) {
	    dump16(tmp);
	}

	if (!strncmp(tmp, server_id, sizeof(server_id))) {
	    pthread_t net2tap_tid;
	    pthread_t tap2net_tid;

	    syslog(LOG_INFO, "Decrypted server_id is okay!\n");

	    memcpy(tmp, client_id, sizeof(client_id));

	    if (sarg->debug) {
		dump16(tmp);
	    }

	    aes_encrypt(&aes_ctx, (uint8_t *) tmp, (uint8_t *) aes_tmp);

	    if (sarg->debug) {
		dump16(aes_tmp);
	    }

	    if (cwrite(sarg->net_fd, aes_tmp, sizeof(aes_tmp)) != sizeof(aes_tmp)) {
		syslog(LOG_ERR, "Error send client_id (%s)\n", strerror(errno));
		return 1;
	    }

	    syslog(LOG_INFO, "Start VPN connection\n");
	    sarg->vpn_is_alive = 1;

	    if (pthread_create(&net2tap_tid, NULL, &net2tap_thread, (void *)sarg) != 0) {
		syslog(LOG_ERR, "pthread_create(net2tap_thread) (%s)\n", strerror(errno));
	    } else if (pthread_create(&tap2net_tid, NULL, &tap2net_thread, (void *)sarg) != 0) {
		syslog(LOG_ERR, "pthread_create(tap2net_thread) (%s)\n", strerror(errno));
	    } else {
		(void)pthread_join(net2tap_tid, NULL);
		(void)pthread_join(tap2net_tid, NULL);
	    }
	} else {
	    syslog(LOG_INFO, "Wrong decrypted server_id\n");
	}

	syslog(LOG_INFO, "VPN connection finished\n");
    } else {
	syslog(LOG_INFO, "Connection refused\n");
    }

    return 0;
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
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

    /* initialize tun/tap interface */
    if ((tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0) {
	syslog(LOG_ERR, "Error connecting to tun/tap interface %s (%s)!\n", if_name, strerror(errno));
	exit(1);
    }

    syslog(LOG_INFO, "Successfully connected to interface %s\n", if_name);

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	syslog(LOG_ERR, "Can not create socket (%s)\n", strerror(errno));
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
	    syslog(LOG_ERR, "Can not connect to server (%s)\n", strerror(errno));
	    exit(1);
	}

	net_fd = sock_fd;
	syslog(LOG_INFO, "Connected to server %s\n", inet_ntoa(remote.sin_addr));

	server_arg *sarg = malloc(sizeof(server_arg));
	sarg->net_fd = net_fd;
	sarg->tap_fd = tap_fd;
	sarg->use_aes = use_aes;
	sarg->server_name = server_name;
	sarg->web_prefix = web_prefix;
	sarg->debug = debug;
	sarg->mode = cliserv;
	sarg->ping_time = 10;
	pthread_mutex_init(&sarg->mutex_net_write, NULL);

	if (use_aes) {
	    client_connection(sarg);
	} else {
	    syslog(LOG_ERR, "Only secure connection enabled!\n");
	}

	pthread_mutex_destroy(&sarg->mutex_net_write);
	free(sarg);

    } else {
	/* Server, wait for connections */

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
	    sarg->tap_fd = tap_fd;
	    sarg->use_aes = use_aes;
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
