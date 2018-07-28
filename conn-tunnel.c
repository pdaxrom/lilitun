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
	dump_SrcDst(buffer + sizeof(*plength));
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
	    aes_encrypt(sarg->aes_ctx, (uint8 *) buffer + i, (uint8 *) aes_buffer + i);
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
	aes_decrypt(sarg->aes_ctx, (uint8_t *) sarg->rbuffer, (uint8_t *) aes_buffer);
    }

    if (ntohs(*plength) == 0xffff) {
	if (sarg->debug) {
	    syslog(LOG_DEBUG, "Ping packet received\n");
	}
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
		aes_decrypt(sarg->aes_ctx, (uint8 *) sarg->rbuffer + i, (uint8 *) aes_buffer + i);
	    }

	    if (sarg->debug) {
		dump_SrcDst(aes_buffer + sizeof(*plength));
	    }

	    nwrite = cwrite(sarg->tap_fd, aes_buffer + sizeof(*plength), nread - sizeof(*plength));
	} else {
	    /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */

	    if (sarg->debug) {
		dump_SrcDst(sarg->rbuffer + sizeof(*plength));
	    }

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
	aes_encrypt(sarg->aes_ctx, (uint8_t *) buffer, (uint8_t *) aes_buffer);
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
void *tap2net_thread(void *arg)
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
void *net2tap_thread(void *arg)
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

	    if (sarg->debug) {
		syslog(LOG_DEBUG, "Send ping\n");
	    }

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

int server_tunnel(server_arg * sarg, char *h_url)
{
    if (!strcmp(h_url, "/") && sarg->use_aes) {
	int nread;
	char tmp[16];
	char aes_tmp[sizeof(tmp)];

	syslog(LOG_INFO, "[%s] CONNECT to: %s\n", sarg->client_ip, h_url);
	char *resp = http_response_begin(200, "OK");
	http_response_end(resp);

	if (cwrite(sarg->net_fd, resp, strlen(resp)) != strlen(resp)) {
	    free(resp);
	    return -1;
	}
	free(resp);

	if (cwrite(sarg->net_fd, sarg->session_key_aes, 16) != 16) {
	    syslog(LOG_ERR, "[%s] Write encrypted header\n", sarg->client_ip);
	    return -1;
	}

	nread = cread(sarg->net_fd, aes_tmp, 16);
	if (nread <= 0) {
	    syslog(LOG_INFO, "[%s] no data read for client_id\n", sarg->client_ip);
	    return -1;
	}

	if (sarg->debug) {
	    dump16(aes_tmp);
	}

	aes_decrypt(sarg->aes_ctx, (uint8_t *) aes_tmp, (uint8_t *) tmp);

	if (sarg->debug) {
	    dump16(tmp);
	}

	if (!strncmp(tmp, client_id, sizeof(client_id))
	    && !memcmp(tmp + sizeof(server_id), sarg->session_id, 16 - sizeof(server_id))) {
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
	    return -1;
	}
    } else {
	syslog(LOG_INFO, "[%s] http error: Forbidden\n", sarg->client_ip);
	send_error(sarg, 403, "Forbidden");
	return -1;
    }

    return 0;
}

/**************************************************************************
 * client_connection:                                                       *
 **************************************************************************/
int client_tunnel(server_arg * sarg)
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

	aes_decrypt(sarg->aes_ctx, (uint8_t *) aes_tmp, (uint8_t *) tmp);

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

	    aes_encrypt(sarg->aes_ctx, (uint8_t *) tmp, (uint8_t *) aes_tmp);

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
