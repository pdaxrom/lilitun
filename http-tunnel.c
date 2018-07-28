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
