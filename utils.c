#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <inttypes.h>
#include "aes.h"
#include "lilitun.h"
#include "utils.h"
#include "getrandom.h"

char *copy_str(char *dst, int dst_size, char *src, int src_size)
{
    if (!dst) {
	dst_size = src_size;
	dst = malloc(dst_size + 1);
    } else {
	dst_size = (src_size > dst_size) ? dst_size : src_size;
    }
    memcpy(dst, src, dst_size);
    dst[dst_size] = 0;
    return dst;
}

char *header_get_method(char *header, char *str, int n)
{
    char *tmp = strchr(header, ' ');
    if (tmp) {
	return copy_str(str, n, header, tmp - header);
    }
    if (str) {
	str[0] = 0;
    }
    return NULL;
}

char *header_get_url(char *header, char *str, int n)
{
    char *tmp = strchr(header, ' ');
    if (tmp) {
	char *tmp1 = strchr(tmp + 1, ' ');
	if (tmp1) {
	    return copy_str(str, n, tmp + 1, tmp1 - tmp - 1);
	}
    }
    if (str) {
	str[0] = 0;
    }
    return NULL;
}

char *header_get_spec(char *header, char *str, int n)
{
    char *tmp = strchr(header, ' ');
    if (tmp) {
	char *tmp1 = strchr(tmp + 1, ' ');
	if (tmp1) {
	    for (tmp = tmp1 + 1; *tmp > ' '; tmp++) ;
	    return copy_str(str, n, tmp1 + 1, tmp - tmp1 - 1);
	}
    }
    if (str) {
	str[0] = 0;
    }
    return NULL;
}

char *header_get_field(char *header, char *field, char *str, int n)
{
    char *tmp = strstr(header, field);
    if (tmp) {
	char *tmp1 = strchr(tmp, ':');
	if (tmp1) {
	    for (tmp1++; *tmp1 == ' '; tmp1++);
	    for (tmp = tmp1; *tmp != 0 && *tmp != '\n' && *tmp != '\r'; tmp++);
	    return copy_str(str, n, tmp1, tmp - tmp1);
	}
    }
    return NULL;
}

char *url_get_path(char *url, char *path, int n)
{
    int i;

    for (i = 0; url[i] > ' ' && url[i] != '?'; i++) ;

    return copy_str(path, n, url, i);
}

#define NIB2HEX(b)	(((b) < 10) ? ('0' + (b)) : ('a' + (b) - 10))
#define HEX2NIB(h)	(((h) >= '0' && (h) <= '9') ? ((h) - '0') : ((h) >= 'A' && (h) <= 'F') ? ((h) - 'A' + 10) : ((h) >= 'a' && (h) <= 'f') ? ((h) - 'a' + 10) : 0)

void buf2hex(uint8_t *buf, int n, char *hex)
{
    int i;
    for (i = 0; i < n; i++) {
	hex[i * 2 + 0] = NIB2HEX(buf[i] >> 4);
	hex[i * 2 + 1] = NIB2HEX(buf[i] & 0x0f);
    }
}

void hex2buf(char *hex, int n, uint8_t *buf)
{
    int i;
    for (i = 0; i < n; i++) {
	buf[i] = (HEX2NIB((uint8_t) hex[i * 2 + 0]) << 4) | HEX2NIB((uint8_t) hex[i * 2 + 1]);
    }
}

int generate_session_key(server_arg * sarg)
{
    sarg->session_key = malloc(16);
    if (sarg->use_aes) {
	sarg->session_key_aes = malloc(16);
    }
    sarg->session_key_hex = malloc(16 * 2 + 1);
    sarg->session_id = malloc(16 - sizeof(server_id));

    memcpy(sarg->session_key, server_id, sizeof(server_id));
    if (my_getrandom(sarg->session_key + sizeof(server_id), 16 - sizeof(server_id), 0) == -1) {
	syslog(LOG_ERR, "[%s] getrandom (%s)\n", sarg->client_ip, strerror(errno));
	free_session_key(sarg);
	return -1;
    }
    // Store random key as session id
    memcpy(sarg->session_id, sarg->session_key + sizeof(server_id), 16 - sizeof(server_id));

    if (debug) {
	dump16(sarg->session_key);
    }

    if (sarg->use_aes) {
	aes_encrypt(sarg->aes_ctx, (uint8_t *) sarg->session_key, (uint8_t *) sarg->session_key_aes);

	if (debug) {
	    dump16(sarg->session_key_aes);
	}
    }

    buf2hex((uint8_t *) (sarg->use_aes ? sarg->session_key_aes : sarg->session_key), 16, sarg->session_key_hex);
    sarg->session_key_hex[16 * 2] = 0;

    if (debug) {
	syslog(LOG_DEBUG, "Session key hex: %s\n", sarg->session_key_hex);
    }

    return 0;
}

void free_session_key(server_arg * sarg)
{
    free(sarg->session_key);
    sarg->session_key = NULL;
    if (sarg->use_aes) {
	free(sarg->session_key_aes);
	sarg->session_key_aes = NULL;
    }
    free(sarg->session_key_hex);
    sarg->session_key_hex = NULL;
    free(sarg->session_id);
    sarg->session_id = NULL;
}
