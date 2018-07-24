#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "utils.h"

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
	    for (tmp = tmp1 + 1; *tmp > ' '; tmp++);
	    return copy_str(str, n, tmp1 + 1, tmp - tmp1 - 1);
	}
    }
    if (str) {
	str[0] = 0;
    }
    return NULL;
}

char *url_get_path(char *url, char *path, int n)
{
    int i;

    for (i = 0; url[i] > ' ' && url[i] != '?'; i++);

    return copy_str(path, n, url, i);
}
