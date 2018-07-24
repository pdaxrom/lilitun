#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include "lilitun.h"
#include "utils.h"

#define BUF_SIZE	4096
#define BUF_RESP_SIZE	1024

static struct mimetype {
    char *ext;
    char *mime;
} mimetypes[] = {
#include "mime.h"
};

static char *http_version = "HTTP/1.1";

char *http_response_begin(int status, char *reason)
{
    char *resp = malloc(BUF_RESP_SIZE);
    if (resp)
	snprintf(resp, BUF_RESP_SIZE, "%s %d %s\n", http_version, status,
		 reason);

    return resp;
}

char *http_response_add_time_stamp(char *resp)
{
    time_t t;
    struct tm *tmp;

    t = time(NULL);
    tmp = localtime(&t);

    if (tmp == NULL) {
	perror("localtime");
	return resp;
    }

    char *ptr = resp + strlen(resp);
    strftime(ptr, BUF_RESP_SIZE - strlen(resp), "Date: %a, %d %b %Y %T %Z\n",
	     tmp);

    return resp;
}

char *http_response_add_server(char *resp, char *server)
{
    char *ptr = resp + strlen(resp);
    snprintf(ptr, BUF_RESP_SIZE - strlen(resp), "Server: %s\n", server);

    return resp;
}

char *http_response_add_modtime_stamp(char *resp, time_t * t)
{
    struct tm *tmp;

    tmp = localtime(t);

    if (tmp == NULL) {
	perror("localtime");
	return resp;
    }

    char *ptr = resp + strlen(resp);
    strftime(ptr, BUF_RESP_SIZE - strlen(resp),
	     "Last-Modified: %a, %d %b %Y %T %Z\n", tmp);

    return resp;
}

char *http_response_add_content_type(char *resp, char *mime)
{
    char *ptr = resp + strlen(resp);
    snprintf(ptr, BUF_RESP_SIZE - strlen(resp), "Content-Type: %s\n", mime);

    return resp;
}

char *http_response_add_content_length(char *resp, size_t length)
{
    char *ptr = resp + strlen(resp);
    snprintf(ptr, BUF_RESP_SIZE - strlen(resp), "Content-Length: %lu\n",
	     length);

    return resp;
}

char *http_response_add_connection(char *resp, char *token)
{
    char *ptr = resp + strlen(resp);
    snprintf(ptr, BUF_RESP_SIZE - strlen(resp), "Connection: %s\n", token);

    return resp;
}

char *http_response_add_accept_ranges(char *resp)
{
    char *ptr = resp + strlen(resp);
    snprintf(ptr, BUF_RESP_SIZE - strlen(resp), "Accept-Ranges: bytes\n");

    return resp;
}

char *http_response_add_range(char *resp, size_t from, size_t to,
			      size_t length)
{
    char *ptr = resp + strlen(resp);
    snprintf(ptr, BUF_RESP_SIZE - strlen(resp),
	     "Content-Range: bytes %lu-%lu/%lu\n", from, to, length);

    return resp;
}

char *http_response_end(char *resp)
{
    return strncat(resp, "\n", BUF_RESP_SIZE);
}

char *get_mimetype(char *file)
{
    char *ptr = strrchr(file, '.');
    if (ptr && strlen(ptr + 1)) {
	int i = 0;
	for (i = 0; i < sizeof(mimetypes) / sizeof(struct mimetype); i++) {
	    if (!strcmp(mimetypes[i].ext, ptr)) {
		return mimetypes[i].mime;
	    }
	}
    }

    return "application/octet-stream";
}

int send_error(server_arg * s, int e, char *t)
{
    char path[PATH_MAX];
    char page[BUF_SIZE];
    struct stat sb;

    snprintf(path, sizeof(path), "%s/wwwresp/%d.html", s->web_prefix, e);

    FILE *inf = fopen(path, "rb");

    if ((stat(path, &sb) == -1) || (!inf)) {
	do_debug("send_file/stat error!");
	return send_error(s, 500, "Internal Server Error");
    }

    char *resp = http_response_begin(e, t);
    http_response_add_time_stamp(resp);
    http_response_add_server(resp, s->server_name);
    http_response_add_content_length(resp, sb.st_size);
    http_response_add_content_type(resp, "text/html; charset=UTF-8");
    http_response_end(resp);
    if (cwrite(s->net_fd, resp, strlen(resp)) != strlen(resp)) {
	free(resp);
	return 1;
    }
    free(resp);

    if (inf) {
	int len = fread(page, 1, sizeof(page), inf);
	fclose(inf);
	if (len > 0) {
	    if (cwrite(s->net_fd, page, len) != len) {
		return 1;
	    }
	}
    } else {
	do_debug("File %s is not found, ignore.\n", path);
    }

    return 0;
}

int send_file(server_arg * s, char *f, char **mime)
{
    char page[BUF_SIZE];
    struct stat sb;
    char *resp;

    FILE *inf = fopen(f, "rb");

    if ((stat(f, &sb) == -1) || (!inf)) {
	do_debug("send_file/stat error!");
	return send_error(s, 500, "Internal Server Error");
    }

    resp = http_response_begin(200, "OK");
    http_response_add_time_stamp(resp);
    http_response_add_server(resp, s->server_name);
    http_response_add_modtime_stamp(resp, &sb.st_mtime);
    http_response_add_content_length(resp, sb.st_size);
    http_response_add_content_type(resp, get_mimetype(f));
    http_response_end(resp);

    if (cwrite(s->net_fd, resp, strlen(resp)) != strlen(resp)) {
	free(resp);
	return 1;
    }
    free(resp);

    while (sb.st_size > 0) {
	int len = (sb.st_size > sizeof(page)) ? sizeof(page) : sb.st_size;
	int nread = fread(page, 1, len, inf);
	if (nread != len) {
	    break;
	}
	if (cwrite(s->net_fd, page, nread) != nread) {
	    break;
	}
	sb.st_size -= nread;
    }

    fclose(inf);

    if (mime) {
	*mime = get_mimetype(f);
    }

    return 0;
}
