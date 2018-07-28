#ifndef __HTTP_H__

char *http_response_begin(int status, char *reason);
char *http_response_add_content_type(char *resp, char *mime);
char *http_response_add_content_length(char *resp, size_t length);
char *http_response_add_connection(char *resp, char *token);
char *http_response_add_accept_ranges(char *resp);
char *http_response_add_range(char *resp, size_t from, size_t to,
			      size_t length);
char *http_response_end(char *resp);

int send_404(server_arg * s, char *url);
int send_error(server_arg * s, int e, char *t);
int send_file(server_arg * s, char *f, int h);

#endif
