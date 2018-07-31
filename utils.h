#ifndef __UTILS_H__
#define __UTILS_H__

char *copy_str(char *dst, int dst_size, char *src, int src_size);

char *header_get_method(char *header, char *str, int n);
char *header_get_url(char *header, char *str, int n);
char *header_get_spec(char *header, char *str, int n);
char *header_get_field(char *header, char *field, char *str, int n);

char *url_get_path(char *url, char *path, int n);

int generate_session_key(server_arg * sarg);
void free_session_key(server_arg *sarg);

void buf2hex(uint8_t *buf, int n, char *hex);
void hex2buf(char *hex, int n, uint8_t *buf);

#endif
