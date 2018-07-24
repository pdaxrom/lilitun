#ifndef __UTILS_H__
#define __UTILS_H__

char *copy_str(char *dst, int dst_size, char *src, int src_size);

char *header_get_method(char *header, char *str, int n);
char *header_get_url(char *header, char *str, int n);
char *header_get_spec(char *header, char *str, int n);

char *url_get_path(char *url, char *path, int n);

#endif
