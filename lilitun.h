#ifndef __LILITUN_H__

typedef struct {
    int net_fd;
    int tap_fd;
    int use_aes;
    char *web_prefix;
} server_arg;

void do_debug(char *msg, ...);
int cwrite(int fd, char *buf, int n);

#endif
