#ifndef __LILITUN_H__

typedef struct {
    int net_fd;
    int tap_fd;
    int use_aes;
    char *server_name;
    char *web_prefix;
    int vpn_is_alive;
} server_arg;

void do_debug(char *msg, ...);
int cwrite(int fd, char *buf, int n);

#endif
