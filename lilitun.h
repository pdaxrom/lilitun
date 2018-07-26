#ifndef __LILITUN_H__

typedef struct {
    int net_fd;
    int tap_fd;
    int use_aes;
    int rbuffer_size;
    char *rbuffer;
    int rbuffered;
    char *client_ip;
    char *server_name;
    char *web_prefix;
    int vpn_is_alive;
    int debug;
} server_arg;

int cwrite(int fd, char *buf, int n);

#endif
