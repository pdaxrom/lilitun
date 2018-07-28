#ifndef __LILITUN_H__

#define BUFSIZE 2048

typedef struct {
    int net_fd;
    int tap_fd;
    int use_aes;
    aes_context *aes_ctx;
    int rbuffer_size;
    char *rbuffer;
    int rbuffered;
    int mode;
    char *client_ip;
    char *server_name;
    char *web_prefix;
    int vpn_is_alive;
    int debug;
    int ping_time;
    pthread_mutex_t mutex_net_write;
} server_arg;

extern char server_id[6];
extern char client_id[6];

void dump16(char *ptr);
void dump_SrcDst(char *p);

int cread(int fd, char *buf, int n);
int cwrite(int fd, char *buf, int n);

#endif
