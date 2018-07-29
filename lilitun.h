#ifndef __LILITUN_H__

#define BUFSIZE 2048

typedef struct {
    pthread_mutex_t mutex_net_write;
    int net_fd;
    int tap_fd;
    char *tap_if_name;
    int tap_flags;

    int use_aes;
    aes_context *aes_ctx;

    int rbuffer_size;
    char *rbuffer;
    int rbuffered;

    char *session_key;
    char *session_key_aes;
    char *session_key_hex;
    char *session_id;

    int mode;

    char *client_ip;
    char *server_name;
    char *web_prefix;

    int vpn_is_alive;
    int debug;
    int ping_time;
} server_arg;

extern char server_id[6];
extern char client_id[6];

void dump16(char *ptr);
void dump_SrcDst(char *p);

int tun_alloc(char *dev, int flags);

int cread(int fd, char *buf, int n);
int cwrite(int fd, char *buf, int n);

#endif
