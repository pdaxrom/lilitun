#ifndef __CONN_TUNNEL_H__
#define __CONN_TUNNEL_H__

void *tap2net_thread(void *arg);
void *net2tap_thread(void *arg);

int server_tunnel(server_arg * sarg, char *h_url);
int client_tunnel(server_arg * sarg);

#endif
