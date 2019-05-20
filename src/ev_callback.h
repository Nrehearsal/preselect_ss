#ifndef _EV_CALLBACK_
#define _EV_CALLBACK_

void accept_cb(EV_P_ ev_io *w, int revents);

void server_recv_cb(EV_P_ ev_io *w, int revents);
void server_send_cb(EV_P_ ev_io *w, int revents);
void server_timeout_cb(EV_P_ ev_timer *watcher, int revents);

void remote_recv_cb(EV_P_ ev_io *w, int revents);
void remote_send_cb(EV_P_ ev_io *w, int revents);

void resolve_recv_cb(EV_P_ ev_io *w, int revents);
void resolve_send_cb(EV_P_ ev_io *w, int revents);

#endif
