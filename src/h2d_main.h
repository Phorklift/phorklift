#ifndef H2D_MAIN_H
#define H2D_MAIN_H

/* include common headers here */
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <assert.h>
#include <time.h>
#include <string.h>

#include "libwuya/wuy_dict.h"
#include "libwuya/wuy_slist.h"
#include "libwuya/wuy_list.h"
#include "libwuya/wuy_nop_list.h"
#include "libwuya/wuy_nop_hlist.h"
#include "libwuya/wuy_cflua.h"
#include "libwuya/wuy_tcp.h"
#include "libwuya/wuy_sockaddr.h"
#include "libwuya/wuy_http.h"
#include "libwuya/wuy_json.h"
#include "libwuya/wuy_base64.h"
#include "libwuya/wuy_shmpool.h"
#include "libwuya/wuy_time.h"
#include "libwuya/wuy_rand.h"
#include "libwuya/wuy_murmurhash.h"

#include "libloop/loop.h"

#include "libhttp2/http2.h"

#include "h2d_module.h"
#include "h2d_dynamic.h"
#include "h2d_conf.h"
#include "h2d_connection.h"
#include "h2d_request.h"
#include "h2d_http1.h"
#include "h2d_http2.h"
#include "h2d_header.h"
#include "h2d_ssl.h"
#include "h2d_upstream.h"
#include "h2d_resolver.h"
#include "h2d_lua_api.h"
#include "h2d_log.h"

/* return values */
#define H2D_OK			0
#define H2D_ERROR		-1
#define H2D_AGAIN		-2

#define H2D_PTR_ERROR		(void *)-1
#define H2D_PTR_AGAIN		(void *)-2

#define H2D_PTR2RET(pr)		((intptr_t)pr)
#define H2D_PTR_IS_OK(pr)	(H2D_PTR2RET(pr) > 0)

/* exit status */
#define H2D_EXIT_OK		0
#define H2D_EXIT_GETOPT		1
#define H2D_EXIT_CONF		2
#define H2D_EXIT_MODULE_INIT	3
#define H2D_EXIT_FORK_WORKER	4
#define H2D_EXIT_RESOLVER	5
#define H2D_EXIT_DYNAMIC	6

#define MIN(a, b) (a)<(b)?(a):(b)
#define MAX(a, b) (a)>(b)?(a):(b)

/* global event-driven loop */
extern loop_t *h2d_loop;

extern bool h2d_in_worker;

#endif
