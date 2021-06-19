#ifndef PHL_MAIN_H
#define PHL_MAIN_H

/* include common headers here */
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <assert.h>
#include <time.h>
#include <ctype.h>
#include <string.h>

#include "libwuya/wuy_dict.h"
#include "libwuya/wuy_slist.h"
#include "libwuya/wuy_list.h"
#include "libwuya/wuy_heap.h"
#include "libwuya/wuy_nop_list.h"
#include "libwuya/wuy_nop_hlist.h"
#include "libwuya/wuy_cflua.h"
#include "libwuya/wuy_tcp.h"
#include "libwuya/wuy_sockaddr.h"
#include "libwuya/wuy_http.h"
#include "libwuya/wuy_json.h"
#include "libwuya/wuy_base64.h"
#include "libwuya/wuy_shmpool.h"
#include "libwuya/wuy_pool.h"
#include "libwuya/wuy_time.h"
#include "libwuya/wuy_rand.h"
#include "libwuya/wuy_vhash.h"
#include "libwuya/wuy_luastr.h"

#include "libloop/loop.h"

#include "libhttp2/http2.h"

#include "phl_module.h"
#include "phl_dynamic.h"
#include "phl_conf.h"
#include "phl_connection.h"
#include "phl_request.h"
#include "phl_http1.h"
#include "phl_http2.h"
#include "phl_header.h"
#include "phl_ssl.h"
#include "phl_upstream.h"
#include "phl_resolver.h"
#include "phl_lua_thread.h"
#include "phl_lua_call.h"
#include "phl_lua_api.h"
#include "phl_log.h"

/* return values */
#define PHL_OK			0
#define PHL_ERROR		-1
#define PHL_AGAIN		-2
#define PHL_BREAK		-3

#define PHL_PTR_ERROR		(void *)-1
#define PHL_PTR_AGAIN		(void *)-2

#define PHL_PTR2RET(pr)		((intptr_t)pr)
#define PHL_PTR_IS_OK(pr)	(PHL_PTR2RET(pr) > 0)

/* exit status */
#define PHL_EXIT_OK		0
#define PHL_EXIT_GETOPT		1
#define PHL_EXIT_CONF		2
#define PHL_EXIT_MODULE_INIT	3
#define PHL_EXIT_FORK_WORKER	4
#define PHL_EXIT_RESOLVER	5
#define PHL_EXIT_DYNAMIC	6

#define MIN(a, b) (a)<(b)?(a):(b)
#define MAX(a, b) (a)>(b)?(a):(b)

/* global event-driven loop */
extern loop_t *phl_loop;

extern bool phl_in_worker;

extern pid_t phl_pid;

#endif
