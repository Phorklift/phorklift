#include <signal.h>
#include <errno.h>

#include "h2d_main.h"

#define H2D_VERSION "0.1"

static int opt_worker_num = 4;
static const char *opt_worker_user = NULL;
static const char *opt_pid_file = "logs/h2tpd.pid";
static const char *opt_defaults_file = "conf/defaults.lua";
static const char *opt_conf_file = "conf/h2tpd.lua";

static void h2d_getopt(int argc, char *const *argv)
{
	const char *help = "Usage: h2tpd [options]\n"
		"Options:\n"
		"    -u USER     set worker user, only for root []\n"
		"    -w NUM      set worker number, 0 for no worker for debugging [4]\n"
		"    -p PREFIX   change directory []\n"
		"    -i PID      set pid file [logs/h2tpd.pid]\n"
		"    -d DEFAULT  set user defaults file [conf/user_defaults.lua]\n"
		"    -c CONF     set configuration file [conf/h2tpd.lua]\n"
		"    -v          show version and quit\n"
		"    -h          show this help and quit\n";

	int opt;
	char *endptr;
	while ((opt = getopt(argc, argv, "u:w:p:i:d:c:vh")) != -1) {
		switch (opt) {
		case 'u':
			opt_worker_user = strdup(optarg);
			break;
		case 'w':
			opt_worker_num = strtol(optarg, &endptr, 0);
			if (endptr[0] != '\0') {
				fprintf(stderr, "Invalid option worker number: %s\n", optarg);
				exit(-1);
			}
			break;
		case 'p':
			if (chdir(optarg) != 0) {
				fprintf(stderr, "Fail to chdir to %s : %s\n", optarg, strerror(errno));
				exit(-1);
			}
			break;
		case 'i':
			opt_pid_file = strdup(optarg);
			break;
		case 'd':
			opt_defaults_file = strdup(optarg);
			break;
		case 'c':
			opt_conf_file = strdup(optarg);
			break;
		case 'v':
			printf("version: %s\n", H2D_VERSION);
			exit(0);
		case 'h':
			printf("%s", help);
			exit(0);
		default:
			printf("%s", help);
			exit(-1);
		}
	}
}

loop_t *h2d_loop;
int main(int argc, char * const *argv)
{
	/* command line options */
	h2d_getopt(argc, argv);

	/* initialization */
	signal(SIGPIPE, SIG_IGN); /* for network */

	h2d_loop = loop_new();

	h2d_module_master_init();

	h2d_ssl_init();
	h2d_http2_init();
	h2d_upstream_init();
	h2d_request_init();

	/* configuration */
	wuy_array_t *listens = h2d_conf_parse(opt_defaults_file, opt_conf_file);
	if (listens == NULL) {
		return -1;
	}

	h2d_module_master_post();

	/* listen */
	if (!h2d_connection_listen(listens)) {
		return -1;
	}

	/* run */
	printf("start working loop\n");
	loop_run(h2d_loop);

	return 0;
}
