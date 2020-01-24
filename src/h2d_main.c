#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>

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
		"    -u USER     set worker processes user, only for root []\n"
		"    -w NUM      set worker processes number, 0 means no worker [4]\n"
		"    -p PREFIX   change directory []\n"
		"    -i PID      set pid file [logs/h2tpd.pid]\n"
		"    -d DEFAULT  set user defaults file [conf/defaults.lua]\n"
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
				exit(H2D_EXIT_GETOPT);
			}
			break;
		case 'p':
			if (chdir(optarg) != 0) {
				fprintf(stderr, "Fail to chdir to %s : %s\n", optarg, strerror(errno));
				exit(H2D_EXIT_GETOPT);
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
			exit(H2D_EXIT_GETOPT);
		}
	}
}

loop_t *h2d_loop = NULL;
static void h2d_signal_worker_quit(int signo)
{
	loop_kill(h2d_loop);
}
static void h2d_worker_entry(wuy_array_t *listens)
{
	printf("start worker: %d\n", getpid());

	signal(SIGQUIT, h2d_signal_worker_quit);
	signal(SIGUSR1, h2d_signal_worker_quit);

	prctl(PR_SET_NAME, (unsigned long)"h2tpd-worker", 0, 0, 0);

	h2d_loop = loop_new();

	h2d_upstream_init();
	h2d_request_init();
	h2d_module_worker_init();

	h2d_connection_listen(listens);

	loop_run(h2d_loop);
	printf("!!!!! worker quit\n");
}

static void h2d_signal_dispatch(int signo)
{
	/* Dispatch signals to all worker processes.
	 * Since kill(0, signo) sends signal to this process self too.
	 * we check time here to avoid loop. */
	static time_t last = 0;
	time_t now = time(NULL);
	if (now - last <= 1) {
		return;
	}
	last = now;

	kill(0, signo);
}

int main(int argc, char * const *argv)
{
	h2d_getopt(argc, argv);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGQUIT, h2d_signal_dispatch);
	signal(SIGUSR1, h2d_signal_dispatch);

	h2d_ssl_init();
	h2d_http2_init();

	h2d_module_master_init();

	wuy_array_t *listens = h2d_conf_parse(opt_defaults_file, opt_conf_file);

	h2d_module_master_post();

	if (opt_worker_num == 0) {
		h2d_worker_entry(listens);
		return 0;
	}

	/* start workers */
	for (int i = 0; i < opt_worker_num; i++) {
		pid_t pid = fork();
		if (pid < 0) {
			perror("fail in fork");
			return H2D_EXIT_FORK_WORKER;
		}
		if (pid == 0) {
			h2d_worker_entry(listens);
			exit(0);
		}
	}

	/* master */
	while (1) {
		int status;
		pid_t pid = wait(&status);
		if (pid < 0) {
			if (errno == EINTR) {
				continue;
			}
			break; /* errno == ECHILD */
		}

		if (WIFEXITED(status)) {
			printf("worker %d exit with %d\n", pid, WEXITSTATUS(status));
			continue;
		} else if (WIFSIGNALED(status)) {
			printf("worker %d signal with %d\n", pid, WTERMSIG(status));
		} else {
			printf("worker %d quit!\n", pid);
			continue;
		}

		/* create new worker */
		pid = fork();
		if (pid < 0) {
			perror("fail in fork");
			continue;
		}
		if (pid == 0) {
			h2d_worker_entry(listens);
			exit(0);
		}
	}

	return 0;
}
