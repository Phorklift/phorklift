#include <signal.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>

#include "h2d_main.h"

#define H2D_VERSION "0.1"

static int opt_worker_num = 0;
static const char *opt_pid_file = "h2tpd.pid";
static const char *opt_error_file = "error.log";

static const char *h2d_getopt(int argc, char *const *argv)
{
	const char *help = "Usage: h2tpd [options] conf_file\n"
		"Options:\n"
		"    -p PREFIX   change directory\n"
		"    -w NUM      set #worker processes, 0:#cpu-core, -1:disable [0]\n"
		"    -i FILE     set pid file [h2tpd.pid]\n"
		"    -e FILE     set error log file [error.log]\n"
		"    -m MODULE   add dynamic module\n"
		"    -m @FILE    add dynamic module list file\n"
		"    -v          show version and quit\n"
		"    -h          show this help and quit\n";

	int opt;
	char *endptr;
	while ((opt = getopt(argc, argv, "w:p:i:m:e:vh")) != -1) {
		switch (opt) {
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
			opt_pid_file = optarg;
			break;
		case 'e':
			opt_error_file = optarg;
			break;
		case 'm':
			h2d_module_dynamic_add(optarg);
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

	if (optind > argc - 1) {
		fprintf(stderr, "argument conf_file is need!\n");
		exit(H2D_EXIT_GETOPT);
	}
	if (optind < argc - 1) {
		fprintf(stderr, "only 1 conf_file is allowed!\n");
		exit(H2D_EXIT_GETOPT);
	}
	return argv[optind];
}

loop_t *h2d_loop = NULL;

bool h2d_in_worker = false;

static void h2d_signal_worker_quit(int signo)
{
	loop_kill(h2d_loop);
}
static void h2d_worker_entry(void)
{
	printf("start worker: %d\n", getpid());

	signal(SIGQUIT, h2d_signal_worker_quit);

	prctl(PR_SET_NAME, (unsigned long)"h2tpd-worker", 0, 0, 0);

	h2d_in_worker = true;

	loop_new_event(h2d_loop);

	h2d_connection_add_listen_event();

	h2d_module_worker_init();

	/* go to work! */
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

static pid_t h2d_worker_new(void)
{
	pid_t pid = fork();
	if (pid < 0) {
		perror("fail in fork");
		return -1;
	}
	if (pid == 0) {
		h2d_worker_entry();
		exit(0);
	}
	return pid;
}

int main(int argc, char * const *argv)
{
	const char *conf_file = h2d_getopt(argc, argv);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGQUIT, h2d_signal_dispatch);

	/* The loop is run at workers. We create it here because some
	 * initialization need to create timer or defer at the loop.
	 * It will be duplicated to the workers during fork(). */
	h2d_loop = loop_new_noev();

	h2d_log_global(opt_error_file);
	h2d_ssl_init();
	h2d_http2_init();
	h2d_upstream_init();
	h2d_resolver_init();
	h2d_dynamic_init();
	h2d_log_init();
	h2d_request_init();
	h2d_connection_init();

	h2d_module_master_init();

	h2d_conf_parse(conf_file);

	h2d_module_master_post();

	h2d_lua_api_init();

	if (opt_worker_num < 0) {
		h2d_worker_entry();
		return 0;
	}

	/* start workers */
	if (opt_worker_num == 0) {
		opt_worker_num = sysconf(_SC_NPROCESSORS_ONLN);
	}
	for (int i = 0; i < opt_worker_num; i++) {
		if (h2d_worker_new() < 0) {
			return H2D_EXIT_FORK_WORKER;
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

		} else if (WIFSIGNALED(status)) {
			printf("worker %d is terminated by signal %d\n", pid, WTERMSIG(status));
			h2d_worker_new();

		} else {
			printf("worker %d quit!\n", pid);
		}
	}

	return 0;
}
