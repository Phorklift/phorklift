#include <signal.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>

#include "h2d_main.h"

#define H2D_VERSION "0.1"

static bool opt_daemon = true;
static const char *opt_pid_file = "h2tpd.pid";

static bool sig_reload_conf = false;

static const char *h2d_getopt(int argc, char *const *argv)
{
	const char *help = "Usage: h2tpd [options] conf_file\n"
		"Options:\n"
		"    -p PREFIX   change directory\n"
		"    -i FILE     set pid file [h2tpd.pid]\n"
		"    -m MODULE   add dynamic module\n"
		"    -m @FILE    add dynamic module list file\n"
		"    -f          run in foreground, but not daemon\n"
		"    -r          show configration reference and quit\n"
		"    -v          show version and quit\n"
		"    -h          show this help and quit\n";

	int opt;
	while ((opt = getopt(argc, argv, "p:i:m:rfvh")) != -1) {
		switch (opt) {
		case 'p':
			if (chdir(optarg) != 0) {
				fprintf(stderr, "Fail to chdir to %s : %s\n", optarg, strerror(errno));
				exit(H2D_EXIT_GETOPT);
			}
			break;
		case 'i':
			opt_pid_file = optarg;
			break;
		case 'm':
			h2d_module_dynamic_add(optarg);
			break;
		case 'f':
			opt_daemon = false;
			break;
		case 'r':
			h2d_module_master_init();
			h2d_upstream_init();
			h2d_conf_doc();
			exit(0);
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

pid_t h2d_pid;

static void h2d_signal_worker_quit(int signo)
{
	loop_kill(h2d_loop);
}
static void h2d_worker_entry(void)
{
	h2d_in_worker = true;
	h2d_pid = getpid();

	printf("start worker: %d\n", getpid());

	signal(SIGHUP, SIG_IGN);
	signal(SIGQUIT, h2d_signal_worker_quit);

	prctl(PR_SET_NAME, (unsigned long)"h2tpd-worker", 0, 0, 0);

	loop_new_event(h2d_loop);

	h2d_conf_listen_init_worker();

	h2d_module_worker_init();

	/* go to work! */
	loop_run(h2d_loop);
	printf("!!!!! worker quit\n");
}

static void h2d_signal_reload_conf(int signo)
{
	sig_reload_conf = true;
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

static bool h2d_worker_check(void)
{
	int status;
	pid_t pid = waitpid(-1, &status, WNOHANG);
	if (pid <= 0) {
		return true;
	}
	if (pid < 0) {
		if (errno == EINTR) {
			return true;
		}
		return false; /* errno == ECHILD */
	}

	struct h2d_conf_runtime_worker *worker = &h2d_conf_runtime->worker;

	int i;
	for (i = 0; i < worker->num; i++) {
		if (pid == worker->list[i]) {
			worker->list[i] = 0;
			break;
		}
	}

	if (WIFEXITED(status)) {
		printf("worker %d exit with %d\n", pid, WEXITSTATUS(status));

	} else if (WIFSIGNALED(status)) {
		assert(i < worker->num); /* must found */
		printf("worker %d is terminated by signal %d\n", pid, WTERMSIG(status));
		worker->list[i] = h2d_worker_new();

	} else {
		printf("worker %d quit!\n", pid);
	}

	return h2d_worker_check();
}

static int h2d_run(const char *conf_file)
{
	if (!h2d_conf_parse(conf_file)) {
		return H2D_EXIT_CONF;
	}

	h2d_lua_api_init();

	h2d_module_master_post();

	if (opt_daemon) {
		opt_daemon = false;
		assert(daemon(1, 0) == 0);
	}

	/* start workers */
	struct h2d_conf_runtime_worker *worker = &h2d_conf_runtime->worker;
	for (int i = 0; i < worker->num; i++) {
		worker->list[i] = h2d_worker_new();
	}

	return 0;
}

int main(int argc, char * const *argv)
{
	const char *conf_file = h2d_getopt(argc, argv);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, h2d_signal_reload_conf);
	signal(SIGQUIT, h2d_signal_dispatch);

	/* The loop is run at workers. We create it here because some
	 * initialization need to create timer or defer at the loop.
	 * It will be duplicated to the workers during fork(). */
	h2d_loop = loop_new_noev();

	h2d_ssl_init();
	h2d_http2_init();
	h2d_upstream_init();
	h2d_resolver_init();
	h2d_dynamic_init();
	h2d_request_init();
	h2d_connection_init();
	h2d_log_init(); /* init log at last for loop_defer:flush log at last */

	h2d_module_master_init();

	int ret = h2d_run(conf_file);
	if (ret != 0) {
		return ret;
	}

	/* master */
	while (1) {
		printf("master pause...\n");
		pause(); /* wait for signals */

		if (sig_reload_conf) {
			sig_reload_conf = false;
			h2d_run(conf_file);
		}

		if (!h2d_worker_check()) {
			break;
		}
	}

	return 0;
}
