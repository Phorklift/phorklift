#include <signal.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>

#include "h2d_main.h"

#define H2D_VERSION "0.0.1"

static bool opt_daemon = true;
static const char *opt_pid_file = "h2tpd.pid";

static pid_t *h2d_workers = NULL;

static bool sig_reload_conf = false;

static const char *h2d_getopt(int argc, char *const *argv)
{
	const char *help = "Usage: h2tpd [options] conf_file\n"
		"Options:\n"
		"    -p PREFIX   change directory\n"
		"    -i FILE     set pid file [h2tpd.pid]\n"
		"    -f          run in foreground, but not daemon\n"
		"    -r          show configration reference and quit\n"
		"    -v          show version and quit\n"
		"    -h          show this help and quit\n";

	int opt;
	while ((opt = getopt(argc, argv, "p:i:rfvh")) != -1) {
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

	h2d_conf_log(H2D_LOG_INFO, "worker starts!");

	signal(SIGHUP, SIG_IGN);
	signal(SIGQUIT, h2d_signal_worker_quit);

	prctl(PR_SET_NAME, (unsigned long)"h2tpd-worker", 0, 0, 0);

	loop_new_event(h2d_loop);

	h2d_conf_listen_init_worker();

	h2d_module_worker_init();

	/* go to work! */
	loop_run(h2d_loop);

	h2d_conf_log(H2D_LOG_INFO, "worker quits!");
}

static void h2d_signal_reload_conf(int signo)
{
	sig_reload_conf = true;
}
static void h2d_signal_nothing(int signo)
{
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
		h2d_conf_log(H2D_LOG_ERROR, "fail in fork %s", strerror(errno));
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
	if (pid == 0) {
		return true;
	}
	if (pid < 0) {
		if (errno == EINTR) {
			return true;
		}
		return false; /* errno == ECHILD */
	}

	if (WIFEXITED(status)) {
		h2d_conf_log(H2D_LOG_ERROR, "worker exits with status=%d", WEXITSTATUS(status));

	} else if (WIFSIGNALED(status)) {
		h2d_conf_log(H2D_LOG_ERROR, "worker is terminated by signal %d", WTERMSIG(status));
		for (int i = 0; h2d_workers[i] != -1; i++) {
			if (pid == h2d_workers[i]) {
				h2d_workers[i] = h2d_worker_new();
				break;
			}
		}
	} else {
		h2d_conf_log(H2D_LOG_ERROR, "worker quits!");
	}

	return h2d_worker_check();
}

static int h2d_run(const char *conf_file)
{
	if (!h2d_conf_parse(conf_file)) {
		return H2D_EXIT_CONF;
	}

	h2d_lua_api_init();

	h2d_conf_log(H2D_LOG_INFO, "start!");

	if (opt_daemon) {
		fprintf(stdout, "go to daemon.\n");
		opt_daemon = false;
		assert(daemon(1, 0) == 0);
		h2d_pid = getpid();

		h2d_resolver_init_if_fork();
	}

	/* start workers */
	int worker_num = h2d_conf_runtime->worker.num;
	if (worker_num < 0) {
		h2d_worker_entry();
		return 0;
	}

	pid_t *workers = malloc((worker_num + 1) * sizeof(pid_t));
	for (int i = 0; i < worker_num; i++) {
		workers[i] = h2d_worker_new();
	}
	workers[worker_num] = -1;

	/* sleep 10 ms to wait new workers start */
	usleep(10000);

	/* stop old workers */
	if (h2d_workers != NULL) {
		for (int i = 0; h2d_workers[i] != -1; i++) {
			if (h2d_workers[i] != 0) {
				kill(h2d_workers[i], SIGQUIT);
			}
		}

		free(h2d_workers);
	}

	h2d_workers = workers;
	return 0;
}

int main(int argc, char * const *argv)
{
	h2d_pid = getpid();
	const char *conf_file = h2d_getopt(argc, argv);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, h2d_signal_nothing); /* to wake up pause() */
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
		fprintf(stderr, "FAIL TO START!!!\n");
		return ret;
	}

	/* master */
	while (1) {
		h2d_conf_log(H2D_LOG_INFO, "master pause...");
		pause(); /* wait for signals */
		h2d_conf_log(H2D_LOG_INFO, "master wake up");

		if (sig_reload_conf) {
			h2d_conf_log(H2D_LOG_INFO, "reload configration");
			sig_reload_conf = false;
			h2d_run(conf_file);
		}

		if (!h2d_worker_check()) {
			break;
		}
	}

	return 0;
}
