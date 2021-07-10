#include <signal.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>

#include "phl_main.h"

#define PHL_VERSION "0.0.1"

static bool opt_daemon = true;

static pid_t *phl_workers = NULL;

static bool sig_reload_conf = false;

static const char *phl_getopt(int argc, char *const *argv)
{
	const char *help = "Usage: phorklift [options] conf_file\n"
		"Options:\n"
		"    -p PREFIX   change directory\n"
		"    -f          run in foreground, but not daemon\n"
		"    -r          show configration reference and quit\n"
		"    -v          show version and quit\n"
		"    -h          show this help and quit\n";

	int opt;
	while ((opt = getopt(argc, argv, "p:rfvh")) != -1) {
		switch (opt) {
		case 'p':
			if (chdir(optarg) != 0) {
				fprintf(stderr, "Fail to chdir to %s : %s\n", optarg, strerror(errno));
				exit(PHL_EXIT_GETOPT);
			}
			break;
		case 'f':
			opt_daemon = false;
			break;
		case 'r':
			phl_module_master_init();
			phl_upstream_init();
			phl_conf_doc();
			exit(0);
		case 'v':
			printf("version: %s\n", PHL_VERSION);
			exit(0);
		case 'h':
			printf("%s", help);
			exit(0);
		default:
			printf("%s", help);
			exit(PHL_EXIT_GETOPT);
		}
	}

	if (optind > argc - 1) {
		fprintf(stderr, "argument conf_file is need!\n");
		exit(PHL_EXIT_GETOPT);
	}
	if (optind < argc - 1) {
		fprintf(stderr, "only 1 conf_file is allowed!\n");
		exit(PHL_EXIT_GETOPT);
	}
	return argv[optind];
}

loop_t *phl_loop = NULL;

bool phl_in_worker = false;

pid_t phl_pid;

static void phl_signal_worker_quit(int signo)
{
	loop_kill(phl_loop);
}
static void phl_worker_entry(void)
{
	phl_in_worker = true;
	phl_pid = getpid();

	phl_conf_log(PHL_LOG_INFO, "worker starts!");

	signal(SIGHUP, SIG_IGN);
	signal(SIGQUIT, phl_signal_worker_quit);

	prctl(PR_SET_NAME, (unsigned long)"phorklift-worker", 0, 0, 0);

	loop_new_event(phl_loop);

	phl_conf_listen_init_worker();

	phl_module_worker_init();

	/* go to work! */
	loop_run(phl_loop);

	phl_conf_log(PHL_LOG_INFO, "worker quits!");
}

static void phl_signal_reload_conf(int signo)
{
	sig_reload_conf = true;
}
static void phl_signal_nothing(int signo)
{
}

static void phl_signal_dispatch(int signo)
{
	for (int i = 0; phl_workers[i] != -1; i++) {
		if (phl_workers[i] != 0) {
			kill(phl_workers[i], signo);
		}
	}
}

static pid_t phl_worker_new(void)
{
	pid_t pid = fork();
	if (pid < 0) {
		phl_conf_log(PHL_LOG_ERROR, "fail in fork %s", strerror(errno));
		return -1;
	}
	if (pid == 0) {
		phl_worker_entry();
		exit(0);
	}
	return pid;
}

static bool phl_worker_check(void)
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
		phl_conf_log(PHL_LOG_ERROR, "worker exits with status=%d", WEXITSTATUS(status));

	} else if (WIFSIGNALED(status)) {
		phl_conf_log(PHL_LOG_ERROR, "worker is terminated by signal %d", WTERMSIG(status));
		for (int i = 0; phl_workers[i] != -1; i++) {
			if (pid == phl_workers[i]) {
				phl_workers[i] = phl_worker_new();
				break;
			}
		}
	} else {
		phl_conf_log(PHL_LOG_ERROR, "worker quits!");
	}

	return phl_worker_check();
}

static int phl_run(const char *conf_file)
{
	if (!phl_conf_parse(conf_file)) {
		return PHL_EXIT_CONF;
	}

	phl_lua_api_init();

	phl_conf_log(PHL_LOG_INFO, "start!");

	if (opt_daemon) {
		fprintf(stdout, "go to daemon.\n");
		opt_daemon = false;
		assert(daemon(1, 0) == 0);
		phl_pid = getpid();

		phl_resolver_init_if_fork();
	}

	/* start workers */
	int worker_num = phl_conf_runtime->worker.num;
	if (worker_num < 0) {
		phl_worker_entry();
		exit(0);
	}

	pid_t *workers = malloc((worker_num + 1) * sizeof(pid_t));
	for (int i = 0; i < worker_num; i++) {
		workers[i] = phl_worker_new();
	}
	workers[worker_num] = -1;

	/* sleep 10 ms to wait new workers start */
	usleep(10000);

	/* stop old workers */
	if (phl_workers != NULL) {
		for (int i = 0; phl_workers[i] != -1; i++) {
			if (phl_workers[i] != 0) {
				kill(phl_workers[i], SIGQUIT);
			}
		}

		free(phl_workers);
	}

	phl_workers = workers;
	return 0;
}

int main(int argc, char * const *argv)
{
	phl_pid = getpid();
	const char *conf_file = phl_getopt(argc, argv);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, phl_signal_nothing); /* to wake up pause() */
	signal(SIGHUP, phl_signal_reload_conf);
	signal(SIGQUIT, phl_signal_dispatch);

	/* The loop is run at workers. We create it here because some
	 * initialization need to create timer or defer at the loop.
	 * It will be duplicated to the workers during fork(). */
	phl_loop = loop_new_noev();

	phl_ssl_init();
	phl_http2_init();
	phl_upstream_init();
	phl_resolver_init();
	phl_dynamic_init();
	phl_request_init();
	phl_connection_init();
	phl_log_init(); /* init log at last for loop_defer:flush log at last */

	phl_module_master_init();

	int ret = phl_run(conf_file);
	if (ret != 0) {
		fprintf(stderr, "FAIL TO START!!!\n");
		return ret;
	}

	/* this is not updated if reloading configration */
	FILE *fp = fopen(phl_conf_runtime->pid, "w");
	fprintf(fp, "%d\n", getpid());
	fclose(fp);

	/* master */
	while (1) {
		phl_conf_log(PHL_LOG_INFO, "master pause...");
		pause(); /* wait for signals */
		phl_conf_log(PHL_LOG_INFO, "master wake up");

		if (sig_reload_conf) {
			phl_conf_log(PHL_LOG_INFO, "reload configration");
			sig_reload_conf = false;
			phl_run(conf_file);
		}

		if (!phl_worker_check()) {
			break;
		}
	}

	unlink(phl_conf_runtime->pid);

	return 0;
}
