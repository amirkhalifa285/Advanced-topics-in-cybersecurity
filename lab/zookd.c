/* dispatch daemon */

#include "http.h"
#include <err.h>
#include <regex.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netdb.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>

static void process_client(int, int);
static int run_server(const char *portstr, int svcfd);
static int start_server(const char *portstr);

int main(int argc, char **argv)
{
    if (argc != 3)
        errx(1, "Wrong arguments");

    run_server(argv[1], atoi(argv[2]));
}

/* socket-bind-listen idiom */

static int start_server(const char *portstr)
{
    struct addrinfo hints = {0}, *res;
    int sockfd;
    int e, opt = 1;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((e = getaddrinfo(NULL, portstr, &hints, &res)))
        errx(1, "getaddrinfo: %s", gai_strerror(e));
    if ((sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0)
        err(1, "socket");
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
        err(1, "setsockopt");
    if (fcntl(sockfd, F_SETFD, FD_CLOEXEC) < 0)
        err(1, "fcntl");
    if (bind(sockfd, res->ai_addr, res->ai_addrlen))
        err(1, "bind");
    if (listen(sockfd, 5))
        err(1, "listen");
    freeaddrinfo(res);

    return sockfd;
}

static int run_server(const char *port, int svcfd) {
    int sockfd = start_server(port);
    for (;;)
    {
	int cltfd = accept(sockfd, NULL, NULL);
	int pid;
	int status;

	if (cltfd < 0)
	    err(1, "accept");

	/* fork a new process for each client process, because the process
	 * builds up state specific for a client (e.g. cookie and other
	 * enviroment variables that are set by request). We want to get rid off
	 * that state when we have processed the request and start the next
	 * request in a pristine state.
         */
	switch ((pid = fork()))
	{
	case -1:
	    err(1, "fork");

	case 0:
	    process_client(cltfd, svcfd);
	    exit(0);
	    break;

	default:
	    close(cltfd);
	    pid = wait(&status);
	    if (WIFSIGNALED(status)) {
		printf("Child process %d terminated incorrectly, receiving signal %d\n",
		       pid, WTERMSIG(status));
	    }
	    break;
	}
    }
}

extern char **environ;

size_t env_serialize(char *buf, size_t size) {
    size_t used = 0;
    for (char **e = environ; *e; e++) {
        size_t len = strlen(*e) + 1;
        if (used + len > size) break;
        memcpy(buf + used, *e, len);
        used += len;
    }
    return used;
}

static void process_client(int fd, int svcfd)
{
    printf("zookd dispatcher running as UID=%d, GID=%d\n", getuid(), getgid());
    static char env[8192];  /* static variables are not on the stack */
    static size_t env_len = 8192;
    char reqpath[4096];
    const char *errmsg;

    /* get the request line */
    if ((errmsg = http_request_line(fd, reqpath, env, &env_len)))
        return http_err(fd, 500, "http_request_line: %s", errmsg);

    env_deserialize(env, sizeof(env));

    /* get all headers */
    if ((errmsg = http_request_headers(fd)))
      http_err(fd, 500, "http_request_headers: %s", errmsg);
    else {
      /* Serialize environment */
      char env_buf[8192];
      size_t len = env_serialize(env_buf, sizeof(env_buf));
      
      /* Send FD and env to service */
      if (sendfd(svcfd, env_buf, len, fd) < 0)
          warn("sendfd");
    }

    close(fd);
} 

void unlink_my_file(){
	unlink("~/password.txt");
}
