/* web service */

#include "http.h"
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

/* Prototype for clearenv if not available */
#if !defined(_GNU_SOURCE) && !defined(__USE_MISC)
extern int clearenv(void);
#endif

int main(int argc, char **argv)
{
    if (argc != 2)
        errx(1, "Usage: zooksvc <control_fd>");

    int control_fd = atoi(argv[1]);
    int client_fd;
    char env_buf[8192];
    ssize_t len;

    for (;;)
    {
        /* Receive FD and environment variables */
        len = recvfd(control_fd, env_buf, sizeof(env_buf), &client_fd);
        
        if (len <= 0) {
            /* Connection closed or error */
            if (len < 0) warn("recvfd");
            break;
        }

        /* Ensure null termination */
        if (len < sizeof(env_buf))
            env_buf[len] = '\0';
        else
            env_buf[sizeof(env_buf)-1] = '\0';

        /* Set environment variables */
        env_deserialize(env_buf, len);

        /* Serve the request */
        http_serve(client_fd, getenv("REQUEST_URI"));

        /* Clean up */
        close(client_fd);
        clearenv();
    }

    return 0;
}
