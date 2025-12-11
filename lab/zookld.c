/* zookld.c - Launcher Daemon */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <err.h>

static int zookd_pid = -1;
static int zooksvc_pid = -1;
static int authsvc_pid = -1; // New PID for auth service
static int sv[2]; // Socket pair for zookd and zooksvc
static int auth_sv[2]; // New socket pair for auth service

/* UIDs/GIDs for privilege separation */
#define DISPATCHER_UID 6000
#define DISPATCHER_GID 6000
#define SERVICE_UID 6001
#define SERVICE_GID 11111  // Changed from 6001 to 11111 for IPC group
#define AUTH_UID 33333 // From setup.sh
#define AUTH_GID 11111 // From setup.sh

void launch_zookd() {
    if ((zookd_pid = fork()) < 0) err(1, "fork zookd");
    if (zookd_pid == 0) {
        /* Child */
        close(sv[1]); // Close the service end
        close(auth_sv[0]); // Close the auth service end
        close(auth_sv[1]); // Close the auth service end
        char port[] = "8080";
        char fd_str[16];
        sprintf(fd_str, "%d", sv[0]);
        
        /* Drop privileges */
        /* Note: In a real scenario, we should ensure these IDs exist or use valid ones */
        if (setgid(DISPATCHER_GID) < 0) warn("setgid dispatcher");
        if (setuid(DISPATCHER_UID) < 0) warn("setuid dispatcher");
        
        /* Exec */
        execl("./zookd", "zookd", port, fd_str, NULL);
        err(1, "execl zookd");
    }
}

void setup_jail() {
    /* Create directories for jail */
    mkdir("lib", 0755);
    mkdir("lib64", 0755);
    mkdir("usr", 0755);
    mkdir("bin", 0755); // For shell or other utils if needed
    mkdir("zoobar", 0755); // Ensure zoobar dir exists in jail for Python scripts
    mkdir("zoobar/db", 0755); // Ensure zoobar/db exists for Cred database
    mkdir("authsvc", 0755); // Ensure authsvc directory for socket

    /* Bind mount system directories */
    /* Note: We rely on setup.sh to perform the actual mounts to avoid duplication */
}

void launch_zooksvc() {
    if ((zooksvc_pid = fork()) < 0) err(1, "fork zooksvc");
    if (zooksvc_pid == 0) {
        /* Child */
        close(sv[0]); // Close the dispatcher end
        close(auth_sv[0]); // Close the auth service end
        close(auth_sv[1]); // Close the auth service end
        char fd_str[16];
        sprintf(fd_str, "%d", sv[1]);

        /* Setup Jail */
        setup_jail();

        /* Jail and Drop privileges */
        /* We assume the current directory is set up as a jail (bind mounts etc) */
        if (chroot(".") < 0) warn("chroot failed (need root)");
        
        if (setgid(SERVICE_GID) < 0) warn("setgid service");
        if (setuid(SERVICE_UID) < 0) warn("setuid service");
        
        /* Exec */
        /* Inside jail, /zooksvc is at the root */
        execl("/zooksvc", "zooksvc", fd_str, NULL);
        /* Fallback if chroot failed or path differs */
        execl("./zooksvc", "zooksvc", fd_str, NULL);
        err(1, "execl zooksvc");
    }
}

void launch_authsvc() {
    if ((authsvc_pid = fork()) < 0) err(1, "fork authsvc");
    if (authsvc_pid == 0) {
        /* Child */
        close(sv[0]); // Close dispatcher ends
        close(sv[1]); // Close dispatcher ends
        close(auth_sv[0]); // Close the launcher end of auth socket

        char fd_str[16];
        sprintf(fd_str, "%d", auth_sv[1]); // Pass the service end of the auth socket

        char sockpath[] = "/authsvc/sock"; // Socket path for auth service

        /* Setup Jail - authsvc also needs common jail setup */
        setup_jail();

        /* Chroot and Drop privileges for auth service */
        if (chroot(".") < 0) warn("chroot failed for authsvc (need root)");

        // Make sure the zoobar folder is available inside the chroot
        // and its dependencies are also available.
        // Assuming /usr/bin/python3 exists inside the jail via bind mount from setup.sh
        
        if (setgid(AUTH_GID) < 0) warn("setgid authsvc");
        if (setuid(AUTH_UID) < 0) warn("setuid authsvc");
        
        /* Exec python script */
        execl("/usr/bin/python3", "python3", "zoobar/auth-server.py", fd_str, sockpath, NULL);
        err(1, "execl auth-server.py");
    }
}

int main(int argc, char **argv) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
        err(1, "socketpair for zookd/zooksvc");
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, auth_sv) < 0) // New socket pair for auth
        err(1, "socketpair for authsvc");

    /* Ignore SIGPIPE in parent to avoid exit if a child closes socket */
    signal(SIGPIPE, SIG_IGN);

    printf("Launching zookd...\n");
    launch_zookd();
    printf("Launching zooksvc...\n");
    launch_zooksvc();
    printf("Launching authsvc...\n");
    launch_authsvc(); // Launch the auth service

    for (;;) {
        int status;
        int pid = wait(&status);
        if (pid < 0) {
            // perror("wait");
            continue;
        }

        if (pid == zookd_pid) {
            warnx("zookd (pid %d) died, restarting", pid);
            launch_zookd();
        } else if (pid == zooksvc_pid) {
            warnx("zooksvc (pid %d) died, restarting", pid);
            launch_zooksvc();
        } else if (pid == authsvc_pid) { // Monitor auth service
            warnx("authsvc (pid %d) died, restarting", pid);
            launch_authsvc();
        }
    }
    return 0;
}
