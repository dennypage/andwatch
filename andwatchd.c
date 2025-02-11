
//
// Copyright (c) 2025, Denny Page
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>

#include "andwatch.h"


// Command line variables/flags
static const char *             progname;
static unsigned int             foreground = 0;
static unsigned int             promisc = 1;
static const char *             pidfile_name = NULL;
static const char *             user_filter = NULL;
static int                      snaplen = PCAP_SNAPLEN;


//
// Termination handler
//
__attribute__ ((noreturn))
static void term_handler(
    int                         signum)
{
    // Remove the pid file if in use
    if (pidfile_name)
    {
        (void) unlink(pidfile_name);
    }
    logger("exiting on signal %d\n", signum);
    exit(0);
}



//
// Create pid file
//
static int create_pidfile(void)
{
    int                         pidfile_fd = -1;
    char                        pidbuf[64];
    pid_t                       pid;
    ssize_t                     rs;
    int                         r;

    // Attempt to create the pid file
    pidfile_fd = open(pidfile_name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (pidfile_fd != -1)
    {
        // Lock the pid file
        r = flock(pidfile_fd, LOCK_EX | LOCK_NB);
        if (r == -1)
        {
            fatal("lock of pid file %s failed: %s\n", pidfile_name, strerror(errno));
        }
    }
    else
    {
        // Pid file already exists?
        pidfile_fd = open(pidfile_name, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
        if (pidfile_fd == -1)
        {
            fatal("create/open of pid file %s failed: %s\n", pidfile_name, strerror(errno));
        }

        // Lock the pid file
        r = flock(pidfile_fd, LOCK_EX | LOCK_NB);
        if (r == -1)
        {
            fatal("pid file %s is in use by another process\n", pidfile_name);
        }

        // Check for existing pid
        rs = read(pidfile_fd, pidbuf, sizeof(pidbuf) - 1);
        if (rs > 0)
        {
            pidbuf[rs] = 0;
            pid = (pid_t) strtol(pidbuf, NULL, 10);
            if (pid > 0)
            {
                // Is the pid still alive?
                r = kill(pid, 0);
                if (r == 0)
                {
                    fatal("pid file %s is in use by process %u\n", pidfile_name, (unsigned int) pid);
                }
            }
        }

        // Reset the pid file
        (void) lseek(pidfile_fd, 0, 0);
        r = ftruncate(pidfile_fd, 0);
        if (r == -1)
        {
            fatal("write of pid file %s failed: %s\n", pidfile_name, strerror(errno));
        }
    }

    return pidfile_fd;
}


//
// Write pid file
//
static void write_pidfile(
    int                         pidfile_fd)
{
    char                        pidbuf[64];
    ssize_t                     len;
    ssize_t                     rs;
    int                         r;

    len = snprintf(pidbuf, sizeof(pidbuf), "%u\n", (unsigned) getpid());
    if (len < 0 || (size_t) len > sizeof(pidbuf))
    {
        fatal("error formatting pidfile\n");
    }

    rs = write(pidfile_fd, pidbuf, (size_t) len);
    if (rs == -1)
    {
        fatal("write of pidfile %s failed: %s\n", pidfile_name, strerror(errno));
    }

    r = close(pidfile_fd);
    if (r == -1)
    {
        fatal("close of pidfile %s failed: %s\n", pidfile_name, strerror(errno));
    }
}



//
// Parse command line arguments
//
__attribute__ ((noreturn))
static void usage(void)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s [-h] [-f] [-s] [-n cmd] [-p file] [-F filter] [-L dir] [-O days] [-P] [-S len] ifname\n", progname);
    fprintf(stderr, "  options:\n");
    fprintf(stderr, "    -h display usage\n");
    fprintf(stderr, "    -f run in foreground\n");
    fprintf(stderr, "    -s log notifications via syslog\n");
    fprintf(stderr, "    -n command for notifications\n");
    fprintf(stderr, "    -p process id file name\n");
    fprintf(stderr, "    -F additional pcap filter (max %d bytes)\n", PCAP_FILTER_USER_MAX);
    fprintf(stderr, "    -L directory for database files (default: %s)\n", LIB_DIR);
    fprintf(stderr, "    -O number of days before deleting old records (default: %u)\n", DELETE_DAYS);
    fprintf(stderr, "    -P disable promiscuous mode\n");
    fprintf(stderr, "    -S pcap snaplen (default/minimum: %u)\n", PCAP_SNAPLEN);
    fprintf(stderr, "  \nNotes:\n");
    fprintf(stderr, "    The notification command is invoked as \"cmd date_time ifname ipaddr old_hwaddr old_hwaddr_org new_hwaddr new_hwaddr_org\"\n");
    fprintf(stderr, "    For details on tcpdump/pcap filter formats, see https://www.tcpdump.org/manpages/pcap-filter.7.html\n");

    exit(1);
}

static void parse_args(
    int                         argc,
    char * const                argv[])
{
    int                         opt;
    char *                      p;

    progname = argv[0];

    while((opt = getopt(argc, argv, "hfsn:p:F:L:O:PS:")) != -1)
    {
        switch (opt)
        {
        case 'f':
            foreground = 1;
            break;
        case 's':
            flag_syslog = 1;
            break;
        case 'n':
            notify_cmd = optarg;
            break;
        case 'p':
            pidfile_name = optarg;
            break;
        case 'F':
            user_filter = optarg;
            if (strlen(user_filter) > PCAP_FILTER_USER_MAX)
            {
                usage();
            }
            break;
        case 'L':
            lib_dir = optarg;
            break;
        case 'O':
            delete_days = strtol(optarg, &p, 10);
            if (*p != '\0' || delete_days < 1)
            {
                usage();
            }
            break;
        case 'P':
            promisc = 0;
            break;
        case 'S':
            snaplen = strtol(optarg, &p, 10);
            if (*p != '\0' || snaplen < PCAP_SNAPLEN)
            {
                usage();
            }
            break;
        default:
            usage();
        }
    }

    // Ensure we have the correct number of parameters
    if (argc != optind + 1)
    {
        usage();
        exit(EXIT_FAILURE);
    }
    ifname = argv[optind];

    // Safty check: Ensure the library path and interface name are not too long
    if (ANDWATCH_PATH_BUFFER <= strlen(lib_dir) + sizeof("/") + strlen(ifname) + sizeof(DB_SUFFIX))
    {
        fatal("db_filename (%s/%s%s) exceeds maximum length of %d\n",
            lib_dir, ifname, DB_SUFFIX, ANDWATCH_PATH_BUFFER);
    }
}


//
// Main
//
int main(
    int                         argc,
    char * const                argv[])
{
    pcap_t *                    pcap;
    sqlite3 *                   db;
    int                         pidfile_fd = -1;
    pid_t                       pid;
    struct sigaction            act;

    // Handle command line args
    parse_args(argc, argv);

    // Open the pcap interface
    pcap = interface_open(ifname, snaplen, promisc);

    // Drop privileges
    (void) setgid(getgid());
    (void) setuid(getuid());

    // Open the ipmap database and attach the malist database
    db = db_ipmap_open(ifname, DB_READ_WRITE);
    db_ma_attach(db);

    // Termination handler
    memset(&act, 0, sizeof(act));
    act.sa_handler = (void (*)(int)) term_handler;
    (void) sigaction(SIGTERM, &act, NULL);
    (void) sigaction(SIGINT, &act, NULL);

    // Create pid file if requested
    if (pidfile_name)
    {
        pidfile_fd = create_pidfile();
    }

    // Self background
    if (foreground == 0)
    {
        pid = fork();

        if (pid == -1)
        {
            fatal("fork failed: %s\n", strerror(errno));
        }

        if (pid)
        {
            _exit(EXIT_SUCCESS);
        }

        (void) setsid();
    }

    // Write pid file if requested
    if (pidfile_fd != -1)
    {
        write_pidfile(pidfile_fd);
    }

    // Start the pcap loop
    interface_loop(pcap, user_filter, pcap_packet_callback, db);

    return 0;
}
