
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include "andwatch.h"


// External notify command
const char *                    notify_cmd = NULL;


//
// Change notifications
//
void change_notification(
    sqlite3 *                   db,
    const struct timeval *      timeval,
    int                         af_type,
    const void *                addr,
    const char *                ipaddr,
    const char *                new_hwaddr,
    const char *                old_hwaddr)
{
    struct tm *                 tm;
    pid_t                       pid;
    char                        new_hwaddr_org[MA_ORG_NAME_LIMIT] = "(none)";
    char                        old_hwaddr_org[MA_ORG_NAME_LIMIT] = "(none)";
    const char *                argv[10];
    char                        timestamp[71];
    char                        hostname[HOSTNAME_LEN];

    // Log the change
    logger("IP address %s changed from %s to %s\n", ipaddr, old_hwaddr, new_hwaddr);

    // If the notify command is not set, return
    if (notify_cmd == NULL)
    {
        return;
    }

    // Fork a child process
    pid = fork();
    if (pid == -1)
    {
        logger("fork failed: %s\n", strerror(errno));
        return;
    }

    // Parent is done
    if (pid)
    {
        return;
    }

    // Format the timestamp
    tm = localtime(&timeval->tv_sec);
    snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02d %02d:%02d:%02d",
        tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
        tm->tm_hour, tm->tm_min, tm->tm_sec);

    // Get the hostname
    reverse_naddr(af_type, addr, hostname, sizeof(hostname));

    // Get the hardware orgs
    if (new_hwaddr[0] != '(')
    {
        db_query_ma(db, new_hwaddr, new_hwaddr_org);
    }
    if (old_hwaddr[0] != '(')
    {
        db_query_ma(db, old_hwaddr, old_hwaddr_org);
    }

    // Build the argv array
    argv[0] = notify_cmd;
    argv[1] = timestamp;
    argv[2] = ifname;
    argv[3] = hostname;
    argv[4] = ipaddr;
    argv[5] = new_hwaddr;
    argv[6] = new_hwaddr_org;
    argv[7] = old_hwaddr;
    argv[8] = old_hwaddr_org;
    argv[9] = NULL;

    // Execute the command
    execv(notify_cmd, (char * const *) argv);
}
