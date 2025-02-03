
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
#include <time.h>

#include "andwatch.h"


// The command for externalnotifications
const char *                    notify_cmd = NULL;


//
// Change notifications
//
void change_notification(
    sqlite3 *                   db,
    const char *                ipaddr,
    const char *                old_hwaddr,
    const char *                new_hwaddr,
    const struct timeval *      timeval)
{
    struct tm *                 tm;
    char                        old_hwaddr_org[MA_ORG_NAME_LIMIT] = "";
    char                        new_hwaddr_org[MA_ORG_NAME_LIMIT] = "";
    char                        system_cmd[4096];

    // Log the change
    logger("IP address %s changed from %s to %s\n", ipaddr, old_hwaddr, new_hwaddr);

    // If the notify command is not set, return
    if (notify_cmd == NULL)
    {
        return;
    }

    // Get the old and new hardware orgs
    if (old_hwaddr[0] != '(')
    {
        db_query_ma(db, old_hwaddr, old_hwaddr_org);
    }
    if (new_hwaddr[0] != '(')
    {
        db_query_ma(db, new_hwaddr, new_hwaddr_org);
    }

    // Create the command string
    tm = localtime(&timeval->tv_sec);
    snprintf(system_cmd, sizeof(system_cmd), "%s '%04d-%02d-%02d %02d:%02d:%02d' '%s' '%s' '%s' '%s' '%s' '%s' &",
        notify_cmd,
        tm->tm_year + 1900,
        tm->tm_mon + 1,
        tm->tm_mday,
        tm->tm_hour,
        tm->tm_min,
        tm->tm_sec,
        ifname,
        ipaddr,
        old_hwaddr,
        old_hwaddr_org,
        new_hwaddr,
        new_hwaddr_org);

    // Execute the command
    (void) system(system_cmd);
}
