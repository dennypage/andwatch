
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
#include <memory.h>
#include <stdlib.h>
#include <syslog.h>

#include "andwatch.h"


// Command line variables/flags
const char *                    lib_dir = LIB_DIR;
const char *                    ifname = NULL;
unsigned int                    flag_syslog = 0;



//
// Log abnormal events
//
__attribute__ ((format (printf, 1, 2)))
void logger(
    const char *                format,
    ...)
{
    va_list                     args;

    va_start(args, format);
    if (flag_syslog)
    {
        vsyslog(LOG_WARNING, format, args);
    }
    else
    {
        vfprintf(stderr, format, args);
    }
    va_end(args);
}


//
// Report a fatal error
//
__attribute__ ((noreturn, format (printf, 1, 2)))
void fatal(
    const char *                format,
    ...)
{
    va_list                     args;

    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);

    exit(EXIT_FAILURE);
}


//
// Safe strncpy (ensures null termination)
//
void safe_strncpy(
    char *                      dst,
    const char *                src,
    size_t                      limit
)
{
    size_t                      len = strlen(src);

    if (len >= limit)
    {
        len = limit - 1;
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
}


//
// Do a reverse lookup on a network address
//
void reverse_naddr(
    int                         af_type,
    const void *                addr,
    char *                      host,
    size_t                      hostlen)
{
    union {
        struct sockaddr_storage storage;
        struct sockaddr         sa;
        struct sockaddr_in      ipv4_sin;
        struct sockaddr_in6     ipv6_sin;
    } sock_addr;
    size_t                      addrlen;
    int                         link_local = 0;

    // Set the socket address
    if (af_type == AF_INET)
    {
        sock_addr.ipv4_sin.sin_family = AF_INET;
        addrlen = sizeof(sock_addr.ipv4_sin);
        memcpy(&sock_addr.ipv4_sin.sin_addr, addr, sizeof(sock_addr.ipv4_sin.sin_addr));

        if ((sock_addr.ipv4_sin.sin_addr.s_addr & 0xffff0000) == 0xa9fe0000)
        {
            link_local = 1;
        }
    }
    else
    {
        sock_addr.ipv6_sin.sin6_family = AF_INET6;
        memcpy(&sock_addr.ipv6_sin.sin6_addr, addr, sizeof(sock_addr.ipv6_sin.sin6_addr));
        addrlen = sizeof(struct sockaddr_in6);

        if (IN6_IS_ADDR_LINKLOCAL(&sock_addr.ipv6_sin.sin6_addr))
        {
            link_local = 1;
        }
    }

    // No reverse lookup for link-local addresses
    if (link_local)
    {
        strncpy(host, "(link-local)", hostlen);
        return;
    }

    // Do the reverse lookup
    if (getnameinfo(&sock_addr.sa, addrlen, host, hostlen, NULL, 0, NI_NAMEREQD) != 0)
    {
        strncpy(host, "(unknown)", hostlen);
    }
}


//
// Do a reverse lookup on a printable (text) address
//
void reverse_paddr(
    db_iptype                   type,
    const char *                addr,
    char *                      host,
    size_t                      hostlen)
{
    union {
        struct in_addr          ipv4_addr;
        struct in6_addr         ipv6_addr;
    } ip_addr;
    int                         af_type = 0;

    if (type == DB_IPTYPE_4)
    {
        if (inet_pton(AF_INET, addr, &ip_addr.ipv4_addr) == 1)
        {
            af_type = AF_INET;
        }
    }
    else if (type == DB_IPTYPE_6)
    {
        if (inet_pton(AF_INET6, addr, &ip_addr.ipv6_addr) == 1)
        {
            af_type = AF_INET6;
        }
    }

    if (af_type)
    {
        reverse_naddr(af_type, &ip_addr, host, hostlen);
    }
    else
    {
        strncpy(host, "(none)", hostlen);
    }
}
