
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


#include <memory.h>
#include <pcap.h>

#include "andwatch.h"


#define PCAP_FILTERBUF_SIZE     (sizeof(PCAP_FIXED_FILTER) + PCAP_FILTER_USER_MAX + sizeof(" and ()") - 1)

#define PCAP_FIXED_FILTER       "((arp && not src 0) || " \
                                 "(icmp6 && " \
                                   "(icmp6[icmp6type] == icmp6-neighborsolicit || " \
                                    "icmp6[icmp6type] == icmp6-neighboradvert) && " \
                                   "not src ::))"


//
// Open a pcap session
//
pcap_t * interface_open(
    const char *                interface,
    const int                   snaplen,
    const int                   promisc)
{
    pcap_t *                    pcap;
    int                         r;
    char                        errbuf[PCAP_ERRBUF_SIZE];

    memset(errbuf, 0, sizeof(errbuf));

    // Create the pcap session
    pcap = pcap_create(interface, errbuf);
    if (pcap == NULL)
    {
        fatal("pcap_create for interface %s failed: %s\n", interface, errbuf);
    }

    // Set pcap options
    r = pcap_set_snaplen(pcap, snaplen);
    if (r != 0)
    {
        fatal("pcap_set_snaplen failed: %d\n", r);
    }
    r = pcap_set_promisc(pcap, promisc);
    if (r != 0)
    {
        fatal("pcap_set_promisc failed: %d\n", r);
    }
    r = pcap_set_timeout(pcap, PCAP_TIMEOUT);
    if (r != 0)
    {
        fatal("pcap_set_timeout failed: %d\n", r);
    }

    // Activate the pcap session
    r = pcap_activate(pcap);
    if (r < 0)
    {
        fatal("pcap_activate failed: %s\n", pcap_geterr(pcap));
    }

    return pcap;
}


//
// Run the pcap interface loop
//
void interface_loop(
    pcap_t *                    pcap,
    const char *                user_filter,
    pcap_handler                callback,
    void *                      closure)
{
    struct bpf_program          program;
    char                        filter[PCAP_FILTERBUF_SIZE] = PCAP_FIXED_FILTER;
    int                         r;

    // If the user passed in a filter, append it
    if (user_filter)
    {
        snprintf(filter + sizeof(PCAP_FIXED_FILTER) - 1, sizeof(filter) - sizeof(PCAP_FIXED_FILTER), " and (%s)", user_filter);
    }

    // Compile the filter
    r = pcap_compile(pcap, &program, filter, 1, PCAP_NETMASK_UNKNOWN);
    if (r == PCAP_ERROR)
    {
        fatal("pcap_compile failed: %s\n", pcap_geterr(pcap));
    }

    // Set the filter
    r = pcap_setfilter(pcap, &program);
    if (r != 0)
    {
        fatal("pcap_setfilter failed: %s\n", pcap_geterr(pcap));
    }
    pcap_freecode(&program);

    // Start the party
    pcap_loop(pcap, 0, callback, closure);
}
