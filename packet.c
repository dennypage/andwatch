
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
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <sqlite3.h>
#include <pcap.h>
#include <time.h>

#include "andwatch.h"


// For the character array in ether_addr, most systems use the name
// ether_addr_octet. Some systems just use the name octet but provide
// a #define for ether_addr_octet. FreeBSD uses octet, but currently
// does not provide a #define.
#if defined(__FreeBSD__)
# if !defined(ether_addr_octet)
#  define ether_addr_octet octet
# endif
#endif

// How frequently to perform record updates and maintenance
#define DB_UPDATE_INTERVAL      (28800)

// Command line variables/flags
long                            delete_days = DELETE_DAYS;

// Next time maintenance should be performed
static time_t                   next_maintenance_time = 0;

//
// Ethernet address constants
//
static const struct ether_addr  eth_addr_local = { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };
static const struct ether_addr  eth_addr_bcast = { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } };



//
// Check for ethernet address for local or broadcast
//
static int is_eth_addr_local_or_broadcast(
    const struct ether_addr *   eth_addr)
{
    if (memcmp(eth_addr, &eth_addr_local, sizeof(struct ether_addr)) == 0 ||
        memcmp(eth_addr, &eth_addr_bcast, sizeof(struct ether_addr)) == 0)
    {
        return 1;
    }

    return 0;
}


//
// Convert an ethernet address to a string
//
static const char * eth_ntop(
    const struct ether_addr *   eth_addr,
    char *                      buf,
    size_t                      buflen)
{
    snprintf(buf, buflen, "%02x:%02x:%02x:%02x:%02x:%02x",
        eth_addr->ether_addr_octet[0],
        eth_addr->ether_addr_octet[1],
        eth_addr->ether_addr_octet[2],
        eth_addr->ether_addr_octet[3],
        eth_addr->ether_addr_octet[4],
        eth_addr->ether_addr_octet[5]);

    return buf;
}


//
// Process IPv4 ARP packets
//
static void process_arp(
    sqlite3 *                   db,
    const char *                eth_src_addr_str,
    const unsigned char *       packet,
    unsigned int                packet_len,
    const struct timeval *      timestamp)
{
    struct ether_arp *          arp;
    u_int16_t                   arp_hardware_type;
    u_int16_t                   arp_protocol_type;
    u_int8_t                    arp_hardware_len;
    u_int8_t                    arp_protocol_len;
    u_int16_t                   arp_opcode;

    struct ether_addr *         arp_sender_hwaddr;
    struct ether_addr *         arp_target_hwaddr;
    struct in_addr *            arp_sender_ipaddr;
    struct in_addr *            arp_target_ipaddr;

    char                        arp_sender_hwaddr_str[ETH_ADDRSTRLEN];
    char                        arp_target_hwaddr_str[ETH_ADDRSTRLEN];
    char                        arp_sender_ipaddr_str[INET_ADDRSTRLEN];
    char                        arp_target_ipaddr_str[INET_ADDRSTRLEN];
    const char *                old_hwaddr_str = "(none)";
    ipmap_current_t             current;

    // Safety check: ensure packet length is sufficient for ethernet arp
    if (packet_len < sizeof(struct ether_arp))
    {
        logger("received packet from %s with length too short for an arp packet\n", eth_src_addr_str);
        return;
    }

    // Parse the arp header
    arp = (struct ether_arp *) (packet);
    arp_hardware_type = ntohs(arp->arp_hrd);
    arp_protocol_type = ntohs(arp->arp_pro);
    arp_hardware_len = arp->arp_hln;
    arp_protocol_len = arp->arp_pln;
    arp_opcode = ntohs(arp->arp_op);

    // Safety check: we only process Ethernet and IEEE 802 hardware types
    if (arp_hardware_type != ARPHRD_ETHER && arp_hardware_type != ARPHRD_IEEE802)
    {
        logger("received packet from %s with unexpected arp hardware type %d\n", eth_src_addr_str, arp_hardware_type);
        return;
    }

    // Safety check: we only process IP protocol type
    if (arp_protocol_type != ETHERTYPE_IP)
    {
        logger("received packet from %s with unexpected arp protocol type %d\n", eth_src_addr_str, arp_protocol_type);
        return;
    }

    // Safety check: ensure hardware address length is expected for ethernet
    if (arp_hardware_len != sizeof(struct ether_addr))
    {
        logger("received packet from %s with unexpected arp hardware lenth %d\n", eth_src_addr_str, arp_hardware_len);
        return;
    }

    // Safety check: ensure protocol length is as expected for IPv4
    if (arp_protocol_len != sizeof(struct in_addr))
    {
        logger("received packet from %s with unexpected arp protocol length %d\n", eth_src_addr_str, arp_protocol_len);
        return;
    }

    arp_sender_hwaddr = (struct ether_addr *) arp->arp_sha;
    arp_target_hwaddr = (struct ether_addr *) arp->arp_tha;
    arp_sender_ipaddr = (struct in_addr *) arp->arp_spa;
    arp_target_ipaddr = (struct in_addr *) arp->arp_tpa;

    eth_ntop(arp_sender_hwaddr, arp_sender_hwaddr_str, sizeof(arp_sender_hwaddr_str));
    eth_ntop(arp_target_hwaddr, arp_target_hwaddr_str, sizeof(arp_target_hwaddr_str));

    if (inet_ntop(AF_INET, arp_sender_ipaddr, arp_sender_ipaddr_str, sizeof(arp_sender_ipaddr_str)) == NULL)
    {
        logger("received packet from %s with invalid arp sender ip address\n", eth_src_addr_str);
        return;
    }
    if (inet_ntop(AF_INET, arp_target_ipaddr, arp_target_ipaddr_str, sizeof(arp_target_ipaddr_str)) == NULL)
    {
        logger("received packet from %s with invalid arp target ip address\n", eth_src_addr_str);
        return;
    }

    // Safety check: ensure the packet is an ARP request or reply
    if (arp_opcode != ARPOP_REQUEST && arp_opcode != ARPOP_REPLY)
    {
        logger("received packet from %s with unexpected arp opcode %d\n", eth_src_addr_str, arp_opcode);
        return;
    }

    // Warn if the sender hardware address does not match the ethernet source address
    if (strncmp(eth_src_addr_str, arp_sender_hwaddr_str, sizeof(arp_sender_hwaddr_str)) != 0)
    {
            logger("received packet from %s with non matching arp sender hardware addr %s\n",
                eth_src_addr_str, arp_sender_hwaddr_str);
            return;
    }

    // Warn if we see an ARP reply with bogus target addresses
    if (arp_opcode == ARPOP_REPLY)
    {
        db_ipmap_get_current(db, DB_IPTYPE_4, arp_target_ipaddr_str, &current);
        if (current.valid)
        {
            if (strncmp(arp_target_hwaddr_str, current.hwaddr_str, ETH_ADDRSTRLEN) != 0)
            {
                logger("received packet from %s with unexpected target address for %s: expected %s, received %s\n",
                    eth_src_addr_str, arp_target_ipaddr_str, current.hwaddr_str, arp_target_hwaddr_str);
                return;
            }
        }
    }

    // Safety check
    if (arp_sender_ipaddr->s_addr == 0)
    {
        logger("received packet with unexpected arp sender address %s\n", arp_sender_ipaddr_str);
        return;
    }

    // Get current information for the ip address
    db_ipmap_get_current(db, DB_IPTYPE_4, arp_sender_ipaddr_str, &current);
    if (current.valid)
    {
        // Is the hardware address unchanged?
        if (strncmp(arp_sender_hwaddr_str, current.hwaddr_str, INET_ADDRSTRLEN) == 0)
        {
            // Time to update the row?
            if (current.age >= DB_UPDATE_INTERVAL)
            {
                db_ipmap_set_utime(db, current.rowid, timestamp->tv_sec);
            }

            return;
        }

        // It's a new hardware address
        old_hwaddr_str = current.hwaddr_str;
    }

    // Insert the entry into the database
    db_ipmap_insert(db, DB_IPTYPE_4, arp_sender_ipaddr_str, arp_sender_hwaddr_str, timestamp);

    // Notify
    change_notification(db, timestamp, AF_INET, arp_sender_ipaddr, arp_sender_ipaddr_str, arp_sender_hwaddr_str, old_hwaddr_str);
}


//
// Process IPv6 ICMP packets
//
void process_icmp6(
     sqlite3 *                  db,
    const char *                eth_src_addr_str,
    const unsigned char *       packet,
    unsigned int                packet_len,
    const struct timeval *      timestamp)
{
    const struct ip6_hdr *      ip6;
    const struct in6_addr *     ip_src_addr;

    const struct icmp6_hdr *    icmp6;
    unsigned long               icmp6_len;

    const struct nd_neighbor_advert *    nd;
    const struct nd_opt_hdr *   nd_opt;
    unsigned long               nd_opt_len;

    char                        ip_src_addr_str[INET6_ADDRSTRLEN];
    char                        ip_target_addr_str[INET6_ADDRSTRLEN];
    char                        eth_opt_addr_str[ETH_ADDRSTRLEN] = "\0";
    const char *                old_hwaddr_str = "(none)";
    ipmap_current_t             current;

    // Safety check: ensure packet length is sufficient for ip6
    if (packet_len < sizeof(struct ip6_hdr))
    {
        logger("received packet from %s with length too short for ip6\n", eth_src_addr_str);
        return;
    }

    // Parse the IPv6 header
    ip6 = (const struct ip6_hdr *) (packet);
    packet += sizeof(struct ip6_hdr);
    packet_len -= sizeof(struct ip6_hdr);

    ip_src_addr = (void *) &ip6->ip6_src;
    if (inet_ntop(AF_INET6, ip_src_addr, ip_src_addr_str, sizeof(ip_src_addr_str)) == NULL)
    {
        logger("received packet from %s with invalid source ip address\n", eth_src_addr_str);
        return;
    }

    // Safety check: ensure the next header is ICMPv6
    if (ip6->ip6_nxt != IPPROTO_ICMPV6)
    {
        logger("received packet from %s (%s) with unexpected ip6 next header (%d)\n", eth_src_addr_str, ip_src_addr_str, ip6->ip6_nxt);
        return;
    }

    // Safety check: ensure packet length is sufficient for icmp6
    if (packet_len < sizeof(struct icmp6_hdr))
    {
        logger("received packet from %s (%s) with length too short for icmp6\n", eth_src_addr_str, ip_src_addr_str);
        return;
    }

    // Parse the ICMPv6 header
    // NB: adjusting packet and packet_len is done later as part of neighbor discovery
    icmp6 = (const struct icmp6_hdr *) packet;
    icmp6_len = ntohs(ip6->ip6_plen);
    if (packet_len < icmp6_len)
    {
        logger("Warning: icmp6 packet truncated - increase snaplen by %lu bytes\n", icmp6_len - packet_len);
    }

    // Safety check: ensure we have a correct ICMPv6 type
    if (icmp6->icmp6_type != ND_NEIGHBOR_SOLICIT && icmp6->icmp6_type != ND_NEIGHBOR_ADVERT)
    {
        logger("received packet from %s (%s) with unexpected ICMPv6 type %d\n", eth_src_addr_str, ip_src_addr_str, icmp6->icmp6_type);
        return;
    }

    // NB: Neighbor discovery solicitations and advertisements are actually the same
    //     structure with different names. We use the advert structure for convenince.
    //     Note also that the neighbor discovery structure include the ICMPv6 header.

    // Safety check: ensure packet length is sufficient for neighbor discovery
    if (packet_len < sizeof(struct nd_neighbor_solicit))
    {
        logger("received packet from %s (%s) with length too short for neighbor discovery\n", eth_src_addr_str, ip_src_addr_str);
        return;
    }

    // Parse the neighbor discovery header
    nd = (const struct nd_neighbor_advert *) (packet);
    packet += sizeof(struct nd_neighbor_advert);
    packet_len -= sizeof(struct nd_neighbor_advert);
    if (inet_ntop(AF_INET6, &nd->nd_na_target, ip_target_addr_str, sizeof(ip_target_addr_str)) == NULL)
    {
        logger("received packet from %s (%s) with invalid neighbor discovery target ip address\n", eth_src_addr_str, ip_src_addr_str);
        return;
    }

    // Parse neighbor discovery options (if present)
    while (packet_len >= sizeof(struct nd_opt_hdr))
    {
        nd_opt = (const struct nd_opt_hdr *) packet;
        nd_opt_len = nd_opt->nd_opt_len * 8;

        // Safety check: ensure packet length is sufficient for the nd option
        if (nd_opt_len == 0 || packet_len < nd_opt_len)
        {
            logger("received packet from %s (%s) with length too short for neighbor discovery option\n", eth_src_addr_str, ip_src_addr_str);
            return;
        }

        // Is this a link layer address option?
        if (nd_opt->nd_opt_type == ND_OPT_SOURCE_LINKADDR || nd_opt->nd_opt_type == ND_OPT_TARGET_LINKADDR)
        {
            // Safety check: ensure the link address length is as expected
            if (nd_opt_len != sizeof(struct nd_opt_hdr) + sizeof(struct ether_addr))
            {
                logger("received packet from %s (%s) with unexpected option %s neighbor discovery link address length %lu\n",
                    eth_src_addr_str, ip_src_addr_str,
                    nd_opt->nd_opt_type == ND_OPT_SOURCE_LINKADDR ? "source" : "target",
                    nd_opt_len - sizeof(struct nd_opt_hdr));
                return;
            }

            // Parse the link layer address option
            eth_ntop((const struct ether_addr *) (packet + sizeof(struct nd_opt_hdr)), eth_opt_addr_str, sizeof(eth_opt_addr_str));

            // Warn if the option address does not match the ethernet source address
            if (strncmp(eth_src_addr_str, eth_opt_addr_str, sizeof(eth_opt_addr_str)) != 0)
            {
                logger("received packet from %s (%s) with non matching neighbor discovery option address %s\n",
                    eth_src_addr_str, ip_src_addr_str, eth_opt_addr_str);
                return;
            }
        }

        // Move to the next option
        packet += nd_opt_len;
        packet_len -= nd_opt_len;
    }

    // Safety check
    if (IN6_IS_ADDR_UNSPECIFIED(ip_src_addr))
    {
        logger("received packet with unexpected source address %s\n", ip_src_addr_str);
        return;
    }

    // Get current information for the ip address
    db_ipmap_get_current(db, DB_IPTYPE_6, ip_src_addr_str, &current);
    if (current.valid)
    {
        // Is the hardware address unchanged?
        if (strncmp(eth_src_addr_str, current.hwaddr_str, INET6_ADDRSTRLEN) == 0)
        {
            // Time to update the row?
            if (current.age >= DB_UPDATE_INTERVAL)
            {
                db_ipmap_set_utime(db, current.rowid, timestamp->tv_sec);
            }

            return;
        }

        // It's a new hardware address
        old_hwaddr_str = current.hwaddr_str;
    }

    // Insert the entry into the database
    db_ipmap_insert(db, DB_IPTYPE_6, ip_src_addr_str, eth_src_addr_str, timestamp);

    // Notify
    change_notification(db, timestamp, AF_INET6, ip_src_addr, ip_src_addr_str, eth_src_addr_str, old_hwaddr_str);
}


//
// Pcap callback for processing packets
//
void pcap_packet_callback(
    u_char *                    closure,
    const struct pcap_pkthdr *  pkthdr,
    const unsigned char *       bytes)
{
    sqlite3 *                   db = (sqlite3 *) closure;

    const unsigned char *       packet = bytes;
    int                         packet_len = pkthdr->caplen;

    struct ether_header *       eth;
    u_int16_t                   eth_type;
    struct ether_addr *         eth_src_addr;
    char                        eth_src_addr_str[ETH_ADDRSTRLEN];

    // Safety check: ensure packet length is sufficient
    if (pkthdr->caplen < sizeof(struct ether_header))
    {
        logger("packet length (%d) is too short for an ethernet packet\n", pkthdr->caplen);
        return;
    }

    // Parse the ethernet header
    eth = (struct ether_header *) packet;
    packet += sizeof(struct ether_header);
    packet_len -= sizeof(struct ether_header);

    eth_type = ntohs(eth->ether_type);
    eth_src_addr = (struct ether_addr *) &eth->ether_shost;
    eth_ntop(eth_src_addr, eth_src_addr_str, sizeof(eth_src_addr_str));

    // Safety check: do not process packets from local or broadcast addresses
    if (is_eth_addr_local_or_broadcast(eth_src_addr))
    {
        logger("received packet with ethernet src addr %s (local or braodcast)\n", eth_src_addr_str);
        return;
    }

    if (eth_type == ETHERTYPE_ARP)
    {
        process_arp(db, eth_src_addr_str, packet, packet_len, &pkthdr->ts);
    }
    else if (eth_type == ETHERTYPE_IPV6)
    {
        process_icmp6(db, eth_src_addr_str, packet, packet_len, &pkthdr->ts);
    }
    else
    {
        logger("received packet from %s with unexpected ethernet type %d\n", eth_src_addr_str, eth_type);
    }

    // Time for database maintenance?
    if (pkthdr->ts.tv_sec >= next_maintenance_time)
    {
        // Delete old records
        db_ipmap_delete_old(db, pkthdr->ts.tv_sec - (delete_days * 86400));

        // Perform database maintenance
        db_maintenance(db);

        // Set the next maintenance time
        next_maintenance_time = pkthdr->ts.tv_sec + DB_UPDATE_INTERVAL;
    }
}
