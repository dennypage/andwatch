
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


#ifndef _COMMON_H
#define _COMMON_H 1

#include <time.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <sqlite3.h>
#include <pcap.h>


// Version number of andwatch
#define VERSION                 "1.0.1"

// Default directory for the andwatch data files
#ifndef LIB_DIR
# define LIB_DIR                "/var/lib/andwatch"
#endif

// Default update time (minutes)
#define UPDATE_MINUTES          (10)

// Default delete time (days)
#define DELETE_DAYS             (30)

// Buffer size for various strings
#define ANDWATCH_PATH_BUFFER    (1024)
#define ANDWATCH_SQL_BUFFER     (1024)

// MA database and table names
#define MA_DB_NAME              "ma_db"
#define MA_L_NAME               "ma_l"
#define MA_M_NAME               "ma_m"
#define MA_S_NAME               "ma_s"
#define MA_U_NAME               "ma_u"
#define MA_ORG_NAME_LIMIT       (128)

// File suffixes
#define DB_SUFFIX               ".sqlite"
#define CSV_SUFFIX              ".csv"
#define TMP_SUFFIX              ".tmp"

//
// Notes on snapshot length for pcap
//
// IPv4 ARP (fixed size):       42 bytes
//  ether header                14
//  arp header                  28
//
// IPv6 ICMP ND (minimum size): 86 bytes
//  ether header                14
//  ip6 hdr                     40
//  nd solicit / advertise      24 (includes icmp6 hdr of size 8)
//  nd option link layer addr    8 (includes nd_opt_header of size 2)
//
//  NB: IPv6 ICMP ND packets are actually variable sized, and
//      additional nd options may be present. However we choose
//      to assume that the link layer address option will be the
//      first in order to keep the snapshot length small.
//
#define PCAP_SNAPLEN            (86)

// Filter for pcap
#define PCAP_FILTER             "arp || (icmp6 && (icmp6[icmp6type] == icmp6-neighborsolicit || icmp6[icmp6type] == icmp6-neighboradvert))"

// Pcap/packet options
#define PCAP_TIMEOUT            (100)

// Ethernet address string length
#define ETH_ADDRSTRLEN          (18)


//
// Common types and structures
//

// Database write mode
typedef enum db_write_mode
{
    DB_READ_ONLY = 0,
    DB_READ_WRITE = 1
} db_write_mode;

// Database write mode
typedef enum db_iptype
{
    DB_IPTYPE_ANY = 0,
    DB_IPTYPE_4 = 4,
    DB_IPTYPE_6 = 6
} db_iptype;


// Structure for current info query on an ip address
typedef struct ipmap_current {
    // Valid flag
    int                         valid;

    // Row ID in the table
    long                        rowid;

    // Time in minutes since last update
    long                        age;

    // Current hardware address
    char                        hwaddr_str[ETH_ADDRSTRLEN];
} ipmap_current_t;


// Command line variables/flags
extern unsigned int             flag_syslog;
extern const char *             lib_dir;
extern const char *             ifname;
extern const char *             notify_cmd;
extern long                     update_minutes;
extern long                     delete_days;

//
// Global functions
//

// Log for abnormal events
__attribute__ ((format (printf, 1, 2)))
extern void logger(
    const char *                format,
    ...);

// Fatal error
__attribute__ ((noreturn, format (printf, 1, 2)))
extern void fatal(
    const char *                format,
    ...);

// Safe strncpy (ensures null termination)
extern void safe_strncpy(
    char *                      dst,
    const char *                src,
    size_t                      limit);

// Open a pcap interface
extern pcap_t * interface_open(
    const char *                interface,
    const int                   snaplen,
    const int                   promisc);

// Start a pcap session
extern void interface_loop(
    pcap_t *                    pcap,
    const char *                filter,
    pcap_handler                callback,
    void *                      closure);

// Pcap callback for processing packets
extern void pcap_packet_callback(
    u_char *                    closure,
    const struct pcap_pkthdr *  pkghdr,
    const unsigned char *       bytes);

// Open an ipmap database
extern sqlite3 * db_ipmap_open(
    const char *                db_name,
    db_write_mode               write);

// Open the ma database
extern sqlite3 * db_ma_open(
    db_write_mode               write);

// Attach the ma database
extern void db_ma_attach(
    sqlite3 *                   db);

// Drop and re-create the tables in the ma database
extern void db_ma_recreate_tables(
    sqlite3 *                   db);

// Perform maintenance on the database
extern void db_maintenance(
    sqlite3 *                   db);

// Close a database
extern void db_close(
    sqlite3 *                   db);

// Begin a transaction
extern void db_begin_transaction(
    sqlite3 *                   db);

// End a transaction
extern void db_end_transaction(
    sqlite3 *                   db);

// Insert an entry into the ma database
extern void db_ma_insert(
    sqlite3 *                   db,
    const char *                table,
    const char *                prefix,
    const char *                org);

// Insert an entry in an ipmap database
extern void db_ipmap_insert(
    sqlite3 *                   db,
    db_iptype                   iptype,
    const char *                ipaddr,
    const char *                hwaddr,
    const struct timeval *      timeval);

extern void db_ipmap_delete_old(
    sqlite3 *                   db,
    time_t                      time);

// Get the current (last) values for an ip address
extern void db_ipmap_get_current(
    sqlite3 *                   db,
    db_iptype                   iptype,
    const char *                ipaddr,
    ipmap_current_t *           current);

// Set the update time for a row
extern void db_ipmap_set_utime(
    sqlite3 *                   db,
    long                        rowid,
    time_t                      time);

// Lookup the organization name for a mac address
extern void db_query_ma(
    sqlite3 *                   db,
    const char *                hwaddr,
    char *                      org);

// Dump an ipmap database
extern void db_ipmap_dump(
    sqlite3 *                   db);

// Generate a report of ip address to hardware address mappings for an ip type
extern void db_ipmap_report(
    sqlite3 *                   db,
    db_iptype                   iptype);

extern void db_ipmap_query(
    sqlite3 *                   db,
    const db_iptype             iptype,
    const unsigned int          all,
    const char *                ipaddr);

// Change notifications
extern void change_notification(
    sqlite3 *                   db,
    const char *                ipaddr,
    const char *                old_hwaddr,
    const char *                new_hwaddr,
    const struct timeval *      timeval);

#endif
