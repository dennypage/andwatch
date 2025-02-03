
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
#include <memory.h>
#include <ctype.h>
#include <sqlite3.h>
#include <time.h>

#include "andwatch.h"


//
// Database table, index and column names
//

// MA names
#define TBL_MA_L                MA_L_NAME
#define TBL_MA_M                MA_M_NAME
#define TBL_MA_S                MA_S_NAME
#define TBL_MA_U                MA_U_NAME
#define COL_PREFIX              "prefix"
#define COL_OFFSET              "off"
#define COL_LENGTH              "len"
#define COL_ORG                 "org"

// IP map names
#define TBL_IPMAP               "ipmap"
#define IDX_IPMAP_LAST          "ipmap_last"
#define COL_ROWID               "rowid"
#define COL_IPTYPE              "iptype"
#define COL_IPADDR              "ipaddr"
#define COL_HWADDR              "hwaddr"
#define COL_SEC                 "sec"
#define COL_USEC                "usec"
#define COL_UTIME               "utime"


//
// Open a database
//
static sqlite3 * db_open(
    const char *                db_name,
    db_write_mode               write)
{
    char                        db_filename[ANDWATCH_PATH_BUFFER];
    sqlite3 *                   db;
    int                         flags;
    int                         r;

    // Construct the database filename
    snprintf(db_filename, sizeof(db_filename), "%s/%s%s", lib_dir, db_name, DB_SUFFIX);

    // Set the flags
    if (write == DB_READ_WRITE)
    {
        flags = SQLITE_OPEN_URI | SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
    }
    else
    {
        flags = SQLITE_OPEN_URI | SQLITE_OPEN_READONLY;
    }

    // Open the database
    r = sqlite3_open_v2(db_filename, &db, flags, NULL);
    if (r != SQLITE_OK)
    {
        fatal("sqlite3 open of %s failed: %s\n", db_filename, sqlite3_errmsg(db));
    }

    // If write is required, ensure the database is not read-only
    if (write == DB_READ_WRITE)
    {
        r = sqlite3_db_readonly(db, NULL);
        if (r != SQLITE_OK)
        {
            fatal("sqlite3 open of %s failed: read-only database\n", db_filename);
        }
    }

    return db;
}


//
// Open an ipmap database
//
sqlite3 * db_ipmap_open(
    const char *                filename,
    db_write_mode               write)
{
    sqlite3 *                   db;
    int                         r;

    // SQL to create the ipmap table
    //
    #define SQL_IPMAP_CREATE_TABLE \
        "CREATE TABLE IF NOT EXISTS " TBL_IPMAP " (" \
            COL_IPTYPE " TEXT NOT NULL," \
            COL_IPADDR " TEXT NOT NULL," \
            COL_HWADDR " TEXT NOT NULL," \
            COL_SEC " INTEGER NOT NULL," \
            COL_USEC " INTEGER NOT NULL," \
            COL_UTIME " INTEGER NOT NULL" \
        ");" \
        "CREATE INDEX IF NOT EXISTS " IDX_IPMAP_LAST " ON " TBL_IPMAP "(" \
            COL_IPTYPE "," COL_IPADDR "," COL_SEC "," COL_USEC \
        ");"

    // Open the database
    db = db_open(filename, write);
    if (write == DB_READ_WRITE)
    {
        // Create the table if it does not exist
        r = sqlite3_exec(db, SQL_IPMAP_CREATE_TABLE, NULL, NULL, NULL);
        if (r != SQLITE_OK)
        {
            fatal("sqlite3 create table failed: %s\n", sqlite3_errmsg(db));
        }
    }

    return db;
}


//
// Create the tables in the ma database
//
static void db_ma_create_tables(
    sqlite3 *                   db)
{
    int                         r;

    // SQL to create the ma database tables and indexes
    //
    #define SQL_MA_CREATE_TABLES \
        "CREATE TABLE IF NOT EXISTS " TBL_MA_L " (" \
            COL_PREFIX " TEXT NOT NULL PRIMARY KEY ON CONFLICT REPLACE," \
            COL_ORG " TEXT NOT NULL" \
        ");\n" \
        "CREATE TABLE IF NOT EXISTS " TBL_MA_M " (" \
            COL_PREFIX " TEXT NOT NULL PRIMARY KEY ON CONFLICT REPLACE," \
            COL_ORG " TEXT NOT NULL" \
        ");\n" \
        "CREATE TABLE IF NOT EXISTS " TBL_MA_S " (" \
            COL_PREFIX " TEXT NOT NULL PRIMARY KEY ON CONFLICT REPLACE," \
            COL_ORG " TEXT NOT NULL" \
        ");" \
        "CREATE TABLE IF NOT EXISTS " TBL_MA_U " (" \
            COL_PREFIX " TEXT NOT NULL PRIMARY KEY ON CONFLICT REPLACE," \
            COL_ORG " TEXT NOT NULL" \
        ");"

    // Create the tables if they do not exist
    r = sqlite3_exec(db, SQL_MA_CREATE_TABLES, NULL, NULL, NULL);
    if (r != SQLITE_OK)
    {
        fatal("sqlite3 create table failed: %s\n", sqlite3_errmsg(db));
    }
}


//
// Open the ma database
//
sqlite3 * db_ma_open(
    db_write_mode               write)
{
    sqlite3 *                   db;

    // Open the database
    db = db_open(MA_DB_NAME, write);
    if (write == DB_READ_WRITE)
    {
        // Create the tables if they do not exist
        db_ma_create_tables(db);
    }

    return db;
}



//
// Attach the ma database
//
void db_ma_attach(
    sqlite3 *                   db)
{
    char                        sql[ANDWATCH_SQL_BUFFER + ANDWATCH_PATH_BUFFER];
    int                         r;

    // SQL to attach the ma database
    //
    // Paramaters:
    //      lib_dir             library directory (string)
    //
    #define SQL_MA_ATTACH \
    "ATTACH DATABASE 'file:%s/" MA_DB_NAME DB_SUFFIX "?mode=ro' AS " MA_DB_NAME

    // Safety check: ensure sql buffer is large enough
    _Static_assert ((sizeof(SQL_MA_ATTACH) + ANDWATCH_PATH_BUFFER < sizeof(sql)),
        "SQL_MA_ATTACH exceeds sql buffer size");

    #define SQL_MA_CONFIRM_INITIALIZED \
        "SELECT EXISTS(SELECT 1 FROM " TBL_MA_U ")"

    // Safety check: ensure sql buffer is large enough
    _Static_assert ((sizeof(SQL_MA_CONFIRM_INITIALIZED)  < sizeof(sql)),
        "SQL_MA_CONFIRM_INITIALIZED exceeds sql buffer size");

    // Construct the sql
    snprintf(sql, sizeof(sql), SQL_MA_ATTACH, lib_dir);

    // Execute
    r = sqlite3_exec(db, sql, NULL, NULL, NULL);
    if (r == SQLITE_OK)
    {
        // Confirm that the ma database has been initialized
        r = sqlite3_exec(db, SQL_MA_CONFIRM_INITIALIZED, NULL, NULL, NULL);
    }

    if (r != SQLITE_OK)
    {
        fatal("the ma database (%s/%s%s) has not been initialized: run andwatch-update-ma\n", lib_dir, MA_DB_NAME, DB_SUFFIX);
    }
}


//
// Drop and re-create the tables in the ma database
//
void db_ma_recreate_tables(
    sqlite3 *                   db)
{
    int                         r;

    // SQL to drop the existing ma tables
    //
    #define SQL_MA_DROP_TABLES \
        "DROP TABLE IF EXISTS " TBL_MA_L ";\n" \
        "DROP TABLE IF EXISTS " TBL_MA_M ";\n" \
        "DROP TABLE IF EXISTS " TBL_MA_S ";\n" \
        "DROP TABLE IF EXISTS " TBL_MA_U ";"

    // Drop the existing tables
    r = sqlite3_exec(db, SQL_MA_CREATE_TABLES, NULL, NULL, NULL);
    if (r != SQLITE_OK)
    {
        fatal("sqlite3 create table failed: %s\n", sqlite3_errmsg(db));
    }

    // Create the new tables
    db_ma_create_tables(db);
}


//
// Perform maintenance on the database
//
void db_maintenance(
    sqlite3 *                   db)
{
    int                         r;

    // SQL to optimize the database
    //
    #define SQL_OPTIMIZE \
        "PRAGMA optimize;"

    // Execute
    r = sqlite3_exec(db, SQL_OPTIMIZE, NULL, NULL, NULL);
    if (r != SQLITE_OK)
    {
        logger("database optimize failed: %s\n", sqlite3_errmsg(db));
    }

    // SQL to vacuum the database
    //
    #define SQL_VACUUM \
        "VACUUM;"

    // Execute
    r = sqlite3_exec(db, SQL_VACUUM, NULL, NULL, NULL);
    if (r != SQLITE_OK)
    {
        logger("database vacuum failed: %s\n", sqlite3_errmsg(db));
    }
}


//
// Close a database
//
void db_close(
    sqlite3 *                   db)
{
    (void) sqlite3_close(db);
}


//
// Begin a transaction
//
void db_begin_transaction(
    sqlite3 *                   db)
{
    int                         r;

    r =sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, NULL);
    if (r != SQLITE_OK)
    {
        fatal("begin transaction failed: %s\n", sqlite3_errmsg(db));
    }
}


//
// End a transaction
//
void db_end_transaction(
    sqlite3 *                   db)
{
    int                         r;

    r =sqlite3_exec(db, "END TRANSACTION", NULL, NULL, NULL);
    if (r != SQLITE_OK)
    {
        fatal("begin transaction failed: %s\n", sqlite3_errmsg(db));
    }
}


//
// Insert an entry into the ma database
//
void db_ma_insert(
    sqlite3 *                   db,
    const char *                table,
    const char *                prefix,
    const char *                org)
{
    char                        sql[ANDWATCH_SQL_BUFFER];
    int                         r;

    // SQL to insert an entry into an ma table
    //
    // Paramaters:
    //      table               ma table name (string)
    //      prefix              hw address prefix (string)
    //      org                 organization name (string)
    //
    #define SQL_MA_INSERT_ENTRY \
        "INSERT INTO %s VALUES ('%s', '%s')"

    // Safety check: ensure sql buffer is large enough
    _Static_assert ((sizeof(SQL_MA_INSERT_ENTRY) + sizeof(MA_L_NAME) + ETH_ADDRSTRLEN + MA_ORG_NAME_LIMIT < sizeof(sql)),
        "SQL_MA_INSERT_ENTRY exceeds sql buffer size");

    // Construct the sql
    snprintf(sql, sizeof(sql), SQL_MA_INSERT_ENTRY, table, prefix, org);

    // Execute
    r = sqlite3_exec(db, sql, NULL, NULL, NULL);
    if (r != SQLITE_OK)
    {
        logger("ma insert entry failed: %s\n", sqlite3_errmsg(db));
    }
}


//
// Insert an entry into an ipmap database
//
void db_ipmap_insert(
    sqlite3 *                   db,
    db_iptype                   iptype,
    const char *                ipaddr,
    const char *                hwaddr,
    const struct timeval *      timeval)
{
    char                        sql[ANDWATCH_SQL_BUFFER];
    int                         r;

    // SQL to insert an entry into the ipmap table
    //
    // Paramaters:
    //      iptype              DB_IPTYPE_4 or DB_IPTYPE_6 (integer)
    //      ipaddr              ip address (string)
    //      hwaddr              hardware address (string)
    //      seconds             seconds (long integer)
    //      useconds            microseconds (long integer)
    //      update              last update epoch timestamp (long integer)
    //
    #define SQL_IPMAP_INSERT \
        "INSERT INTO " TBL_IPMAP " VALUES (%d, '%s', '%s', %ld, %ld, %ld)"

    // Safety check: ensure sql buffer is large enough
    _Static_assert ((sizeof(SQL_IPMAP_INSERT) + 1 + INET6_ADDRSTRLEN + ETH_ADDRSTRLEN + 10 + 10 < sizeof(sql)),
        "SQL_IPMAP_INSERT exceeds sql buffer size");

    // Construct the sql
    snprintf(sql, sizeof(sql), SQL_IPMAP_INSERT, iptype, ipaddr, hwaddr, timeval->tv_sec, (long) timeval->tv_usec, timeval->tv_sec);

    // Execute
    r = sqlite3_exec(db, sql, NULL, NULL, NULL);
    if (r != SQLITE_OK)
    {
        logger("ipmap insert entry failed: %s\n", sqlite3_errmsg(db));
    }
}


//
// Set the update time for a row
//
void db_ipmap_set_utime(
    sqlite3 *                   db,
    long                        rowid,
    time_t                      time)
{
    char                        sql[ANDWATCH_SQL_BUFFER];
    int                         r;

    // SQL to set the update time for a row
    //
    // Paramaters:
    //      time                epoch time (long integer)
    //      rowid               rowid (long integer)
    //
    #define SQL_IPMAP_SET_UPTIME \
        "UPDATE " TBL_IPMAP " SET " COL_UTIME " = %ld WHERE " COL_ROWID " = %ld"

    // Safety check: ensure sql buffer is large enough
    _Static_assert ((sizeof(SQL_IPMAP_SET_UPTIME) + 10 + 10 < sizeof(sql)),
        "SQL_IPMAP_SET_UPTIME exceeds sql buffer size");

    // Construct the sql
    snprintf(sql, sizeof(sql), SQL_IPMAP_SET_UPTIME, time, rowid);

    // Execute
    r = sqlite3_exec(db, sql, NULL, NULL, NULL);
    if (r != SQLITE_OK)
    {
        logger("ipmap update failed: %s\n", sqlite3_errmsg(db));
    }
}


//
// Delete entries older than a given time
//
void db_ipmap_delete_old(
    sqlite3 *                   db,
    time_t                      time)
{
    char                        sql[ANDWATCH_SQL_BUFFER];
    int                         r;

    // SQL to delete entries older than a given time
    //
    // Paramaters:
    //      time                epoch time (long integer)
    //
    #define SQL_IPMAP_DELETE_OLD \
        "DELETE FROM " TBL_IPMAP " WHERE " COL_UTIME " <= %ld"

    // Safety check: ensure sql buffer is large enough
    _Static_assert ((sizeof(SQL_IPMAP_DELETE_OLD) + 10 < sizeof(sql)),
        "SQL_IPMAP_DELETE_OLD exceeds sql buffer size");

    // Construct the sql
    snprintf(sql, sizeof(sql), SQL_IPMAP_DELETE_OLD, time);

    // Execute
    r = sqlite3_exec(db, sql, NULL, NULL, NULL);
    if (r != SQLITE_OK)
    {
        logger("ipmap delete old records failed: %s\n", sqlite3_errmsg(db));
    }
}


//
// Callback for getting the current (last) values for an ip address
//
static int db_ipmap_get_current_callback(
    void *                      closure,
    int                         count,
    char **                     columns,
    __attribute__ ((unused))
    char **                     names)
{
    ipmap_current_t *           current = (ipmap_current_t *) closure;

    // Expected columns:
    //      rowid
    //      age
    //      hwaddr

    // Safety check
    if (count < 3)
    {
        logger("insufficient columns in ipmap current callback: %d\n", count);
        return 1;
    }

    // Save the information
    current->rowid = strtol(columns[0], NULL, 10);
    current->age = strtol(columns[1], NULL, 10);
    safe_strncpy(current->hwaddr_str, columns[2], sizeof(current->hwaddr_str));

    // Mark the current data as valid
    current->valid = 1;

    return 0;
}


//
// Get the current (last) values for an ip address
//
void db_ipmap_get_current(
    sqlite3 *                   db,
    db_iptype                   iptype,
    const char *                ipaddr,
    ipmap_current_t *           current)
{
    char                        sql[ANDWATCH_SQL_BUFFER];
    int                         r;

    // Mark the current data as invalid
    current->valid = 0;

    // SQL to get the current information an ip address
    //
    // Paramaters:
    //      iptype              DB_IPTYPE_4 or DB_IPTYPE_6 (integer)
    //      ipaddr              ip address (string)
    //
    #define SQL_IPMAP_GET_CURRENT \
        "SELECT " COL_ROWID ",(unixepoch() - " COL_UTIME ") / 60," COL_HWADDR " FROM " TBL_IPMAP "\n" \
        "WHERE rowid = (\n" \
            "SELECT rowid\n" \
            "FROM " TBL_IPMAP "\n" \
            "WHERE " COL_IPTYPE " == %d AND " COL_IPADDR " == '%s'\n" \
            "ORDER BY " COL_SEC " DESC," COL_USEC " DESC\n" \
            "LIMIT 1" \
        ")"

    // Safety check: ensure sql buffer is large enough
    _Static_assert ((sizeof(SQL_IPMAP_GET_CURRENT) + 1 + INET6_ADDRSTRLEN < sizeof(sql)),
        "SQL_IPMAP_GET_CURRENT exceeds sql buffer size");

    // Construct the sql
    snprintf(sql, sizeof(sql), SQL_IPMAP_GET_CURRENT, iptype, ipaddr);

    // Execute
    r = sqlite3_exec(db, sql, db_ipmap_get_current_callback, current, NULL);
    if (r != SQLITE_OK)
    {
        logger("get ipmap get current failed: %s\n", sqlite3_errmsg(db));
    }
}


//
// Callback for organization lookup
//
static int db_query_ma_callback(
    __attribute__ ((unused))
    void *                      closure,
    int                         count,
    char **                     columns,
    __attribute__ ((unused))
    char **                     names)
{
    char *                      org = (char *) closure;

    // Expected columns:
    //      org

    // Safety check
    if (count < 1)
    {
        logger("insufficient columns in ma lookup org callback: %d\n", count);
        return 1;
    }

    // Save the information
    safe_strncpy(org, columns[0], MA_ORG_NAME_LIMIT);

    return 0;
}


//
// Lookup the organization name for a mac address
//
// NB: Parameter org must be at least MA_ORG_NAME_LIMIT characters
//
void db_query_ma(
    sqlite3 *                   db,
    const char *                hwaddr,
    char *                      org)
{
    char                        sql[ANDWATCH_SQL_BUFFER];
    int                         r;

    // SQL to lookup the organization name for a mac address
    //
    // Paramaters:
    //      hwaddr              mac address (string)
    //
    #define SQL_MA_LOOKUP_ORG \
        "SELECT coalesce(" \
            "(SELECT " COL_ORG " FROM " TBL_MA_S " WHERE prefix = substr('%s',1,13)),\n" \
            "(SELECT " COL_ORG " FROM " TBL_MA_M " WHERE prefix = substr('%s',1,10)),\n" \
            "(SELECT " COL_ORG " FROM " TBL_MA_L " WHERE prefix = substr('%s',1,8)),\n" \
            "(SELECT " COL_ORG " FROM " TBL_MA_U " WHERE prefix = substr('%s',2,1)),\n" \
            "'(unknown)'" \
        ")"

    // Safety check: ensure sql buffer is large enough
    _Static_assert ((sizeof(SQL_MA_LOOKUP_ORG) + ETH_ADDRSTRLEN * 4 < sizeof(sql)),
        "SQL_MA_LOOKUP_ORG exceeds sql buffer size");

    // Construct the sql
    snprintf(sql, sizeof(sql), SQL_MA_LOOKUP_ORG, hwaddr, hwaddr, hwaddr, hwaddr);

    // Execute
    r = sqlite3_exec(db, sql, db_query_ma_callback, org, NULL);
    if (r != SQLITE_OK)
    {
        logger("ma lookup org failed: %s\n", sqlite3_errmsg(db));
        safe_strncpy(org, "(failed)", MA_ORG_NAME_LIMIT);
    }
}


//
// Callback for printing ipmap entries
//
static int db_ipmap_query_callback(
    __attribute__ ((unused))
    void *                      closure,
    int                         count,
    char **                     columns,
    __attribute__ ((unused))
    char **                     names)
{
    // Expected columns:
    //      date_time
    //      age
    //      ipaddr
    //      hwaddr
    //      org

    // Safety check
    if (count < 5)
    {
        logger("insufficient columns in ipmap print callback: %d\n", count);
        return 1;
    }

    printf("%s %s %s %s %s\n", columns[0], columns[1], columns[2], columns[3], columns[4]);

    return 0;
}



//
// Query based on IP address
//
void db_ipmap_query(
    sqlite3 *                   db,
    const db_iptype             iptype,
    const unsigned int          all,
    const char *                addr)
{
    int                         addr_len = 0;
    char                        where[128] = "";
    char                        sql[ANDWATCH_SQL_BUFFER];
    int                         r;

    // SQL to select the columns used by query reports
    //
    #define SQL_QUERY_SELECT_COLUMNS \
        "SELECT datetime(" COL_SEC ",'unixepoch','localtime'),\n" \
                "(unixepoch() - " COL_UTIME ") / 60,\n" \
                COL_IPADDR "," COL_HWADDR ",\n" \
            "coalesce(\n" \
                "(SELECT " COL_ORG " FROM " TBL_MA_S " WHERE prefix = substr(hwaddr,1,13)),\n" \
                "(SELECT " COL_ORG " FROM " TBL_MA_M " WHERE prefix = substr(hwaddr,1,10)),\n" \
                "(SELECT " COL_ORG " FROM " TBL_MA_L " WHERE prefix = substr(hwaddr,1,8)),\n" \
                "(SELECT " COL_ORG " FROM " TBL_MA_U " WHERE prefix = substr(hwaddr,2,1)),\n" \
                "'(unknown)'\n" \
            ")\n"

    // SQL used to order the results used by query reports
    #define SQL_QUERY_ORDER_BY \
        "ORDER BY " COL_SEC "," COL_USEC

    //
    // SQL to query all rows
    //
    // Paramaters:
    //      where               where clause for query (string)
    //
    #define SQL_IPMAP_SELECT_ALL_ROWS \
        SQL_QUERY_SELECT_COLUMNS \
        "FROM " TBL_IPMAP " %s\n" \
        SQL_QUERY_ORDER_BY

    //
    // SQL to query current (last) rows
    //
    // Paramaters:
    //      where               where clause for query (string)
    //
    #define SQL_IPMAP_SELECT_CURRENT_ROWS \
        SQL_QUERY_SELECT_COLUMNS \
        "FROM (\n" \
            "SELECT " COL_SEC "," COL_USEC "," COL_UTIME "," COL_IPADDR "," COL_HWADDR ",row_number()\n" \
                "OVER (\n" \
                    "PARTITION BY " COL_IPADDR "\n" \
                    "ORDER BY " COL_SEC " DESC," COL_USEC " DESC\n" \
                ") AS number\n" \
            "FROM " TBL_IPMAP " %s\n"\
        ")\n" \
        "WHERE number = 1\n" \
        SQL_QUERY_ORDER_BY


    // Safety check: ensure where buffer is large enough
    _Static_assert ((sizeof("WHERE " COL_HWADDR " = ''") + ETH_ADDRSTRLEN + sizeof(" AND " COL_IPTYPE " = ") + 10 < sizeof(where)) &&
                    (sizeof("WHERE " COL_IPADDR " = ''") + INET6_ADDRSTRLEN < sizeof(where)),
        "where clause exceeds where buffer size");

    // Build the WHERE clause
    if (addr)
    {
        addr_len = strlen(addr);
        if (addr_len > INET6_ADDRSTRLEN)
        {
            fatal("invalid query address: \"%s\"\n", addr);
        }

        // Is it a hardware address?
        if (addr_len == sizeof("00:00:00:00:00:00") - 1 &&
            isxdigit(addr[0]) && isxdigit(addr[1]) &&
            addr[2] == ':' &&
            isxdigit(addr[3]) && isxdigit(addr[4]) &&
            addr[5] == ':' &&
            isxdigit(addr[6]) && isxdigit(addr[7]) &&
            addr[8] == ':' &&
            isxdigit(addr[9]) && isxdigit(addr[10]) &&
            addr[11] == ':' &&
            isxdigit(addr[12]) && isxdigit(addr[13]) &&
            addr[14] == ':' &&
            isxdigit(addr[15]) && isxdigit(addr[16]))
        {
            int offset = snprintf(where, sizeof(where), "WHERE " COL_HWADDR " = '%s'", addr);

            if (iptype)
            {
                snprintf(where + offset, sizeof(where), " AND " COL_IPTYPE " = %d\n", iptype);
            }
        }
        else
        {
            snprintf(where, sizeof(where), "WHERE " COL_IPADDR " = '%s'", addr);
        }
    }
    else
    {
        if (iptype)
        {
            snprintf(where, sizeof(where), "WHERE " COL_IPTYPE " = %d", iptype);
        }
    }


    // Construct the sql
    if (all)
    {
        snprintf(sql, sizeof(sql), SQL_IPMAP_SELECT_ALL_ROWS, where);
    }
    else
    {
        snprintf(sql, sizeof(sql), SQL_IPMAP_SELECT_CURRENT_ROWS, where);
    }

    // Execute
    r = sqlite3_exec(db, sql, db_ipmap_query_callback, NULL, NULL);
    if (r != SQLITE_OK)
    {
        fatal("query failed: %s\n", sqlite3_errmsg(db));
    }
}
