
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
#include <fcntl.h>

#include "andwatch.h"


// Command line variables/flags
const char *                    progname;
const char *                    hwaddr;



//
// Parse command line arguments
//
__attribute__ ((noreturn))
static void usage(void)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s [-h] [-L dir] hwaddr\n", progname);
    fprintf(stderr, "  options:\n");
    fprintf(stderr, "    -h display usage\n");
    fprintf(stderr, "    -L directory for library files (default: %s)\n", LIB_DIR);
    exit(1);
}

static void parse_args(
    int                         argc,
    char * const                argv[])
{
    int                         opt;

    progname = argv[0];

    while((opt = getopt(argc, argv, "hL:")) != -1)
    {
        switch (opt)
        {
        case 'L':
            lib_dir = optarg;
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

    hwaddr = argv[optind];

    // Safty check: Ensure the path names are not too long
    if (ANDWATCH_PATH_BUFFER <= strlen(lib_dir) + sizeof("/") + sizeof(MA_DB_NAME) + sizeof(DB_SUFFIX))
    {
        fatal("db_filename (%s/%s%s) exceeds maximum length of %d\n",
            lib_dir, MA_DB_NAME, DB_SUFFIX, ANDWATCH_PATH_BUFFER);
    }
}


//
// Main
//
int main(
    int                         argc,
    char * const                argv[])
{
    sqlite3 *                   db;
    char                        org[MA_ORG_NAME_LIMIT];

    // Handle command line args
    parse_args(argc, argv);

    // Open the malist database
    db = db_ma_open(DB_READ_ONLY);

    // Perform the query
    db_query_ma(db, hwaddr, org);
    printf("%s\n", org);

    // Close the database
    db_close(db);
    return 0;
}
