
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
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <curl/curl.h>

#include "andwatch.h"



//
// IEEE MAC Assignment information from:
// https://standards.ieee.org/products-services/regauth/
// https://standards.ieee.org/products-programs/regauth/mac/
// https://regauth.standards.ieee.org/standards-ra-web/pub/view.html
//
//    MA Name,      Source URL
static const char *             ma_files[][2] = {
    { MA_L_NAME,    "https://standards-oui.ieee.org/oui/oui.csv" },
    { MA_M_NAME,    "https://standards-oui.ieee.org/oui28/mam.csv" },
    { MA_S_NAME,    "https://standards-oui.ieee.org/oui36/oui36.csv" }
};

// Command line variables/flags
static const char *             progname;
static const char *             user_agent = "ANDwatch/" VERSION;
static unsigned int             flag_download = 1;

// Buffer for curl error messages
char                            curl_errorbuffer[CURLOPT_ERRORBUFFER];



//
// Progress callback for curl download
//
static int download_progress_callback(
    __attribute__ ((unused))
    void *                      clientp,
    curl_off_t                  dltotal,
    curl_off_t                  dlnow,
    __attribute__ ((unused))
    curl_off_t                  ultotal,
    __attribute__ ((unused))
    curl_off_t                  ulnow)
{
    printf("\r%ldK of %ldK bytes", dlnow / 1024, dltotal / 1024);
    fflush(stdout);
    return 0;
}


//
// Open the curl handle
//
static CURL * curl_open(void)
{
    CURL *                      curl;
    CURLcode                    curlcode;

    // Initialize the curl library
    curl = curl_easy_init();
    if (curl == NULL)
    {
        fatal("curl initialization failed\n");
    }

    // Set the error buffer
    curlcode = curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_errorbuffer);
    if (curlcode != CURLE_OK)
    {
        fatal("setopt for CURLOPT_ERRORBUFFER failed: %s\n", curl_easy_strerror(curlcode));
    }

    // Set the user agent
    curlcode = curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agent);
    if (curlcode != CURLE_OK)
    {
        fatal("setopt for CURLOPT_USERAGENT failed: %s\n", curl_errorbuffer);
    }

    // Enable following redirects
    curlcode = curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    if (curlcode != CURLE_OK)
    {
        fatal("setopt for CURLOPT_URL failed: %s\n", curl_errorbuffer);
    }

    // Fail on errors
    curlcode = curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
    if (curlcode != CURLE_OK)
    {
        fatal("setopt for CURLOPT_FAILONERROR failed: %s\n", curl_errorbuffer);
    }

    // Enable the progress callback
    curlcode = curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, download_progress_callback);
    if (curlcode != CURLE_OK)
    {
        fatal("setopt for CURLOPT_XFERINFOFUNCTION failed: %s\n", curl_errorbuffer);
    }
    curlcode = curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0);
    if (curlcode != CURLE_OK)
    {
        fatal("setopt for CURLOPT_NOPROGRESS failed: %s\n", curl_errorbuffer);
    }

    return curl;
}


//
// Close the curl handle
//
static void curl_close(
    CURL *                      curl)
{
    curl_easy_cleanup(curl);
}


//
// Download a file via curl
//
static void curl_download(
    CURL *                      curl,
    const char *                name,
    const char *                url)
{
    FILE *                      tmp_file;
    char                        filename_tmp[ANDWATCH_PATH_BUFFER];
    char                        filename_csv[ANDWATCH_PATH_BUFFER];
    CURLcode                    curlcode;
    int                         r;

    // Construct the file names
    snprintf(filename_tmp, sizeof(filename_tmp), "%s/%s%s", lib_dir, name, TMP_SUFFIX);
    snprintf(filename_csv, sizeof(filename_csv), "%s/%s%s", lib_dir, name, CSV_SUFFIX);

    // Open the tmp file
    tmp_file = fopen(filename_tmp, "w");
    if (tmp_file == NULL)
    {
        fatal("failed to open %s: %s\n", filename_tmp, strerror(errno));
    }

    // Set the write file handle
    curlcode = curl_easy_setopt(curl, CURLOPT_WRITEDATA, tmp_file);
    if (curlcode != CURLE_OK)
    {
        fatal("setopt for CURLOPT_WRITEDATA failed: %s\n", curl_errorbuffer);
    }

    // Set the URL
    curlcode = curl_easy_setopt(curl, CURLOPT_URL, url);
    if (curlcode != CURLE_OK)
    {
        fatal("setopt for CURLOPT_URL failed: %s\n", curl_errorbuffer);
    }

    // Perform the download
    printf("Downloading %s to %s\n", url, filename_csv);
    curlcode = curl_easy_perform(curl);
    printf("\ncomplete\n");
    fflush(stdout);
    if (curlcode != CURLE_OK)
    {
        fatal("download failed: %s\n", curl_errorbuffer);
    }

    // Close the tmp file
    r = fclose(tmp_file);
    if (r != 0)
    {
        fatal("failed to close %s: %s\n", filename_tmp, strerror(errno));
    }

    // Rename the tmp file to the final name
    r = rename(filename_tmp, filename_csv);
    if (r != 0)
    {
        fatal("failed to rename %s to %s: %s\n", filename_tmp, filename_csv, strerror(errno));
    }
}


//
// Update the malist database based on the csv file
//
void load_malist(
    sqlite3 *                   db,
    const char *                name)
{
    FILE *                      csv_file;
    char *                      registry;
    char *                      assignment;
    char *                      organization;
    char                        mac_prefix[18] = "XX:XX:XX:XX:XX:XX";
    char                        malist_csv_filename[ANDWATCH_PATH_BUFFER];
    char                        buffer[1024];
    char *                      p;

     // Construct the csv file name
    snprintf(malist_csv_filename, sizeof(malist_csv_filename), "%s/%s%s", lib_dir, name, CSV_SUFFIX);

    // Open the csv file
    csv_file = fopen(malist_csv_filename, "r");
    if (csv_file == NULL)
    {
        fatal("failed to open %s: %s\n", malist_csv_filename, strerror(errno));
    }

    // Read the csv file and insert the records into the database
    printf("Updating %s database\n", name);
    while (fgets(buffer, sizeof(buffer), csv_file) != NULL)
    {
        // Format of the csv file is:
        //
        // Registry,Assignment,Organization Name,Organization Address
        //
        // Values of Organization Name and Organization Address that contain commas are enclosed in double quotes.
        //
        // Examples:
        //
        // MA-L,000000,XEROX CORPORATION,M/S 105-50C WEBSTER NY US 14580
        // MA-L,00000C,"Cisco Systems, Inc",170 WEST TASMAN DRIVE SAN JOSE CA US 95134-1706
        // MA-L,00000E,FUJITSU LIMITED,"403, Kosugi-cho 1-chome, Nakahara-ku Kawasaki Kanagawa JP 211-0063 "
        //
        // MA-L,0055DA,IEEE Registration Authority,445 Hoes Lane Piscataway NJ US 08554
        // MA-M,0055DA5,Nanoleaf,"100 Front Street East, 4th Floor Toronto Ontario CA M5A 1E1 "
        //
        // MA-L,70B3D5,IEEE Registration Authority,445 Hoes Lane Piscataway NJ US 08554
        // MA-S,70B3D5E3D,Leo Bodnar Electronics Ltd,Unit 8 New Rookery Farm Silverstone  GB NN12 8UP
        //
        // For purpses of creating the malist database, we are only interested in the first three fields.
        //

        // Get the registry
        registry = buffer;
        p = strchr(registry, ',');
        *p = '\0';

        // If the registry is not MA-[LMS], skip the line
        if (registry[0] != 'M' || registry[1] != 'A' || registry[2] != '-' ||
            (registry[3] != 'L' && registry[3] != 'M' && registry[3] != 'S'))
        {
            continue;
        }

        // Get the assignment
        assignment = p + 1;
        p = strchr(assignment, ',');
        *p = '\0';

        // Get the organization name
        organization = p + 1;
        if (organization[0] == '"')
        {
            organization++;
            p = strchr(organization, '"');
        }
        else
        {
            p = strchr(organization, ',');
        }
        *p = '\0';

        // Check organization name length
        if (strlen(organization) > MA_ORG_NAME_LIMIT)
        {
            organization[MA_ORG_NAME_LIMIT] = '\0';
        }

        // Ensure the organization name does not have single quotes
        p = organization;
        while ((p = strchr(p, '\'')) != NULL)
        {
            *p = '`';
            p++;
        }

        // Prepare a mac prefix value for the database
        switch(strlen(assignment))
        {
        case 6:
            // MA-L
            mac_prefix[0] = tolower(assignment[0]);
            mac_prefix[1] = tolower(assignment[1]);
            mac_prefix[2] = ':';
            mac_prefix[3] = tolower(assignment[2]);
            mac_prefix[4] = tolower(assignment[3]);
            mac_prefix[5] = ':';
            mac_prefix[6] = tolower(assignment[4]);
            mac_prefix[7] = tolower(assignment[5]);
            mac_prefix[8] = '\0';
            break;
        case 7:
            // MA-M
            mac_prefix[0] = tolower(assignment[0]);
            mac_prefix[1] = tolower(assignment[1]);
            mac_prefix[2] = ':';
            mac_prefix[3] = tolower(assignment[2]);
            mac_prefix[4] = tolower(assignment[3]);
            mac_prefix[5] = ':';
            mac_prefix[6] = tolower(assignment[4]);
            mac_prefix[7] = tolower(assignment[5]);
            mac_prefix[8] = ':';
            mac_prefix[9] = tolower(assignment[6]);
            mac_prefix[10] = '\0';
            break;
        case 9:
            // MA-S
            mac_prefix[0] = tolower(assignment[0]);
            mac_prefix[1] = tolower(assignment[1]);
            mac_prefix[2] = ':';
            mac_prefix[3] = tolower(assignment[2]);
            mac_prefix[4] = tolower(assignment[3]);
            mac_prefix[5] = ':';
            mac_prefix[6] = tolower(assignment[4]);
            mac_prefix[7] = tolower(assignment[5]);
            mac_prefix[8] = ':';
            mac_prefix[9] = tolower(assignment[6]);
            mac_prefix[10] = tolower(assignment[7]);
            mac_prefix[11] = ':';
            mac_prefix[12] = tolower(assignment[8]);
            mac_prefix[13] = '\0';
            break;
        default:
            fatal("unexpected assignment value: %s\n", assignment);
        }

        // Insert the record into the database
        db_ma_insert(db, name, mac_prefix, organization);

    }
    printf("\ncomplete\n");

    // Close the csv file
    fclose(csv_file);
}



//
// Parse command line arguments
//
__attribute__ ((noreturn))
static void usage(void)
{
    size_t                      i;

    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s [-h] [-D] [-L dir]\n", progname);
    fprintf(stderr, "  options:\n");
    fprintf(stderr, "    -h display usage\n");
    fprintf(stderr, "    -D skip download of the mac address csv files\n");
    fprintf(stderr, "    -L directory for library files (default: %s)\n", LIB_DIR);
    fprintf(stderr, "    -U user agent for http (default: %s)\n", user_agent);
    fprintf(stderr, "  \nNotes:\n");
    fprintf(stderr, "    This program automatically downloads the MAC address assignment files\n");
    fprintf(stderr, "    from IEEE using curl and saves them in the library directory. If you\n");
    fprintf(stderr, "    prefer to download the files manually, place the files in the library\n");
    fprintf(stderr, "    directory as shown below, then use the -D option to skip the download.\n\n");
    for (i = 0; i < sizeof(ma_files) / sizeof(ma_files[0]); i++)
    {
        fprintf(stderr, "    %-47s -> %s/%s%s\n", ma_files[i][1], lib_dir, ma_files[i][0], CSV_SUFFIX);
    }
    exit(1);
}

static void parse_args(
    int                         argc,
    char * const                argv[])
{
    int                         opt;

    progname = argv[0];

    while((opt = getopt(argc, argv, "hDL:")) != -1)
    {
        switch (opt)
        {
        case 'D':
            flag_download = 0;
            break;
        case 'L':
            lib_dir = optarg;
            break;
        case 'U':
            user_agent = optarg;
            break;
        default:
            usage();
        }
    }

    // Safty check: Ensure the path names are not too long
    if (ANDWATCH_PATH_BUFFER <= strlen(lib_dir) + sizeof("/") + sizeof(MA_DB_NAME) + sizeof(DB_SUFFIX))
    {
        fatal("db_filename (%s/%s%s) exceeds maximum length of %d\n",
            lib_dir, MA_DB_NAME, DB_SUFFIX, ANDWATCH_PATH_BUFFER);
    }
    if (ANDWATCH_PATH_BUFFER <= strlen(lib_dir) + sizeof("/") + sizeof(ma_files[0][0]) + sizeof(CSV_SUFFIX))
    {
        fatal("db_filename (%s/%s%s) exceeds maximum length of %d\n",
            lib_dir, ma_files[0][0], CSV_SUFFIX, ANDWATCH_PATH_BUFFER);
    }
}



//
// Main
//
int main(
    int                         argc,
    char * const                argv[])
{
    CURL *                      curl;
    sqlite3 *                   db;
    size_t                      i;

    // Handle command line args
    parse_args(argc, argv);

    // Download the ma files
    if (flag_download)
    {
        // Initialize the curl library
        curl = curl_open();

        // Download the csv files
        for (i = 0; i < sizeof(ma_files) / sizeof(ma_files[0]); i++)
        {
            curl_download(curl, ma_files[i][0], ma_files[i][1]);
        }

        // Cleanup curl
        curl_close(curl);
    }


    // Open the malist database
    db = db_ma_open(DB_READ_WRITE);
    if (db == NULL)
    {
        fatal("failed to open the malist database\n");
    }

    // Begin the transaction
    db_begin_transaction(db);

    // Recreate the tables
    db_ma_recreate_tables(db);

    // Load the ma tables
    for (i = 0; i < sizeof(ma_files) / sizeof(ma_files[0]); i++)
    {
        load_malist(db, ma_files[i][0]);
    }

    // Load the private table
    db_ma_insert(db, MA_U_NAME, "2", "(private)");
    db_ma_insert(db, MA_U_NAME, "6", "(private)");
    db_ma_insert(db, MA_U_NAME, "a", "(private)");
    db_ma_insert(db, MA_U_NAME, "e", "(private)");

    // End the transaction
    db_end_transaction(db);

    // Perform maintenance on the database
    db_maintenance(db);

    // Close the database
    db_close(db);

    return 0;
}
