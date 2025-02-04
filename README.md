# ANDwatch - Arp and Neighbor Discovery Watch daemon

ANDwatch monitors Arp (IPv4) and Neighbor Discovery (IPv6) packets,
maintains a database of IP address to hardware address (Ethernet) 
mappings, and issues notifications when the hardware address of an
IP address changes.

ANDwatch is intended as a modern replacement for arpwatch. When contrasted with arpwatch, ANDwatch offers the following enhancements:
- Support for IPv6 addresses.
- Support for all IEEE MAC Address Blocks:
  - 24 bit Large MAC Address Block MA-L.
  - 28 bit Medium MAC Address Block MA-M (*new*).
  - 36 bit Small MAC Address Block MA-S (*new*).
- Identification of private (locally administered) hardware addresses.
- Allows queries for both current and historical ip / hardware address information.
- Does not use a hardcoded notification mechanism (sendmail).

## Important notes

By default, ANDwatch creates its data files in /var/lib/andwatch. This can be overridden by using the -L option with any of the ANDwatch executables.

**Before using ANDwatch, you must create the MAC Address database in the library directory**. See *ANDwatch update MAC Addresses* below for details.

---

## ANDwatch daemon (andwatchd)

The ANDwatch daemon monitors an interface, maintains the IP address / hardware address map, and provides notifications when the map changes.

The usage of andwatchd is:

	andwatchd [-h] [-f] [-s] [-n cmd] [-p file] [-L dir] [-M minutes] [-O days] [-P] [-S len] ifname

| Option | Description                                                       |
|:-------|:------------------------------------------------------------------|
| -h | Display help.
| -f | Run in foreground. By default, andwatchd runs in the background.
| -s | Log notifications via syslog rather than stdout.
| -n | Command to send external notifications.
| -p | Process id file name.
| -L | Directory for database files (default: /var/lib/andwatch).
| -M | Number of minutes between current record updates (default: 10).
| -O | Number of days before deleting old records (default: 30).
| -P | Don’t enable promiscuous mode.
| -S | Snapshot length for pcap (default/minimum: 86).

**ifname** is the name of the interface to monitor.

If an external notification command is specified, it will be invoked as:

	command date_time ifname ipaddr old_hwaddr old_hwaddr_org new_hwaddr new_hwaddr_org

---

## ANDwatch Query (andwatch-query)

ANDwatch Query provides queries of the live ANDwatch database.

The usage of andwatch-query is:

	andwatch-query [-h] [-a] [-4 | -6] [-L dir] ifname [ipaddr | hwaddr]

| Option | Description                                                       |
|:-------|:------------------------------------------------------------------|
| -h | Display help.
| -a | Select all records rather than just current records.
| -4 | Limit results to IPv4 only.
| -6 | Limit results to IPv6 only.
| -L | directory for library files (default: /var/lib/andwatch).

**ifname** is the name of the interface to query.

**ipaddr** or **hwaddr** is the IP or hardware (Ethernet) address to query. If neither an IP or hardware address is given, andwatch-query will select all records.

The output of andwatch-query contains the following fields:

| field  | description |
|:-------|:-----------|
| date time | Timestamp when the record was created. |
| age | When the record was last updated in minutes. |
| IPaddr | The IP address of the record. |
| HWaddr | The hardware (Ethernet) address of the record. |
| MA org | Organization name of the MAC Address assignment. |

---

## ANDwatch Update MAC Address database (andwatch-update-ma)

The andwatch-update-ma utility downloads the MAC address assignment files
from IEEE, saves them in the library directory, and then creates or updates the
ANDwatch MAC Address database in the library directory (/var/lib/andwatch/ma_db.c).

The usage of andwatch-update-ma is:

	andwatch-update-ma [-h] [-D] [-L dir]

| Option | Description                                                       |
|:-------|:------------------------------------------------------------------|
| -h | Display help.
| -D | Skip downloading of the MAC Address csv files from IEEE.
| -L | Directory for library files (default: /var/lib/andwatch).
| -U | User agent for http (default: ANDwatch/1.0.0).

If you prefer to download the csv files manually, place the files in the
library directory as shown below, then use the -D option to skip the download.

    https://standards-oui.ieee.org/oui/oui.csv      -> /var/lib/andwatch/ma_l.csv
    https://standards-oui.ieee.org/oui28/mam.csv    -> /var/lib/andwatch/ma_m.csv
    https://standards-oui.ieee.org/oui36/oui36.csv  -> /var/lib/andwatch/ma_s.csv

Notes:
* **You must create the MAC Address database before you can use any of the
other ANDwatch commands**.
* The MAC Address database should be updated periodically via cron or other mechanism. Once per month is likely sufficient. 
* There is no need to stop the ANDwatch daemon to update the MAC Address database.

---

## ANDwatch Query MAC Address (andwatch-query-ma)

Query MAC Address database

The usage of andwatch-query-ma is:

    andwatch-query-ma [-h] [-L dir] hwaddr

| Option | Description                                                       |
|:-------|:------------------------------------------------------------------|
| -h | Display help.
| -L | directory for library files (default: /var/lib/andwatch).

**hwaddr** is the hardware address you want to query.

---

### Dependency information
ANDwatch relies on the following external packages:
* sqlite3 3.25 (September 2018) or above
* libpcap 1.9.0 (June 2018) or above
* curl 7.32.0 (August 2013) or above
