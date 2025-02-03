#!/bin/sh

# Change this to suit your needs
DOMAIN=`hostname -d`

FROM="andwatch@$DOMAIN"
TO="andwatch@$DOMAIN"

DIG=/usr/bin/dig
SENDMAIL=/usr/bin/sendmail


# Parameters:
timestamp=$1
ifname=$2
ipaddr=$3
old_hwaddr=$4
old_hwaddr_org=$5
new_hwaddr=$6
new_hwaddr_org=$7

hostname=`${DIG} +short -x ${ipaddr}`
if [ "${hostname}" = "" ]
then
    hostname="(none)"
fi

(
    printf "To: ${TO}\n"
    printf "From: ${FROM}\n"
    printf "Subject: ANDwatch notification\n\n"

    printf "%22s: %s\n" "timestamp" "${timestamp}"
    printf "%22s: %s\n" "interface" "${ifname}"
    printf "%22s: %s\n" "hostname" "${hostname}"
    printf "%22s: %s\n" "ip address" "${ipaddr}"
    printf "%22s: %s\n" "old ethernet address" "${old_hwaddr}  ${old_hwaddr_org}"
    printf "%22s: %s\n" "new ethernet address" "${new_hwaddr}  ${new_hwaddr_org}"
    printf "\n"
) | ${SENDMAIL} -f "${FROM}" "${TO}"
