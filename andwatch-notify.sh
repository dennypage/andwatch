#!/bin/sh

# Change this to suit your needs
DOMAIN=`hostname -d`

FROM="andwatch@$DOMAIN"
TO="andwatch@$DOMAIN"

SENDMAIL=/usr/bin/sendmail


# Parameters:
timestamp=$1
ifname=$2
hostname=$3
ipaddr=$4
new_hwaddr=$5
new_hwaddr_org=$6
old_hwaddr=$7
old_hwaddr_org=$8

(
    printf "To: ${TO}\n"
    printf "From: ${FROM}\n"
    printf "Subject: ANDwatch notification\n\n"

    printf "%22s: %s\n" "timestamp" "${timestamp}"
    printf "%22s: %s\n" "interface" "${ifname}"
    printf "%22s: %s\n" "hostname" "${hostname}"
    printf "%22s: %s\n" "ip address" "${ipaddr}"
    printf "%22s: %s\n" "new ethernet address" "${new_hwaddr}"
    printf "%22s: %s\n" "new ethernet org" "${new_hwaddr_org}"
    printf "%22s: %s\n" "old ethernet address" "${old_hwaddr}"
    printf "%22s: %s\n" "old ethernet org" "${old_hwaddr_org}"
    printf "\n"
) | ${SENDMAIL} -f "${FROM}" "${TO}"
