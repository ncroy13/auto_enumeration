#!/bin/bash

# written by @ncroy13

RED="\033[01;31m"
GREEN="\033[01;32m"
YELLOW="\033[01;33m"
BLUE="\033[01;34m"
BOLD="\033[01;01m"
RESET="\033[00m"

#-- produce a summary of findings
summary(){
    for ip in $(cat ./alive.ip); do
	echo -e $ip > ./open-ports/$ip.txt
	awk \/$ip\/ masscan/scans/portscanAll.gnmap | egrep -o '*[0-9]*/open/*[tcp/udp]*/' | sort | uniq | awk -F '/' '{print $1"/"$3}' >> ./open-ports/$ip.txt
	awk \/$ip\/ nmap/scans/portscan.gnmap | egrep -o '*[0-9]*/open/*[tcp/udp]*/' | sort | uniq | awk -F '/' '{print $1"/"$3}' >> ./open-ports/$ip.txt
	cat ./open-ports/$ip.txt | sort -u > ./open-ports/$ip.txt
    done
    echo -e "\n[${GREEN}+${RESET}] there are $(cat ./alive.ip | wc -l ) ${YELLOW}alive hosts${RESET} and $(egrep -o '[0-9]*/open/' scans/*.gnmap | sort | uniq | wc -l) ${YELLOW}unique ports/services${RESET}"
}
