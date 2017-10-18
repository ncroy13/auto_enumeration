#!/bin/bash

RED="\033[01;31m"
GREEN="\033[01;32m"    
YELLOW="\033[01;33m"   
BLUE="\033[01;34m"     
BOLD="\033[01;01m"     
RESET="\033[00m" 

#-- check for root or exit
if [ $EUID != 0 ]
then
    echo -e "\n[${RED}!${RESET}] must be ${RED}root${RESET}"
    exit 1
fi

#-- check for nmap
if ! which nmap > /dev/null
then
    echo -e "\n[${RED}!${RESET}] nmap ${RED}not${RESET} found"
    exit 1
fi

#-- check for ike-scan
if ! which ike-scan > /dev/null
then
    echo -e "\n[${RED}!${RESET}] ike-scan ${RED}not${RESET} found"
    exit 1
fi

#-- check for curl
if ! which curl > /dev/null
then
    echo -e "\n[${RED}!${RESET}] curl ${RED}not${RESET} found"
    exit 1
fi

if [ ! -d ./open-ports ]
then
    mkdir -p ./open-ports
    touch ./open-ports/443.txt    
    touch ./open-ports/500.txt
fi

if [ ! -d ./nse_scans ]
then
    mkdir -p ./nse_scans
fi

MINHOST=$1
if  [[ -z "$MINHOST" ]]; then
    read -p "--min-hostgroup (256): " MINHOST
fi
if [[ -z "$MINHOST" ]];
then
    MINHOST=256
fi

MINRATE=$2
if  [[ -z "$MINRATE" ]]; then
    read -p "--min-rate (2000): " MINRATE
fi
if [[ -z "$MINRATE" ]];
then
    MINRATE=2000
fi

scan(){
    if [ $(cat open-ports/500.txt | wc -l) -eq '0' ];
    then
	echo -e "\n[${GREEN}+${RESET}] nothing in ${YELLOW}./open-ports/500.txt${RESET}"
    else
	nmap -sU -p 500 -iL open-ports/500.txt \
	     --script=ike-version -oN nse_scans/ike \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
	for ip in $(cat open-ports/500.txt)
	do	    
	    ike-scan -A -M $ip --id=GroupVPN >> nse_scans/IKE-$ip.txt
	done
    fi

    if [ $(cat open-ports/443.txt | wc -l) -eq '0' ];
    then
	echo -e "\n[${GREEN}+${RESET}] nothing in ${YELLOW}./open-ports/443.txt${RESET}"
    else
	for ip in $(cat open-ports/443.txt)
	do
	    curl -v https://$ip/ -H "Host: hostname" \
		 -H "Range: bytes=0-18446744073709551615" -k >> nse_scans/MS15034-$ip.txt
	done
    fi            
}

#-- call function
scan
