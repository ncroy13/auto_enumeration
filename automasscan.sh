#!/bin/bash

# written by @jthorpe6

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

#-- check for masscan
if ! which masscan > /dev/null
then
    echo -e "\n[${RED}!${RESET}] masscan ${RED}not${RESET} found"
    exit 1
fi

#-- check for dig
if ! which dig > /dev/null
then
    echo -e "\n[${RED}!${RESET}] dig ${RED}not${RESET} found"
    exit 1
fi

#-- file/folder setup
if [ ! -f ./targets.ip ]
then
    touch ./targets.ip
    touch ./exclude.ip
    echo -e "\n[${GREEN}+${RESET}] populate the ${YELLOW}targets.ip${RESET} file"
    echo -e "\n[${GREEN}+${RESET}] populate the ${YELLOW}exclude.ip${RESET} file"
    exit 1
fi

if [ ! -d ./scans ]
then
    mkdir -p ./scans/
fi

if [ ! -d ./open-ports ]
then
    mkdir -p ./open-ports
fi

if [ ! -d ./nse_scans ]
then
    mkdir -p ./nse_scans
fi

MAXRATE=$1
if  [[ -z "$MAXRATE" ]]; then
    read -p "--max-rate (100000): " MAXRATE
fi
if [[ -z "$MAXRATE" ]];
then
    MAXRATE=100000
fi

masscanResolver(){
    for item in $(cat ./targets.ip);
    do
	if [ $(dig +short $item |wc -l) -eq '0' ];
	then
	    echo -e $item >> alive.ip
	else
	    echo -e "$(dig +short $item | sort -u| tr -s ' ' '\n')" >> alive.ip
	fi
    done
    
}

portscanallports(){
    masscan --open -iL alive.ip \
	 -oG scans/portscanAll.gnmap -v \
	 -p 0-65535 \
	 --max-rate=$MAXRATE
}

source ./selectivescans.sh
echo -e "\n[${GREEN}+${RESET}] resolving all ${YELLOW}hostnames${RESET} in targets.ip"
masscanResolver
echo -e "\n[${GREEN}+${RESET}] running a ${YELLOW}port scan${RESET} for all ip in alive.ip"
portscanallports
echo -e "\n[${GREEN}+${RESET}] running a ${YELLOW}parser${RESET} for the nse scanning"
parser
echo -e "\n[${GREEN}+${RESET}] running all then ${YELLOW}nse${RESET} scans "
nse
