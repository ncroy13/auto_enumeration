#!/bin/bash

# written by @ncroy13

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

#-- check for nmap
if ! which nmap > /dev/null
then
    echo -e "\n[${RED}!${RESET}] nmap ${RED}not${RESET} found"
    exit 1
fi

#-- file/folder setup
# general
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
    touch ./open-ports/443.txt    
    touch ./open-ports/500.txt
fi

if [ ! -d ./nse_scans ]
then
    mkdir -p ./nse_scans
fi

#masscan
if [ ! -d ./masscan/scans ]
then
    mkdir -p ./masscan/scans/
fi

#nmap
if [ ! -d ./nmap/scans ]
then
    mkdir -p ./nmap/scans/
fi


#-- rate variables
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

MAXRATE=$1
if  [[ -z "$MAXRATE" ]]; then
    read -p "--max-rate (100000): " MAXRATE
fi
if [[ -z "$MAXRATE" ]];
then
    MAXRATE=100000
fi

#-- sources
source ./automasscan.sh
source ./autonmap.sh
source ./selectivescans.sh
source ./other_scans.sh
source ./parser.sh
source ./summary.sh

#-- call functions
# nmap
echo -e "\n[${GREEN}+${RESET}] running ${YELLOW}nmap${RESET} scans"
echo -e "\n[${GREEN}+${RESET}] running an ${YELLOW}nmap ping sweep${RESET} for all ip in targets.ip"
pingsweep
echo -e "\n[${GREEN}+${RESET}] running an ${YELLOW}nmap port scan${RESET} for all ip in nmap/alive.ip"
portscan

# masscan
echo -e "\n[${GREEN}+${RESET}] running ${YELLOW}masscan${RESET} scans"
echo -e "\n[${GREEN}+${RESET}] resolving all ${YELLOW}hostnames${RESET} in targets.ip"
masscanResolver
echo -e "\n[${GREEN}+${RESET}] running a ${YELLOW}port scan${RESET} for all ip in masscan/alive.ip"
portscanallports

# concatinate nmap and masscan
echo -e "\n[${GREEN}+${RESET}] combining ${YELLOW}nmap${RESET} and ${YELLOW}masscan${RESET} scans"
combiner

# parsing for nse scans
echo -e "\n[${GREEN}+${RESET}] running ${YELLOW}parser${RESET} for ${YELLOW}nse${RESET} scans"
parser

# nse
echo -e "\n[${GREEN}+${RESET}] running ${YELLOW}nse${RESET} scans"
nse

# other scans
echo -e "\n[${GREEN}+${RESET}] running ${YELLOW}other${RESET} scans"
scan

# produce a summary of findings
echo -e "\n[${GREEN}+${RESET}] generating a summary of the scans..."
summary
