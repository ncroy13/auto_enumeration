#!/bin/bash

# written by @ncroy13 in collaboration with @jthorpe6

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

#-- functions go here
pingsweep(){
    nmap --open -sn -PE -iL targets.ip \	 -PS3,7,9,13,17,19,21-23,25-26,37,53,79-82,88,100,106,110-111,113,119,135,139,143-144,179,199,254-255,280,311,389,427,443-445,464-465,497,513-515,543-544,548,554,587,593,625,631,636,646,787,808,873,902,990,993,995,1000,1022,1024-1033,1035-1041,1044,1048-1050,1053-1054,1056,1058-1059,1064-1066,1069,1071,1074,1080,1110,1234,1433,1494,1521,1720,1723,1755,1761,1801,1900,1935,1998,2000-2003,2005,2049,2103,2105,2107,2121,2161,2301,2383,2401,2601,2717,2869,2967,3000-3001,3128,3268,3306,3389,3689-3690,3703,3986,4000-4001,4045,4899,5000-5001,5003,5009,5050-5051,5060,5101,5120,5190,5357,5432,5555,5631,5666,5800,5900-5901,6000-6002,6004,6112,6646,6666,7000,7070,7937-7938,8000,8002,8008-8010,8031,8080-8081,8443,8888,9000-9001,9090,9100,9102,9999-10001,10010,32768,32771,49152-49157 -PU53,67-69,111,123,135,137-139,161-162,445,500,514,520,631,996-999,1434,1701,1900,3283,4500,5353,49152-49154 \
	 -oA scans/PingSweep --excludefile exclude.ip --min-hostgroup $MINHOST --min-rate=$MINRATE
    grep "Up" scans/PingSweep.gnmap | cut -d " " -f2 |sort -u > alive.ip
}

portscan(){
    nmap --open -iL alive.ip \
	 -sTU -T4 -A -Pn -n -oA scans/portscan -v \
	 -p T:3,7,9,13,17,19,21-23,25-26,37,53,79-82,88,100,106,110-111,113,119,135,139,143-144,179,199,254-255,280,311,389,427,443-445,464-465,497,513-515,543-544,548,554,587,593,625,631,636,646,787,808,873,902,990,993,995,1000,1022,1024-1033,1035-1041,1044,1048-1050,1053-1054,1056,1058-1059,1064-1066,1069,1071,1074,1080,1110,1234,1433,1494,1521,1720,1723,1755,1761,1801,1900,1935,1998,2000-2003,2005,2049,2103,2105,2107,2121,2161,2301,2383,2401,2601,2717,2869,2967,3000-3001,3128,3268,3306,3389,3689-3690,3703,3986,4000-4001,4045,4899,5000,5003,5009,5050-5051,5060,5101,5120,5190,5357,5432,5555,5631,5666,5800,5900-5901,6000-6002,6004,6112,6646,6666,7000,7070,7937-7938,8000,8002,8008-8010,8031,8080-8081,8443,8888,9000-9001,9090,9100,9102,9999-10001,10010,32768,32771,49152-49157,U:53,69,123,161,500,1434 \
	 --min-hostgroup $MINHOST --min-rate=$MINRATE
}

portscanallports(){
    nmap --open -iL alive.ip \
	 -sTU -T4 -A -Pn -n -oA scans/portscanAll -v \
	 -p T:0-65535,U:0-65535 \
	 --min-hostgroup $MINHOST --min-rate=$MINRATE
}

portscanalltcpports(){
    nmap --open -iL alive.ip \
	 -sTU -T4 -A -Pn -n -oA scans/portscanAllTcp -v \
	 -p T:0-65535,U:53,69,123,161,500,1434 \
	 --min-hostgroup $MINHOST --min-rate=$MINRATE
}
summary(){
    echo -e "\n[${GREEN}+${RESET}] there are $(cat ./alive.ip | wc -l ) ${YELLOW}alive hosts${RESET} and $(egrep -o '[0-9]*/open/' scans/portscan.gnmap | sort | uniq | wc -l) ${YELLOW}unique ports/services${RESET}"
    for ip in $(cat ./alive.ip); do
	echo -e $ip > ./open-ports/$ip.txt
	awk \/$ip\/ scans/portscan.gnmap | egrep -o '*[0-9]*/open/*[tcp/udp]*/' | sort | uniq | awk -F '/' '{print $1"/"$3}' >> ./open-ports/$ip.txt
    done
}
#-- calling functions
source ./selectivescans.sh
echo -e "\n[${GREEN}+${RESET}] running a ${YELLOW}ping sweep${RESET} for all ip in targets.ip"
pingsweep
echo -e "\n[${GREEN}+${RESET}] running a ${YELLOW}port scan${RESET} for all ip in alive.ip"
portscan
echo -e "\n[${GREEN}+${RESET}] running a ${YELLOW}parser${RESET} for the nse scanning"
parser
echo -e "\n[${GREEN}+${RESET}] running all then ${YELLOW}nse${RESET} scans "
nse
echo -e "\n[${GREEN}+${RESET}] to ${YELLOW}summarise${RESET} "
summary
