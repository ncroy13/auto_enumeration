#!/bin/bash

# written by @jthorpe6 and @ncroy13

RED="\033[01;31m"
GREEN="\033[01;32m"
YELLOW="\033[01;33m"
BLUE="\033[01;34m"
BOLD="\033[01;01m"
RESET="\033[00m"

combiner(){
    touch alive.ip
    touch masscan/alive.ip
    cp masscan/scans/* scans
    cp nmap/scans/* scans
    cat masscan/scans/portscanAll.gnmap | head -n -1 test.gnmap | tail -n +3 | cut -d ' ' -f 2 | sort -u > masscan/alive.ip
    cat masscan/alive.ip nmap/alive.ip | sort -u >> alive.ip
}

parser(){
    cat scans/*.gnmap | awk '/ 21\/open\/tcp/{print $2}' | tee -a open-ports/21.txt >/dev/null
    cat scans/*.gnmap | awk '/ 22\/open\/tcp/{print $2}' | tee -a open-ports/22.txt >/dev/null
    cat scans/*.gnmap | awk '/ 23\/open\/tcp/{print $2}' | tee -a open-ports/23.txt >/dev/null
    cat scans/*.gnmap | awk '/ 25\/open\/tcp/{print $2}' | tee -a open-ports/25.txt >/dev/null
    cat scans/*.gnmap | awk '/ 53\/open\/udp/{print $2}' | tee -a open-ports/53.txt >/dev/null
    cat scans/*.gnmap | awk '/ 80\/open\/tcp/{print $2}' | tee -a open-ports/80.txt >/dev/null
    cat scans/*.gnmap | awk '/ 110\/open\/tcp/{print $2}' | tee -a open-ports/110.txt >/dev/null
    cat scans/*.gnmap | awk '/ 111\/open\/tcp/{print $2}' | tee -a open-ports/111.txt >/dev/null
    cat scans/*.gnmap | awk '/ 123\/open\/udp/{print $2}' | tee -a open-ports/123.txt >/dev/null
    cat scans/*.gnmap | awk '/ 161\/open\/udp/{print $2}' | tee -a open-ports/161.txt >/dev/null
    cat scans/*.gnmap | awk '/ 443\/open\/tcp/{print $2}' | tee -a open-ports/443.txt >/dev/null
    cat scans/*.gnmap | awk '/ 445\/open\/tcp/{print $2}' | tee -a open-ports/445.txt >/dev/null
    cat scans/*.gnmap | awk '/ 500\/open\/udp/{print $2}' | tee -a open-ports/500.txt >/dev/null
    cat scans/*.gnmap | awk '/ 1433\/open\/udp/{print $2}' | tee -a open-ports/1433.txt >/dev/null
    cat scans/*.gnmap | awk '/ 1521\/open\/tcp/{print $2}' | tee -a open-ports/1521.txt >/dev/null
    cat scans/*.gnmap | awk '/ 2049\/open\/tcp/{print $2}' | tee -a open-ports/2049.txt >/dev/null
    cat scans/*.gnmap | awk '/ 3306\/open\/tcp/{print $2}' | tee -a open-ports/3306.txt >/dev/null
    cat scans/*.gnmap | awk '/ 3389\/open\/tcp/{print $2}' | tee -a open-ports/3389.txt >/dev/null
    cat scans/*.gnmap | awk '/ 5900\/open\/tcp/{print $2}' | tee -a open-ports/5900.txt >/dev/null
    cat scans/*.gnmap | awk '/ 8080\/open\/tcp/{print $2}' | tee -a open-ports/8080.txt >/dev/null
    cat scans/*.gnmap | awk '/ 8443\/open\/tcp/{print $2}' | tee -a open-ports/8443.txt >/dev/null
    cat scans/*.gnmap | awk '/ 27017\/open\/tcp/{print $2}'| tee -a open-ports/27017.txt >/dev/null
}
