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

nse(){
    if [ $(cat open-ports/21.txt | wc -l) -eq '0' ];
    then
	echo -e "\n[${GREEN}+${RESET}] nothing for port ${YELLOW}21${RESET}"
    else
	nmap -sC -sV -p 21 -iL open-ports/21.txt \
	     --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN nse_scans/ftp \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    fi
    if [ $(cat open-ports/22.txt | wc -l) -eq '0' ];
    then
	echo -e "\n[${GREEN}+${RESET}] nothing for port ${YELLOW}22${RESET}"
    else
	nmap -sC -sV -p 22 -iL open-ports/22.txt \
	     --script=ssh2-enum-algos -oN nse_scans/ssh \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    fi
    if [ $(cat open-ports/23.txt | wc -l) -eq '0' ];
    then
	echo -e "\n[${GREEN}+${RESET}] nothing for port ${YELLOW}23${RESET}"
    else
	nmap -sC -sV -p 23 -iL open-ports/23.txt \
	     --script=telnet-encryption,banner,tn3270-info,tn3270_screen -oN nse_scans/telnet \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    fi
    if [ $(cat open-ports/25.txt | wc -l) -eq '0' ];
    then
	echo -e "\n[${GREEN}+${RESET}] nothing for port ${YELLOW}25${RESET}"
    else
	nmap -sC -sV -p 25 -iL open-ports/25.txt \
	     --script=smtp-brute,smtp-commands,smtp-open-relay,smtp-enum-users.nse --script-args smtp-enum-users.methods={EXPN,VRFY} -oN nse_scans/smtp \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    fi
    if [ $(cat open-ports/53.txt | wc -l) -eq '0' ];
    then
	echo -e "\n[${GREEN}+${RESET}] nothing for port ${YELLOW}53${RESET}"
    else
	nmap -sU -p 53 -iL open-ports/53.txt \
	     --script=dns-recursion,dns-service-discovery,dns-cache-snoop.nse,dns-nsec-enum --script-args dns-nsec-enum.domains=example.com -oN nse_scans/dns \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    fi
    if [ $(cat open-ports/80.txt | wc -l) -eq '0' ];
    then
	echo -e "\n[${GREEN}+${RESET}] nothing for port ${YELLOW}80${RESET}"
    else   
	nmap -sC -sV -p 80 -iL open-ports/80.txt \
	     --script=http-enum,http-title,http-methods,http-robots.txt,http-trace,http-shellshock,http-vuln-cve2017-5638,http-dombased-xss,http-phpself-xss,http-wordpress-enum,http-wordpress-users \
	     -oN nse_scans/http \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    fi
    if [ $(cat open-ports/110.txt | wc -l) -eq '0' ];
    then
	echo -e "\n[${GREEN}+${RESET}] nothing for port ${YELLOW}110${RESET}"
    else
	nmap -sC -sV -p 110 -iL open-ports/110.txt \
	     --script=pop3-capabilities,pop3-brute -oN nse_scans/pop3 \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    fi
    if [ $(cat open-ports/111.txt | wc -l) -eq '0' ];
    then
	echo -e "\n[${GREEN}+${RESET}] nothing for port ${YELLOW}111${RESET}"
    else
	nmap -sV -p 111 -iL open-ports/111.txt \
	     --script=nfs-showmount,nfs-ls -oN nse_scans/nfs111 \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    fi
    if [ $(cat open-ports/123.txt | wc -l) -eq '0' ];
    then
	echo -e "\n[${GREEN}+${RESET}] nothing for port ${YELLOW}123${RESET}"
    else
    nmap -sU -p 123 -iL open-ports/123.txt \
	 --script=ntp-info,ntp-monlist -oN nse_scans/ntp \
	 --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    fi
    if [ $(cat open-ports/161.txt | wc -l) -eq '0' ];
    then
	echo -e "\n[${GREEN}+${RESET}] nothing for port ${YELLOW}161${RESET}"
    else
	nmap -sC -sU -p 161 -iL open-ports/161.txt \
	     --script=snmp-interfaces,snmp-sysdescr,snmp-netstat,snmp-processes,snmp-brute --script-args snmp-brute.communitiesdb=snmp-default.txt -oN nse_scans/snmp \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    fi
    if [ $(cat open-ports/443.txt | wc -l) -eq '0' ];
    then
	echo -e "\n[${GREEN}+${RESET}] nothing for port ${YELLOW}443${RESET}"
    else
	nmap -sC -sV -p 443 -iL open-ports/443.txt \
	     --script=http-title,http-methods,http-robots.txt,http-trace,http-shellshock,http-vuln-cve2017-5638,http-dombased-xss,http-phpself-xss,http-wordpress-enum \
	     -oN nse_scans/https \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE

	nmap -sC -sV -p 443 -iL open-ports/443.txt --version-light \
	 --script=ssl-poodle,ssl-heartbleed,ssl-enum-ciphers,ssl-cert-intaddr --script-args vulns.showall -oN nse_scans/ssl \
	 --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    fi
    if [ $(cat open-ports/445.txt | wc -l) -eq '0' ];
    then
	echo -e "\n[${GREEN}+${RESET}] nothing for port ${YELLOW}445${RESET}"
    else
	nmap -sC -sV  -p 445 -iL open-ports/445.txt \
	     --script=smb-enum-shares.nse,smb-os-discovery.nse,smb-enum-users.nse,smb-security-mode,smb-vuln-ms17-010,smb-vuln-ms08-067,smb2-vuln-uptime -oN nse_scans/smb \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    fi
    if [ $(cat open-ports/1521.txt | wc -l) -eq '0' ];
    then
	echo -e "\n[${GREEN}+${RESET}] nothing for port ${YELLOW}1521${RESET}"
    else
	nmap -p 1521-1560 -iL open-ports/1521.txt \
	     --script=oracle-sid-brute -oN nse_scans/oracle \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    fi
    if [ $(cat open-ports/2049.txt | wc -l) -eq '0' ];
    then
	echo -e "\n[${GREEN}+${RESET}] nothing for port ${YELLOW}2049${RESET}"
    else
	nmap -sV -p 2049 -iL open-ports/2049.txt \
	     --script=nfs-showmount,nfs-ls -oN nse_scans/nfs2049 \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    fi
    if [ $(cat open-ports/3306.txt | wc -l) -eq '0' ];
    then
	echo -e "\n[${GREEN}+${RESET}] nothing for port ${YELLOW}3306${RESET}"
    else
	nmap -sC -sV -p 3306 -iL open-ports/3306.txt \
	     --script=mysql-empty-password,mysql-brute,mysql-users,mysql-enum,mysql-audit --script-args "mysql-audit.username='root', \mysql-audit.password='foobar',mysql-audit.filename='nselib/data/mysql-cis.audit'" -oN nse_scans/mysql \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    
	nmap -sC -sV -p 3306 -iL open-ports/3306.txt \
	     --script=mysql-empty-password,mysql-brute,mysql-users,mysql-enum,mysql-audit --script-args "mysql-audit.username='root', \mysql-audit.password='foobar',mysql-audit.filename='nselib/data/mysql-cis.audit'" -oN nse_scans/mysql \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    fi
    if [ $(cat open-ports/5900.txt | wc -l) -eq '0' ];
    then
	echo -e "\n[${GREEN}+${RESET}] nothing for port ${YELLOW}5900${RESET}"
    else
	nmap -sC -sV -p 5900 -iL open-ports/5900.txt \
	     --script=vnc-brute,banner,vnc-title -oN nse_scans/vnc \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    fi
    if [ $(cat open-ports/8080.txt | wc -l) -eq '0' ];
    then
	echo -e "\n[${GREEN}+${RESET}] nothing for port ${YELLOW}8080${RESET}"
    else
	nmap -sC -sV -p 8080 -iL open-ports/8080.txt \
	     --script=http-title,http-robots.txt,http-methods,http-shellshock,http-vuln-cve2017-5638,http-dombased-xss,http-phpself-xss -oN nse_scans/http8080 \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    fi
    if [ $(cat open-ports/8443.txt | wc -l) -eq '0' ];
    then
	echo -e "\n[${GREEN}+${RESET}] nothing for port ${YELLOW}8443${RESET}"
    else
	nmap -sC -sV -p 8443 -iL open-ports/8443.txt \
	     --script=http-title,http-robots.txt,http-methods,http-shellshock,http-vuln-cve2017-5638,http-dombased-xss,http-phpself-xss -oN nse_scans/https8443 \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    fi
    if [ $(cat open-ports/27017.txt | wc -l) -eq '0' ];
    then
	echo -e "\n[${GREEN}+${RESET}] nothing for port ${YELLOW}27017${RESET}"
    else
	nmap -sC -sV -p 27017 -iL open-ports/27017.txt \
	     --script=mongodb-info,mongodb-databases,mongodb-brute -oN nse_scans/mongodb \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    fi
}
