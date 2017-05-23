# nxdomain-attack-drop
nxdomain-attack-drop is a program written in go using libpcap made to detect
and mitigate nxdomain ddos flood attacks (
https://www.dnsknowledge.com/whatis/nxdomain-non-existent-domain-2/ ) It is
tested and works on linux. It can use **pcap**, or be setup to read **logs** of
**isc bind** format, or listen to **syslog**. It is a command line utility and
is configurable to use a **script** as default **drop action** for the detected
client ip as an argument string. Default is to drop using iptables, your own
firewall drop script / command can be used. If using -pcap or -listen root
privileges are needed.

### TODO
- [ ] Fix mutex locks for update of go 1.8 > (will panic with newer versions of go)

## Install on linux
1. install Go 1.8 or later
2. git clone 
3. enter the directory
4. install dependencies for building **libpcap-devel**, **libpcap-devel**, **ncurses-devel**
5. install dependencies where packet should run **libpcap**, **libpcap**, **ncurses**
5. go get
6. go build

## Usage
Usage of ./nxdomain-attack-drop:
  -block string
    	firewall drop command to issue when blocking hosts (only one '%%%s' substitution allowed) (default "/sbin/iptables -A INPUT -s %s -p udp --dport 53 -j DROP")
  -cores int
    	Nr of cores to utilize (default 4) (default 4)
  -listen string
    	listen for syslog <address:port>
  -maxmem int
    	Max memory allocation in Megabytes before we reset counters (default 1000)
  -ntopc int
    	Number of top clients to watch (range of toplist) (default 30)
  -ntopd int
    	Number of top domains to watch (range of toplist) (default 10)
  -path string
    	path to logs
  -pcap string
    	Set interface <name> in promiscuous mode, this will capture packets on <interface> upd port 53
  -statsn int
    	How often to update stats (per n of requests) (default 300000)

