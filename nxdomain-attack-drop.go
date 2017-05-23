package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	gc "github.com/gbin/goncurses"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	//"github.com/davecheney/profile" //profiling
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

type configs struct {
	logpath     string
	listen      string
	maxmem      int
	statsn      int
	ntopd       int
	ntopc       int
	cores       int
	promiscuous string
	blockCmd    string
}

type dnsquery struct {
	query  string
	domain string
	client string
}

type domain struct {
	freq   int
	domain string
}

type domainsinclient []string
type queriesinclient []string

type dnsclient struct {
	mu              sync.Mutex // goroutine safety
	freq            int
	query           queriesinclient
	domainsinclient domainsinclient
	client          string
	abusechecked    bool // to save effort we check this only once
	isabuser        int
}

func (client *dnsclient) IsAbuser() {
	if client.abusechecked == true {
		if client.isabuser < 70 {
			return
		}
	}

	equals := make(map[string]bool)
	domains := make(map[string]int)

	for _, q := range client.query {
		equals[q] = true
		domains[domainFromQuery(q)] += 1
	}

	prcntnotequal := int((float32(len(equals)) / float32(len(client.query))) * 100) // reflects percentage of q that are uniq

	if len(client.query) == 20 { // We have enough material to evaluate
		likelyhood := prcntnotequal

		if len(domains) >= 3 {
			likelyhood = likelyhood - 30
		} else if len(domains) == 2 {
			likelyhood = likelyhood - 20
		} else {
			likelyhood = likelyhood
		}
		if likelyhood < 0 {
			likelyhood = 0
		}

		client.abusechecked = true
		client.isabuser = likelyhood
	}
}

func (domains domainsinclient) TopDomsForClient() map[int]string {
	topdomainmap := make(map[string]int)
	topdomainmapbynr := make(map[int]string)
	topNdomains := make(map[int]string)
	topnumbers := make([]int, len(topdomainmapbynr))
	for _, d := range domains {
		topdomainmap[d] += 1
	}
	for k, v := range topdomainmap {
		topnumbers = append(topnumbers, v)
		topdomainmapbynr[v] = k
	}
	sort.Ints(topnumbers)
	var topn int
	if len(topnumbers) >= 3 {
		topn = 3
	} else {
		topn = len(topnumbers)
	}
	for _, v := range topnumbers[len(topnumbers)-topn:] {
		topNdomains[v] = topdomainmapbynr[v]
	}
	return topNdomains
}

func (domains domainsinclient) String() string {
	var b bytes.Buffer
	for k, v := range domains.TopDomsForClient() {
		fmt.Fprintf(&b, "%d:%s, ", k, v)
	}
	if len(b.String()) > 50 {
		b.Truncate(50)
	}
	return strings.TrimRight(b.String(), ", ")
}

func (domains domainsinclient) Push(entry string) domainsinclient {
	n := len(domains)
	if n >= 20 { // remove last element
		ndomains := domains[1:n]
		ndomains = append(ndomains, entry)
		return ndomains
	}
	domains = append(domains, entry)
	return domains
}

func (queries queriesinclient) Push(entry string) queriesinclient { // duplicate code .. fix with interface
	n := len(queries)
	if n >= 20 { // remove last element
		nqueries := queries[1:n]
		nqueries = append(nqueries, entry)
		return nqueries
	}
	queries = append(queries, entry)
	return queries
}

var config = &configs{}

func getFilelist(logpath string) (logfiles []string) {
	filepath.Walk(logpath, func(path string, info os.FileInfo, err error) error {
		if strings.Contains(info.Name(), ".log") {
			logfiles = append(logfiles, path)
		}
		return nil
	})
	return logfiles
}

func init() {
	logpath := flag.String("path", "", "path to logs")
	listen := flag.String("listen", "", "listen for syslog <address:port>")
	maxmem := flag.Int("maxmem", 1000, "Max memory allocation in Megabytes before we reset counters")
	ntopc := flag.Int("ntopc", 30, "Number of top clients to watch (range of toplist)")
	ntopd := flag.Int("ntopd", 10, "Number of top domains to watch (range of toplist)")
	promiscuous := flag.String("pcap", "", "Set interface <name> in promiscuous mode, this will capture packets on <interface> upd port 53")
	cores := flag.Int("cores", 4, "Nr of cores to utilize (default 4)")
	statsn := flag.Int("statsn", 300000, "How often to update stats (per n of requests)")
	blockCmd := flag.String("block", "/sbin/iptables -A INPUT -s %s -p udp --dport 53 -j DROP", "firewall drop command to issue when blocking hosts (only one '%%%s' substitution allowed)")
	flag.Parse()
	config.logpath = *logpath
	config.listen = *listen
	config.maxmem = *maxmem
	config.promiscuous = *promiscuous
	config.ntopc = *ntopc
	config.ntopd = *ntopd
	config.cores = *cores
	config.statsn = *statsn
	config.blockCmd = *blockCmd
}

func parseFile(wg *sync.WaitGroup, logpath string) chan string {
	localLinechan := make(chan string, 20000)

	go func(localLinechan chan string) {
		defer close(localLinechan)
		f, err := os.Open(logpath)
		defer f.Close()

		if err != nil {
			Pushlog(fmt.Sprintf("Error opening file %s %v", f, err))
		}

		r := bufio.NewReader(f)

		Pushlog(fmt.Sprintf("Parsing: %s ", logpath))

		for {
			select {
			case <-quit:
				Pushlog(fmt.Sprintf("Exiting parsing of %s", logpath))
				return
			default:

				line, err := r.ReadString(10) // 0x0A separator = newline
				//fmt.Println(line) //debug
				if err == io.EOF {
					Pushlog(fmt.Sprintf("Done with %s", logpath))
					return
				} else if err != nil {
					Pushlog(fmt.Sprintf("Failed to parse file %s: %v\n", logpath, err))
					return
				}
				localLinechan <- line
			}
		}
	}(localLinechan)

	return localLinechan
}

func parseFiles(paths []string) chan string {
	filesLineChan := make(chan string, 200000)
	Pushlog(fmt.Sprintf("Parsing files: %v", paths))

	go func(filesLineChan chan string) {
		defer close(filesLineChan)

		for _, file := range paths {
			// we serialize the logfile parsing, since we want them parsed in some sort of order in order to get real client frequencies
			var wg *sync.WaitGroup
			localLinechan := parseFile(wg, file)

			for line := range localLinechan {
				filesLineChan <- line
				//linechan <- line
			}
		}
		Pushlog(fmt.Sprintf("All files parsed!"))

	}(filesLineChan)

	return filesLineChan
}

var qlineregex = regexp.MustCompile(`(client)\s+(\d+\.\d+\.\d+\.\d+)(#\d+)\s+\S+\s+query:\s+(\S+)\s+IN`)
var domainregex = regexp.MustCompile(`\S+\.(\S+\.\S+$)`)

func domainFromQuery(query string) string {
	domparts := strings.Split(query, ".")
	splitat := 0
	if len(domparts) >= 2 {
		splitat = 2
	}
	domain := strings.Join(domparts[len(domparts)-splitat:], ".")
	return domain
}

func parseqLines(linechan chan string) chan *dnsquery {
	localQchan := make(chan *dnsquery, 100)
	go func(localQchan chan *dnsquery) {
		defer close(localQchan)
		for {
			select {
			case <-quit:
				Pushlog("Closing query line parsing")
				return
			case line := <-linechan:
				/*
					//fmt.Println(line) //debug
					//regex
					if matched := qlineregex.FindStringSubmatch(line); len(matched) != 0 {
						thisq := &dnsquery{}
						thisq.client = matched[2]
						thisq.query = matched[4]
						domparts := strings.Split(thisq.query, ".")
						splitat := 0
						if len(domparts) >= 2 {
							splitat = 2
						}
						thisq.domain = strings.Join(domparts[len(domparts)-splitat:], ".")
						// end regex
				*/
				// Text method ~ 3 times faster
				isArec := strings.Index(line, " IN A")
				if isArec != -1 {
					thisq := &dnsquery{}
					clientidxstart := strings.Index(line, "info: client ") // len 13
					clientidxstart = clientidxstart + 13
					clientidxstop := strings.Index(line, "#") // len 13
					client := line[clientidxstart:clientidxstop]
					thisq.client = client
					if thisq.client == "" {
						Pushlog(fmt.Sprintf("Parsefail: %s", line))
					}

					queryidxstart := strings.Index(line, ": query: ") // len 9
					queryidxstart = queryidxstart + 9
					query := line[queryidxstart:isArec]
					thisq.query = query

					thisq.domain = domainFromQuery(query)
					// end text method

					localQchan <- thisq
				} //else { // debug
			}
		}
	}(localQchan)

	return localQchan
}

func getClientsByFreq(queryMap map[string]*dnsclient) map[string]*dnsclient {
	frequencies := make([]int, 0, len(queryMap))
	clientsByFreq := make(map[int][]string, len(queryMap))
	clientsByFreqTop := make(map[string]*dnsclient, config.ntopc)

	for key, value := range queryMap {
		clientsByFreq[value.freq] = append(clientsByFreq[value.freq], key)
	}

	for frequency, _ := range clientsByFreq { //create an array that we can sort
		frequencies = append(frequencies, frequency)
	}
	sort.Ints(frequencies)
	ntopc := config.ntopc

	if ntopc > len(frequencies) {
		ntopc = len(frequencies)
	} // ensure we do not slice less than is available

	for _, frequency := range frequencies[len(frequencies)-ntopc:] {
		clientsByFreqTop[clientsByFreq[frequency][0]] = queryMap[clientsByFreq[frequency][0]]
	}
	return clientsByFreqTop
}

func sortedClientsbyfrequency(clientsByFreqTop map[string]*dnsclient) (map[int]string, []int) {
	/* Given a map returns new map with "freq" as key and a sorted list to use as a base for presentation*/
	frequencies := make([]int, 0, len(clientsByFreqTop))
	sortedclientbyfreq := make(map[int]string, len(clientsByFreqTop))
	for k, v := range clientsByFreqTop { //create an array that we can sort
		frequencies = append(frequencies, v.freq)
		sortedclientbyfreq[v.freq] = k
	}
	sort.Ints(frequencies)
	return sortedclientbyfreq, frequencies
}

func printIntermediarySecondRunStats(domainMap map[string]*domain, clientsByFreqTop map[string]*dnsclient) {
	var buffer bytes.Buffer
	sortedclientbyfreq, frequencies := sortedClientsbyfrequency(clientsByFreqTop)

	for _, f := range frequencies {
		client := sortedclientbyfreq[f]
		var queryexamples string

		if _, ok := clientsByFreqTop[client]; ok { // to remedy the case when it changes outside of this goroutine
			clientsByFreqTop[client].IsAbuser()
			if len(clientsByFreqTop[client].query) > 3 { // we get the last three queries for client
				queryexamples = strings.Join(clientsByFreqTop[client].query[len(clientsByFreqTop[client].query)-3:], "; ")
			}
			fmt.Fprintf(&buffer, "%-10d %-16s%-3v %-50s %s\n", f, client, clientsByFreqTop[client].isabuser, clientsByFreqTop[client].domainsinclient, queryexamples)
		}
	}

	//Print domain stats
	dfrequencies := make([]int, 0, len(domainMap))
	domainsByFreq := make(map[int][]string, len(domainMap))
	for key, value := range domainMap {
		domainsByFreq[value.freq] = append(domainsByFreq[value.freq], key)
	}

	for frequency, _ := range domainsByFreq { //create an array that we can sort
		dfrequencies = append(dfrequencies, frequency)
	}

	sort.Ints(dfrequencies)
	ntopd := config.ntopd

	if len(dfrequencies) < ntopd {
		ntopd = len(dfrequencies)
	}

	fmt.Fprintf(&buffer, "\n%-18s %s\n", "Frequency", "Domain")

	for _, frequency := range dfrequencies[len(dfrequencies)-ntopd:] {
		fmt.Fprintf(&buffer, "%-18d %s\n", frequency, domainsByFreq[frequency])
	} //End printing top domains
	headerscScrnChan <- fmt.Sprintf("%-10s %-16s%-3s %-50s %s\n", "Queries", "Client", "NX", "Clients Topdomains (Top 3 from last 20)", "Last 3 queries")
	mainScrnChan <- buffer.String()
}

func printIntermediaryStats(domainMap map[string]*domain, queryMap map[string]*dnsclient) {
	var buffer bytes.Buffer
	frequencies := make([]int, 0, len(queryMap))
	clientsByFreq := make(map[int][]string, len(queryMap))

	for key, value := range queryMap {
		clientsByFreq[value.freq] = append(clientsByFreq[value.freq], key)
	}

	for frequency, _ := range clientsByFreq { //create an array that we can sort
		frequencies = append(frequencies, frequency)
	}
	sort.Ints(frequencies)
	ntopc := config.ntopc

	if len(frequencies) < ntopc {
		ntopc = len(frequencies)
	}

	fmt.Fprintf(&buffer, "%-12s %-16s\n", "Frequency", "Client(s)")

	for _, frequency := range frequencies[len(frequencies)-ntopc:] {
		fmt.Fprintf(&buffer, "%-12d %-16s\n", frequency, clientsByFreq[frequency])
	} //End printing top clients

	//Print domain stats
	dfrequencies := make([]int, 0, len(domainMap))
	domainsByFreq := make(map[int][]string, len(domainMap))
	for key, value := range domainMap {
		domainsByFreq[value.freq] = append(domainsByFreq[value.freq], key)
	}

	for frequency, _ := range domainsByFreq { //create an array that we can sort
		dfrequencies = append(dfrequencies, frequency)
	}

	sort.Ints(dfrequencies)
	ntopd := config.ntopd

	if len(dfrequencies) < ntopd {
		ntopd = len(dfrequencies)
	}

	fmt.Fprintf(&buffer, "\n%-18s %s\n", "Frequency", "Domain")

	for _, frequency := range dfrequencies[len(dfrequencies)-ntopd:] {
		fmt.Fprintf(&buffer, "%-18d %s\n", frequency, domainsByFreq[frequency])
	} //End printing top domains
	mainScrnChan <- buffer.String()

}

func blockClients(blockCmd string, clientIPs ...string) error {
	var blockerror error
	for _, cliIP := range clientIPs {
		blkstr := fmt.Sprintf(blockCmd, cliIP)
		bin, args := strings.Fields(blkstr)[0], strings.Fields(blkstr)[1:]
		cmd := exec.Command(bin, args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			Pushlog(string(out))
			blockerror = fmt.Errorf("Failed to block %v", cliIP)
			Pushlog(fmt.Sprintf("Failed to block %v", cliIP))
		} else {
			Pushlog(fmt.Sprintf("Blocked %s", cliIP))
		}
	}
	return blockerror
}

func qReceiver(commandchannel chan string, qchan <-chan *dnsquery, stdscr *gc.Window) {
	timeprocessingmark := time.Now()
	ticker := time.Tick(2 * time.Second)
	filteroutClients := make(map[string]bool) // the ability to filter out non offenders
	blockedClients := make(map[string]bool)   // the ability to block clients (iptables command)
	queryMap := map[string]*dnsclient{}
	domainMap := map[string]*domain{}
	clientsByFreqTop := map[string]*dnsclient{}
	qchango := true
	passes := 0
	passesSince := 0
	var domainfilter string
	togglefreeze := false
	var queriesParsed int64

Queryloop:
	for qchango {
		select {
		case c, _ := <-commandchannel: // Receive commands and behave accordingly
			if c == "r" {
				Pushlog("Resetting stats, emptying memory")
				queryMap = map[string]*dnsclient{}
				domainMap = map[string]*domain{}
				clientsByFreqTop = map[string]*dnsclient{}
				runtime.GC()
			} else if c == "f" {
				if togglefreeze {
					togglefreeze = false
				} else {
					togglefreeze = true
				}
			} else if c == "d" { // filter out top offenders for specified domain
				if domainfilter != "" {
					domainfilter = ""
					untogglemodeScrnChan <- fmt.Sprintf("No domain filter")
					commandchannel <- "Commence commander"
				} else {
					togglefreeze = true
					togglemodeScrnChan <- fmt.Sprintf("Input domain to filter on:")
					domainfilter = <-userInputs
					queryMap = map[string]*dnsclient{}
					domainMap = map[string]*domain{}
					togglefreeze = false
					commandchannel <- "Commence commander"
				}

			} else if c == "m" { // filter out top offenders for specified domain
				// TODO
				// Use a select to decide what to do with the selected clients
				// function must be added to list filtered clients and to unfilter
				// also function to block / unblock
				togglefreeze = true
				clientMenuChan <- clientsByFreqTop
				var filterClients []string

				select {
				case filterClients = <-clientFilterChan: // Filter selected clients
					for _, c := range filterClients {
						filteroutClients[c] = true
						Pushlog(fmt.Sprintf("Ignoring client: %v", c))
					}

				case filterClients = <-clientBlockChan: // Block selected clients
					for _, c := range filterClients {
						if err := blockClients(config.blockCmd, c); err == nil {
							blockedClients[c] = true
							filteroutClients[c] = true
						}
					}

				}

				togglefreeze = false
				for k, _ := range filteroutClients {
					delete(clientsByFreqTop, k)
					delete(queryMap, k)
				}
				clientsByFreqTop = getClientsByFreq(queryMap)
				commandchannel <- "Commence commander"
			}

		case r, qok := <-qchan:
			if qok != true {
				qchango = false
				return
			}
			if filteroutClients[r.client] { // We ignore clients in filter list
				continue
			}
			if domainfilter != "" { // We ignore clients not in domain if we are in domain mode
				if r.domain != domainfilter {
					continue
				}
			}

			queriesParsed += 1

			if _, ok := clientsByFreqTop[r.client]; ok { // client in top clients
				//fmt.Println(r.client, client)
				clientsByFreqTop[r.client].domainsinclient = clientsByFreqTop[r.client].domainsinclient.Push(r.domain) // only last 10 kept
				clientsByFreqTop[r.client].query = clientsByFreqTop[r.client].query.Push(r.query)                      // only last 10 kept
				clientsByFreqTop[r.client].freq += 1
			}
			//} // end second run mode

			//fmt.Printf("qreceiver: %v\n", r)
			if _, ok := queryMap[r.client]; ok { // client exist in map
				queryMap[r.client].freq += 1
				//queryMap[r.client].query = queryMap[r.client].query.Push(r.query) // costly for all clients
			} else {
				queryMap[r.client] = &dnsclient{} // this is the first encounter
				queryMap[r.client].freq = 1
				queryMap[r.client].query = queryMap[r.client].query.Push(r.query) // we do this at least once (first access)

			}

			if _, ok := domainMap[r.domain]; ok { // domain exist in map
				domainMap[r.domain].freq += 1
			} else {
				domainMap[r.domain] = &domain{}
				domainMap[r.domain].freq = 1
			}

			passes += 1
			passesSince += 1

		case tick := <-ticker:
			if !togglefreeze { // We renew the top clients
				clientsByFreqTop = getClientsByFreq(queryMap)
				go printIntermediarySecondRunStats(domainMap, clientsByFreqTop) // Dirty reads are ok
			}

			timedelta := time.Since(timeprocessingmark)
			timeprocessingmark = tick
			statsScrnChan <- newParserStats(fmt.Sprintf("Total queries parsed: %d; q/sec %d", queriesParsed, int(float64(passesSince)/timedelta.Seconds())))
			if reset := memoryManager(); reset {
				Pushlog("Resetting stats, emptying memory!")
				queryMap = map[string]*dnsclient{}
				domainMap = map[string]*domain{}
				clientsByFreqTop = map[string]*dnsclient{}
				runtime.GC()
				passes = 0
				continue Queryloop
			}

			passes = 0
			passesSince = 0
		} // End select
	} // End for
}

func listenUdp(listen string) chan string {
	localLinechan := make(chan string, 100000)
	// we receive log lines directly from syslog udp here and produce a line channel
	// that is merged with the others

	//listen := "127.0.0.1:1200"

	go func(chan string) {
		defer fmt.Println("Closing localLinechan in udpLinechannel")
		defer close(localLinechan)
		udpAddress, err := net.ResolveUDPAddr("udp4", listen)

		if err != nil {
			Pushlog(fmt.Sprintf("error resolving UDP address on ", listen))
			log.Fatal(err)
		}

		conn, err := net.ListenUDP("udp", udpAddress)
		defer conn.Close()

		if err != nil {
			Pushlog(fmt.Sprintf("error listening on UDP port: %s", listen))
			log.Fatal(err)
		} else {
			Pushlog(fmt.Sprintf("Listening on %s", listen))
		}

		var buf []byte = make([]byte, 2048)

		for {
			//time.Sleep(100 * time.Millisecond)

			n, address, err := conn.ReadFromUDP(buf)

			if err != nil {
				fmt.Println("error reading data from connection")
				fmt.Println(err)
			}

			if address != nil {
				//fmt.Println("got message from ", address, " with n = ", n)
				if n > 0 {
					//fmt.Println("from address", address, "got message:", string(buf[0:n]), n)
					localLinechan <- string(buf[0:n])
				}
			}
		}
	}(localLinechan)

	return localLinechan
}

func buildPcapString() string {
	iFace := &net.Interface{}
	if foundiFace, err := net.InterfaceByName(config.promiscuous); err != nil {
		log.Fatal(err)
	} else {
		iFace = foundiFace
	}
	basestring := "udp and port 53"
	ifaceAddresses, _ := iFace.Addrs()                               // we are taking for granted that we will get hold of addresses here
	ifaceAdress := strings.Split(ifaceAddresses[0].String(), "/")[0] // Strip netmask
	Pushlog(fmt.Sprintf("Pcap filter: udp and port 53 and not src host %s", ifaceAdress))
	return fmt.Sprintf("%s and not src host %s", basestring, ifaceAdress) // we choose to filter out the host address so only external clients are seen
}

func pcapHandler() (chan *dnsquery, error) { // handles promiscuous mode capture
	localQchan := make(chan *dnsquery, 100000)
	pcapString := buildPcapString()
	var packetSource *gopacket.PacketSource
	var handle *pcap.Handle
	var err error

	if handle, err = pcap.OpenLive(config.promiscuous, 2048, true, 0); err != nil {
		return localQchan, err
	}

	if err = handle.SetBPFFilter(pcapString); err != nil {
		return localQchan, err
	}

	packetSource = gopacket.NewPacketSource(handle, handle.LinkType())

	go func(chan *dnsquery) {
		defer close(localQchan)

	PKLOOP:
		for {
			select {
			case <-quit:
				return
			default:
				packet, err := packetSource.NextPacket()
				if err == io.EOF {
					break
				} else if err != nil {
					log.Println("Error:", err)
					continue
				}

				if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
					//fmt.Println("DEBUG:", packet) //debug
					if dnsLayer.(*layers.DNS).QR == true || dnsLayer.(*layers.DNS).QDCount < 1 {
						continue PKLOOP
					} // this is not a query
					//Pushlog("This is a query")
					ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4).SrcIP // src ip
					query := string(dnsLayer.(*layers.DNS).Questions[0].Name)     // first dns query
					domparts := strings.Split(query, ".")
					splitat := 0
					if len(domparts) >= 2 {
						splitat = 2
					}
					domain := strings.Join(domparts[len(domparts)-splitat:], ".")
					if domain == "in-addr.arpa" {
						continue PKLOOP
					}
					//Pushlog(ip, query, domain)
					thisq := &dnsquery{query, domain, ip.String()}
					localQchan <- thisq
				}
			}
		}
	}(localQchan)
	return localQchan, nil
}

func signalHandler(c chan os.Signal) {
	for {
		select {
		case command := <-c:
			mainScrnChan <- fmt.Sprintf("Caught: ", command, " exiting this neat little util.")
			//exec.Command("stty", "-F", "/dev/tty", "echo").Run()
			//os.Exit(0)
			close(quit)
		}
	}
}

func memoryManager() bool {
	memStats := &runtime.MemStats{}
	runtime.ReadMemStats(memStats)
	mballocated := int((memStats.Alloc / 1024) / 1024)
	statsScrnChan <- newMemstat(fmt.Sprintf("Memory Allocated: %d MB", mballocated))
	return mballocated > config.maxmem
}

func mergeQchans(chans ...<-chan *dnsquery) <-chan *dnsquery {
	//we merge channels returned by queryproducers

	allQ := make(chan *dnsquery, 100000)
	var wg sync.WaitGroup

	wg.Add(len(chans))

	go func() {
		wg.Wait()
		Pushlog("Closing all queries channel.")
		close(allQ)
	}()

	go func() {
		for _, ch := range chans {
			go func(ch <-chan *dnsquery) {
				for s := range ch {
					allQ <- s
				}
				wg.Done()
			}(ch)

		}
		wg.Wait()
	}()

	return allQ
}

func mergeLinechans(chans ...chan string) chan string {
	//we merge channels returned by line producers

	allLinechans := make(chan string)
	var wg sync.WaitGroup

	wg.Add(len(chans))

	go func() {
		defer close(allLinechans)

		for _, ch := range chans {
			go func(ch chan string) {
				for line := range ch {
					allLinechans <- line
				}
				wg.Done()
			}(ch)
		}
		wg.Wait()
	}()
	return allLinechans
}

// Start ncurses stuff
type scrnUpdate struct {
	data string
	row  int
	col  int
}

func newParserStats(data string) *scrnUpdate {
	return &scrnUpdate{data, 0, 0}
}
func newMemstat(data string) *scrnUpdate {
	return &scrnUpdate{data, 1, 0}
}

var logmsgs = []string{}
var logmsgsc = make(chan string)

func logMsgRcvr() {
	for {
		select {

		case logentry := <-logmsgsc:
			var buffer bytes.Buffer
			nlogmsgs := []string{}
			n := len(logmsgs)
			if n >= 5 { // remove last element
				nlogmsgs = logmsgs[1:]
				nlogmsgs = append(nlogmsgs, logentry)
				logmsgs = nlogmsgs
			} else {
				logmsgs = append(logmsgs, logentry)
			}
			for _, entry := range logmsgs {
				fmt.Fprintf(&buffer, entry)
				fmt.Fprintf(&buffer, "\n")
			}
			logScrnChan <- buffer.String()
		case <-quit:
			return
		}
	}
}

func Pushlog(logentry string) { // we keep a log of 10 msgs
	logmsgsc <- logentry
}

func initCurses() (*gc.Window, *gc.Window, *gc.Window, *gc.Window, *gc.Window, *gc.Window, *gc.Window, *gc.Window) { // initialize ncurses
	var stdscr *gc.Window
	var err error
	if stdscr, err = gc.Init(); err != nil {
		log.Fatal("init curses: ", err)
	}

	//gc.Raw(true)   // turn on raw "uncooked" input
	gc.CBreak(true) // turn on raw "uncooked" input
	gc.Echo(false)  // turn echoing of typed characters off
	gc.Cursor(0)    // hide cursor
	gc.StartColor()
	gc.InitPair(1, gc.C_BLACK, gc.C_WHITE)
	stdscr.Keypad(true) // allow keypad input
	statswin, _ := gc.NewWindow(3, 60, 0, 0)
	headerwin, _ := gc.NewWindow(1, 200, 8, 0)
	headerwin.SetBackground(gc.ColorPair(2))
	headerwin.ColorOn(1)
	helpwin, _ := gc.NewWindow(1, 200, 7, 0)
	modewin, _ := gc.NewWindow(1, 60, 4, 0)
	inputwin, _ := gc.NewWindow(1, 200, 6, 0)
	logwin, _ := gc.NewWindow(6, 60, 0, 61)
	mainwin, _ := gc.NewWindow(60, 200, 9, 0)
	logwin.Print("Logs:\n")
	stdscr.Refresh()
	logwin.Refresh()
	return stdscr, inputwin, statswin, modewin, logwin, mainwin, headerwin, helpwin
}

func inputToggler(toggle bool) func() {
	if toggle {
		return func() {
			gc.CBreak(false)
			gc.Echo(true)
			gc.Cursor(1)
		}
	}
	return func() {
		gc.CBreak(true)
		gc.Echo(false)
		gc.Cursor(0)
	}
}

var toggleInput = inputToggler(true)
var untoggleInput = inputToggler(false)

func clientMenuscrn(stdscr *gc.Window, window *gc.Window, clientsByFreqTop map[string]*dnsclient) { // map of top offenders will be the menu

	sortedclientbyfreq, frequencies := sortedClientsbyfrequency(clientsByFreqTop)

	items := make([]*gc.MenuItem, len(frequencies))

	for idx, f := range frequencies {
		client := sortedclientbyfreq[f]
		var queryexamples string

		if len(clientsByFreqTop[client].query) > 3 { // we get the last three queries for client
			queryexamples = strings.Join(clientsByFreqTop[client].query[len(clientsByFreqTop[client].query)-3:], "; ")
		}
		//items[idx], _ = gc.NewItem(fmt.Sprintf("%-10d %-18s %-50s %s", f, client, clientsByFreqTop[client].domainsinclient, queryexamples), client)
		items[idx], _ = gc.NewItem(fmt.Sprintf("%-10d %-16s%-3v %-50s %s", f, client, clientsByFreqTop[client].isabuser, clientsByFreqTop[client].domainsinclient, queryexamples), client)
	}
	for i := range items {
		defer items[i].Free()
	}

	menu, _ := gc.NewMenu(items)
	defer menu.UnPost()
	defer menu.Free()
	menu.Option(gc.O_ONEVALUE, false)
	menu.Format(len(frequencies), 1)
	window.Erase()
	window.Refresh()
	menu.SetWindow(window)
	menu.Post()
	time.Sleep(time.Millisecond * 50)
	window.Refresh()
	var clientlist []string

	// Pre set some items that are highly suspicious
	for _, item := range items {
		if clientsByFreqTop[item.Description()].isabuser > 85 {
			item.SetValue(true)
		}
	}

	for {
		//gc.Update()
		window.Refresh()
		ch := stdscr.GetChar()

		switch ch {
		case 'b': // block
			for _, item := range items {
				if item.Value() {
					log.Println(item.Value(), item.Description())
					clientlist = append(clientlist, item.Description())
				}
			}

			clientBlockChan <- clientlist
			return

		//case gc.KEY_RETURN, gc.KEY_ENTER: // change to 'f' //filter
		case 'f': // change to 'f' //filter
			for _, item := range items {
				if item.Value() {
					log.Println(item.Value(), item.Description())
					clientlist = append(clientlist, item.Description())
				}
			}

			clientFilterChan <- clientlist
			return

		case 'q':
			clientFilterChan <- []string{}
			return
		case ' ':
			menu.Driver(gc.REQ_TOGGLE)
		case 'a':
			for _, item := range items { //mark all
				item.SetValue(true)
			}
		default:
			menu.Driver(gc.DriverActions[ch])
		}
	}
}

func screenHandler(stdscr *gc.Window, inputwin *gc.Window,
	statswin *gc.Window, modewin *gc.Window, logwin *gc.Window, mainwin *gc.Window, headerwin *gc.Window, helpwin *gc.Window) {

	mainhelpwininfo := "'m':menu; 'r': mem reset; 'q': quit; 'd': domainfilter"
	helpwin.Printf(mainhelpwininfo)
	helpwin.Refresh()

	for {
		select {
		// Todo implement terminal resize
		case scrupdate := <-mainScrnChan:
			//row, col := stdscr.MaxYX()
			//stdscr.MovePrint(scrupdate.row, scrupdate.col, scrupdate.data)
			//stdscr.Refresh()
			mainwin.Erase()
			mainwin.Print(scrupdate)
			mainwin.Refresh()

		case scrupdate := <-helpScrnChan:
			helpwin.Erase()
			helpwin.Print(scrupdate)
			helpwin.Refresh()

		case scrupdate := <-headerscScrnChan:
			headerwin.Erase()
			headerwin.Print(scrupdate)
			headerwin.Refresh()

		case scrupdate := <-logScrnChan:
			logwin.Erase()
			logwin.Print(scrupdate)
			logwin.Refresh()

		case clientsByFreqTop := <-clientMenuChan:
			gc.StartColor()
			gc.Raw(true)
			gc.Echo(false)
			gc.Cursor(0)
			stdscr.Keypad(true)

			helpwin.Clear()
			helpwin.Printf("'<space>: mark'; 'b':block client; 'f': filter client; 'q': quit menu")
			helpwin.Refresh()
			clientMenuscrn(stdscr, mainwin, clientsByFreqTop)
			//toggleInput()
			untoggleInput()
			helpwin.Clear()
			helpwin.Printf(mainhelpwininfo)
			helpwin.Refresh()

		case scrupdate := <-statsScrnChan:
			statswin.MovePrint(scrupdate.row, scrupdate.col, scrupdate.data)
			statswin.Refresh()

		case scrupdate := <-togglemodeScrnChan: // Enable domain filter
			toggleInput()
			var str string
			modewin.Erase()
			modewin.Print(scrupdate)

			str, _ = modewin.GetString(100)
			userInputs <- str

			modewin.Erase()
			untoggleInput()
			modewin.Print(fmt.Sprintf("Filtering on domain: %s", str))
			modewin.Refresh()

		case scrupdate := <-inputFilterChan: // Filter out clients
			toggleInput()
			var str string
			inputwin.Erase()
			inputwin.Print(scrupdate)

			str, _ = inputwin.GetString(300)
			userInputs <- str

			modewin.Erase()
			untoggleInput()
			modewin.Print(fmt.Sprintf("Filtering ips: %s", str))
			modewin.Refresh()

		case scrupdate := <-untogglemodeScrnChan:
			modewin.Erase()
			modewin.Print(scrupdate)
			modewin.Refresh()
			untoggleInput()

		case <-quit:
			mainwin.Print("Quitting!")
			mainwin.Refresh()
			mainwin.Erase()
			return
		}
	}
}

func commander(stdscr *gc.Window) {
	for {
		switch stdscr.GetChar() {
		case 'q':
			/*if _, ok := <-quit; ok == true {
				close(quit)
			}*/
			//close(quit)
			signalc <- os.Interrupt
			return
		case 'r':
			commandchannel <- "r"
		case 'd': // domain filter
			commandchannel <- "d"
			<-commandchannel
		case 'f': //freeze
			commandchannel <- "f"
		case 'm': // Menu
			commandchannel <- "m"
			<-commandchannel
		}

	}
}

// End ncurses stuff

var commandchannel = make(chan string) // Send commands to us
var signalc = make(chan os.Signal, 1)  // Channel receiving signals
var quit = make(chan struct{})         // Channel receiving signals
var mainScrnChan = make(chan string)
var headerscScrnChan = make(chan string)
var logScrnChan = make(chan string)
var helpScrnChan = make(chan string)
var statsScrnChan = make(chan *scrnUpdate)
var togglemodeScrnChan = make(chan string)
var untogglemodeScrnChan = make(chan string)
var inputFilterChan = make(chan string)
var userInputs = make(chan string)
var clientMenuChan = make(chan map[string]*dnsclient)
var clientFilterChan = make(chan []string)
var clientBlockChan = make(chan []string)

//var scrnLogBuffer bytes.Buffer //Log to screen
//var ScrnLogger = log.New(scrnLogBuffer, "", 2)

func main() {
	// logging setup
	logFile, _ := os.OpenFile("/tmp/x_abuse_parser", os.O_WRONLY|os.O_CREATE|os.O_SYNC, 0644) // log panic to file /tmp/x_abuse_parser
	log.SetOutput(logFile)
	defer logFile.Close()
	syscall.Dup2(int(logFile.Fd()), 2) // log panic to file

	//defer profile.Start(profile.CPUProfile).Stop() // Profiling

	// ncurses
	stdscr, inputwin, statswin, modewin, logwin, mainwin, headerwin, helpwin := initCurses()
	defer inputwin.Delete()
	defer headerwin.Delete()
	defer statswin.Delete()
	defer modewin.Delete()
	defer logwin.Delete()
	defer mainwin.Delete()
	defer helpwin.Delete()
	defer gc.End()
	defer stdscr.Delete()

	go screenHandler(stdscr, inputwin, statswin, modewin, logwin, mainwin, headerwin, helpwin)
	go logMsgRcvr()
	go commander(stdscr)
	// end ncurses

	runtime.GOMAXPROCS(config.cores)     // Cores to use
	signal.Notify(signalc, os.Interrupt) // ^C
	signal.Notify(signalc, syscall.SIGTERM)

	// start providers of log lines
	var linechannels = []chan string{}
	if config.logpath != "" {
		logfiles := getFilelist(config.logpath)
		linechannels = append(linechannels, parseFiles(logfiles))
	}
	if config.listen != "" {
		linechannels = append(linechannels, listenUdp(config.listen))
	}

	linechan := mergeLinechans(linechannels...) // merge linechannels here
	// end providers of log lines

	//creating a few lineparsers receiving from linereceivers
	var qchans = []<-chan *dnsquery{}
	for c := 1; c < config.cores+1; c++ {
		Pushlog(fmt.Sprintf("creating qchan: %v", c))
		qchans = append(qchans, parseqLines(linechan))
	}

	if config.promiscuous != "" {
		if pcapqchan, err := pcapHandler(); err != nil {
			Pushlog(fmt.Sprintf("%q", err))
			Pushlog(fmt.Sprintf("%s", "Quitting!!!"))
			time.Sleep(time.Second * 5)
			close(quit)
			return
		} else {
			qchans = append(qchans, pcapqchan)
		}

	}

	qchan := mergeQchans(qchans...)

	go qReceiver(commandchannel, qchan, stdscr) // can this be put in a goroutine likely of no use since locking is needed
	//one solution could be to aggregate from many to one

	<-signalc
	Pushlog(fmt.Sprintf("Exiting this neat little util."))
	//exec.Command("stty", "-F", "/dev/tty", "echo").Run()
} // end main
