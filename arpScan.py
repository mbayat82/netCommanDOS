# == IMPORT ==
try:
    #Import general
    import socket, sys
    #Import local
    from netlib import *
    #Import 3rd party
    import netaddr, netifaces
    from scapy.all import *
    from sty import fg, bg, ef, rs
    from tqdm import tqdm
    from prettytable import PrettyTable
except Exception as e:
    print (e)
    sys.exit()

# == Global Variable ==
lastResult = ""     #to check if discovered IP is already printed to screen

def sendARP(interface, sourceMAC, destMAC, sourceIP, destIP):
    #global variables
    global lastResult
    #crafting arp packet
    pkt = Ether(src=sourceMAC,
                dst=destMAC,
                type=2054) / ARP(hwdst=destMAC,
                                 ptype=2048, hwtype=1,
                                 psrc=sourceIP,
                                 hwlen=6,
                                 plen=4,
                                 pdst=destIP,
                                 hwsrc=sourceMAC,
                                 op=1)
    try:
        answered, unanswered = srp(pkt, iface=interface, timeout=1, verbose=0)
        for send, received in answered:
            #print IP address of host who answered arp packet   
            if received.psrc != lastResult:
                lastResult = received.psrc        
                tqdm.write(fg.li_green + received.psrc + " " + received[Ether].src + fg.rs)
    except Exception as e:
        print(e)     
        print(fg.li_red + "Something went wrong. Packet was not sent" + fg.rs)

def arpScan(selectedInterface):
    global lastResult
    
    while(1):
        os.system('cls' if os.name == 'nt' else 'clear')
        printTitle("ARP Scan")
        print("")
        lastResult = ""

        networkSubnetMask = getNetworkSubnetMask(selectedInterface['ips'][1])
        if networkSubnetMask == "e":
            os.system('cls' if os.name == 'nt' else 'clear')
            return
        
        #print scanned network information
        os.system('cls' if os.name == 'nt' else 'clear')
        printTitle("ARP Scan")
        print("")
        network = netaddr.IPNetwork(networkSubnetMask)
        print("Network  : ",network.network)
        print("Mask     : ", network.netmask)
        print("Hosts    : ", network.size)
        print("")

        #Keep a list of all threads created.
        threads = list()

        #iterate subnet range
        for i in tqdm(range (network.size), file=sys.stdout, leave=False):

            if i == 0:
                tqdm.write('ARP Responses:\n')

            try:
                #source ip is one ip before destination ip
                packetDestIP = network[i]
                packetSourceIP = network[i-1]
                arpThread = threading.Thread(target=sendARP,args=(selectedInterface['name'],
                                                        selectedInterface['mac'],
                                                        "ff:ff:ff:ff:ff:ff",
                                                        packetSourceIP,
                                                        packetDestIP), daemon=True)

                threads.append(arpThread)
                arpThread.start()

                #source ip is one ip after destination ip
                packetSourceIp = network[i+1]
                arpThread = threading.Thread(target=sendARP,args=(selectedInterface['name'],
                                                        selectedInterface['mac'],
                                                        "ff:ff:ff:ff:ff:ff",
                                                        packetSourceIP,
                                                        packetDestIP), daemon=True)
                threads.append(arpThread)
                arpThread.start()

            except Exception as e:
                continue

        # wait for all threads to terminate
        for index, thread in enumerate(threads):
            thread.join()

        #if not responses found
        if lastResult == "":
            print(fg.li_red + 'No ARP responses' + fg.rs)

        #press enter key to continue
        printCont()





