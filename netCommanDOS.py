# == IMPORT ==
try:
    #Import general
    import socket, sys, string
    #Import local
    from netlib import *        #common tools
    from dhcpAttack import *    #dhcp attack library
    from arpScan import *       #arp scan library
    from cfm import *
    from pcaplib import *
    #Import 3rd party
    import netaddr, netifaces
    from scapy.all import *
    import scapy.contrib.igmp as sigmp
    from prettytable import PrettyTable
    from sty import fg, bg, ef, rs
    import keyboard
    from termcolor import cprint 
    from pyfiglet import figlet_format
except Exception as e:
    print (e)
    sys.exit()

def getTaskDialog():

    #txtColorGray = fg("grey_50")
    #txtColorOrange = fg("orange_red_1")
    #txtReset = attr('reset')

    taskTable = PrettyTable()
    taskTable.field_names = ['Index','Task Name']
    taskTable.align['Index'] = "l"
    taskTable.align['Task Name'] = "l"
    taskTable.add_row(['1','Send UDP Packets'])
    taskTable.add_row(['2','Send IGMP Packets'])
    taskTable.add_row(['3','ARP Scan'])
    taskTable.add_row(['4','Fast ARP Scan'])
    taskTable.add_row(['5','DHCP Attack'])
    taskTable.add_row(['6','Alter pcap files'])
    taskTable.add_row(['7','Send pcap files'])
    taskTable.add_row(['8','Send CFM'])

    print(taskTable)
    print (fg.li_yellow + "Press e to exit\n" + fg.rs)

    while(1):
        
        task = input("Enter task index [1]>")
        if (task == "" or task == "1"):
            return 'sendUDP'
        if task == "2":
            return 'sendIGMP'
        if task == "3":
            return 'arpScan'
        if task == "4":
            return 'fastARPscan'
        if task == "5":
            return 'dhcpAttack'
        if task == "6":
            return 'alterPcap'
        if task == "7":
            return 'sendPcap'
        if task == "8":
            return 'sendCFM'
        if task == "e":
            os.system('cls' if os.name == 'nt' else 'clear')
            sys.exit()

        print(fg.li_red + "Enter a valid task index\n" + fg.rs)

def sendUDP(selectedInterface):

    os.system('cls' if os.name == 'nt' else 'clear')

    while(1):
        printTitle("Send UDP Packets")
        print(fg.li_yellow + "Press e to exit\n" + fg.rs)

        #get parameters
        sourceMAC, rsm = getSourceMAC(selectedInterface)
        if sourceMAC == 'e':
            break
        destMAC, rdm = getDestMAC(selectedInterface)
        if destMAC == 'e':
            break
        sourceIP, rsi = getSourceIP(selectedInterface)
        if sourceIP == 'e':
            break
        destIP, rdi = getDestIP(selectedInterface)
        if destIP == 'e':
            break
        sourcePort, rsp = getSourcePort()
        if sourcePort == 'e':
            break
        destPort, rdp = getDestPort()
        if destPort == 'e':
            break
        sendInterval = getInterval()
        if sendInterval == 'e':
            break
        udpData = udpData = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(32)])

        #craft UDP Packet
        pkt = Ether(src=sourceMAC, type=2048, dst=destMAC)/ \
                    IP(flags=0, proto=17, frag=0, tos=0, src=sourceIP,
                    version=4, ttl=64, dst=destIP, options=[],
                    id=32508, ihl=5)/ \
                    UDP(sport=int(sourcePort),
                    dport=int(destPort))/Raw(load=udpData)

        os.system('cls' if os.name == 'nt' else 'clear')
        printTitle("Send UDP Packets")
        print("")

        printPacket(pkt,rsm,rdm,rsi,rdi,rsp,rdp)

        #start keyboard detection to check if user pressed q
        stopThread = threading.Thread(target=stopSend, args=())
        stopThread.start()

        #send packets
        sendPacketInterval(pkt,selectedInterface,sendInterval,rsm,rdm,rsi,rdi,rsp,rdp)

def sendIGMP(selectedInterface):
    os.system('cls' if os.name == 'nt' else 'clear')
    
    while(1):
        printTitle("Send IGMP Packets")
        print(fg.li_yellow + "Press e to exit\n" + fg.rs)
        #get parameters
        igmpMulticastIP= getMulticastIP(selectedInterface)
        if igmpMulticastIP == 'e':
            break
        sourceMAC, rsm = getSourceMAC(selectedInterface)
        if sourceMAC == 'e':
            break
        destMAC, rdm = getDestMAC(selectedInterface)
        if destMAC == 'e':
            break
        sourceIP, rsi = getSourceIP(selectedInterface)
        if sourceIP == 'e':
            break
        destIP, rdi = getDestIP(selectedInterface)
        if destIP == 'e':
            break

        igmpType = getIGMPtype()

        sendInterval = getInterval()
        if sendInterval == 'e':
            break

        

        pkt = Ether(dst=destMAC, src=sourceMAC, type=2048)/ \
                        IP(dst=destIP, version=4, src=sourceIP, \
                        tos=0, options=IPOption(b'\x94\x04\x00\x00'), id=19057,\
                         proto=2, ihl=6, frag=0, ttl=1, flags=0)/ \
                        sigmp.IGMP(gaddr=igmpMulticastIP, type=igmpType)
        
        os.system('cls' if os.name == 'nt' else 'clear')
        printTitle("Send IGMP Packets")
        print("")

        printPacket(pkt,rsm,rdm,rsi,rdi)

        #start keyboard detection to check if user pressed q
        stopThread = threading.Thread(target=stopSend, args=())
        stopThread.start()

        #send packets
        sendPacketInterval(pkt,selectedInterface,sendInterval,rsm,rdm,rsi,rdi)

def fastARPscan(selectedInterface):

    while(1):
        os.system('cls' if os.name == 'nt' else 'clear')
        printTitle("Fast ARP Scan")
        print(fg.li_yellow + "Press e to exit\n" + fg.rs)

        networkSubnetMask = getNetworkSubnetMask(selectedInterface['ips'][1])
        if networkSubnetMask == "e":
            os.system('cls' if os.name == 'nt' else 'clear')
            break
        sendInterval =  getInterval("0")
        if sendInterval == "e":
            os.system('cls' if os.name == 'nt' else 'clear')
            break

        #clear screen
        os.system('cls' if os.name == 'nt' else 'clear')
        printTitle("Fast ARP Scan")
        print("")
        #print scanned network information
        network = netaddr.IPNetwork(networkSubnetMask)
        print("Network  : ",network.network)
        print("Mask     : ", network.netmask)
        print("Hosts    : ", network.size)
        print(fg.li_yellow + "Use wireshark to check resutls. You can filter by arp.opcode == 2" + fg.rs)
        print("")

        pkt = Ether(src=selectedInterface['mac'],
                dst="ff:ff:ff:ff:ff:ff",
                type=2054) / ARP(hwdst="ff:ff:ff:ff:ff:ff",
                                 ptype=2048, hwtype=1,
                                 psrc="0.0.0.0",
                                 hwlen=6,
                                 plen=4,
                                 pdst="255.255.255.255",
                                 hwsrc=selectedInterface['mac'],
                                 op=1)

        #iterate subnet range
        for i in tqdm(range (network.size), file=sys.stdout):
            
            try:
                #source ip is one ip before destination ip
                packetDestIP = network[i]
                packetSourceIP = network[i-1]

                pkt[ARP].psrc = packetSourceIP
                pkt[ARP].pdst = packetDestIP

                sendp(pkt, iface=selectedInterface['name'], verbose=0)
                time.sleep(sendInterval)

                #source ip is one ip after destination ip
                packetSourceIp = network[i+1]
                pkt[ARP].psrc = packetSourceIP

                sendp(pkt, iface=selectedInterface['name'], verbose=0)
                time.sleep(sendInterval)

            except Exception as e:
                continue
        
        #press enter to continue
        printCont()

# == MAIN ==
if __name__ == "__main__":

    os.system('cls' if os.name == 'nt' else 'clear')
    print("netComman"  +fg.li_red + "D" + fg.li_yellow + "O" + fg.li_magenta + "S" + fg.rs + " 1.2")
    print("Created by Mohamad El Bayat\n" + fg.rs)

    while(1):
        task = getTaskDialog()

        if (os.name == 'nt'):
            os.system('cls')
            selectedInterface = getWinInterfaceDialog()
            if selectedInterface == "e":
                continue
        else:
            os.system('clear')
            selectedInterface = getUnixInterfaceDialog()
            if selectedInterface == "e":
                continue

        if task == 'sendUDP':
            sendUDP(selectedInterface)
        elif task == 'sendIGMP':
            sendIGMP(selectedInterface)
        elif task == 'arpScan':
            arpScan(selectedInterface)
        elif task == 'dhcpAttack':
            dhcpAttack(selectedInterface)
        elif task == 'alterPcap':
            alterPcap(selectedInterface)
        elif task == 'fastARPscan':
            fastARPscan(selectedInterface)
        elif task == 'sendPcap':
            sendPcap(selectedInterface)
        elif task == 'sendCFM':
            sendCFM(selectedInterface)
