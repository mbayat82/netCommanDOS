try:
    #Import general
    import socket, sys, string
    #Import 3rd party
    import netaddr, netifaces
    import scapy.contrib.igmp as sigmp
    from scapy.all import *
    from scapy.arch.windows import get_windows_if_list
    from prettytable import PrettyTable
    from sty import fg, bg, ef, rs
    import keyboard
    from termcolor import cprint 
    from pyfiglet import figlet_format

except Exception as e:
    print (e)
    sys.exit()

#global variables
stopFlag = False

#user dialog to get pcap files and returns packets
def getPcap():
    while(1):      
        pcapFile = input('Enter pcap file path:[sample.pcap]>')
        if pcapFile == "":
            pcapFile = 'sample.pcap'
        if pcapFile == "e":
            os.system('cls' if os.name == 'nt' else 'clear')
            return "e"
        try:
            pkts = rdpcap(pcapFile)
            return pkts
        except Exception as e:
            print(fg.li_red + "Could not open pcap file\n" + fg.rs)

#gets all windows interfaces and prints them out to user to select and interface. returns selected interface.
def getWinInterfaceDialog():

	    #Get interfaces names, mac address, and ipv4 addresses. Windows spcecific
        allInterfaces = get_windows_if_list()
        numberOfInterfaces = len(allInterfaces)

        #If no network interfaces, exit program
        if numberOfInterfaces == 0:
            print("No network interfaces found")
            return -1

        #pretty table is a library to print data in a table
        netIfacesTable = PrettyTable()
        netIfacesTable.field_names = ['Index','Network Name', 'MAC Address', 'IP Address']
        netIfacesTable.align['Network Name'] = "l"
        netIfacesTable.align['MAC Address'] = "l"
        netIfacesTable.align['IP Address'] = "l"

        #List all network interfaces
        for interfaceIndex,interfaceInfo in enumerate(allInterfaces):
            try:
                netIfacesTable.add_row([interfaceIndex,interfaceInfo['name'],interfaceInfo['mac'],interfaceInfo['ips'][1]])
            except:
                pass
        print(netIfacesTable.get_string(title="Network Interfaces"))

        print(fg.li_yellow + "Press e to exist\n" + fg.rs)

        #Select an interface loop
        while (1):
            selectedInterfaceIndex = input("Enter interface index [0]>")
            #if index is not entered, set index to 0
            if selectedInterfaceIndex == "":
                selectedInterfaceIndex = "0"
            if selectedInterfaceIndex == "e":
                os.system('cls' if os.name == 'nt' else 'clear')
                return "e"
           
            #chekc if entered index is a digit
            if selectedInterfaceIndex.isdigit():
                #check if entered index is within the range
                if int(selectedInterfaceIndex) < numberOfInterfaces:
                    #check if interface has a mac address
                    if allInterfaces[int(selectedInterfaceIndex)]['mac'] == "":
                        print(fg.li_red + 'Interafce has no MAC address. Please select another inteface.' + fg.rs)
                        continue
                    return allInterfaces[int(selectedInterfaceIndex)]
                else:
                    print(fg.li_red + "Not a valid interface index\n" + fg.rs)
            else:
                print(fg.li_red + "Not a valid interface index\n" + fg.rs)

#gets all linux interfaces and prints them out to user to select and interface. returns selected interface.
#puts the interfacs in the same format as the getWinInterface command
def getUnixInterfaceDialog():
    #Get interfaces names, mac address, and ipv4 addresses. Put them in the same format is get_windows_if_list()
    allInterfaces = []
    ifaces = netifaces.interfaces()
    for iface in ifaces:
        addr = netifaces.ifaddresses(iface)
        IpAddress = addr[netifaces.AF_INET][0]['addr']
        macAddress = addr[netifaces.AF_LINK][0]['addr']
        allInterfaces.append({'name': iface, 'mac': macAddress, 'ips': ['none', IpAddress]})
    
    numberOfInterfaces = len(allInterfaces)
    #If not network interfaces, exit program
    if numberOfInterfaces == 0:
        print("No network interfaces found")
        return -1

    #pretty table is a library to print data in a table
    netIfacesTable = PrettyTable()
    netIfacesTable.field_names = ['Index','Network Name', 'MAC Address', 'IP Address']
    netIfacesTable.align['Network Name'] = "l"
    netIfacesTable.align['MAC Address'] = "l"
    netIfacesTable.align['IP Address'] = "l"

    #List all network interfaces
    for interfaceIndex,interfaceInfo in enumerate(allInterfaces):
        netIfacesTable.add_row([interfaceIndex,interfaceInfo['name'],interfaceInfo['mac'],interfaceInfo['ips'][1]])
    print(netIfacesTable.get_string(title="Network Interfaces"))

    print(fg.li_yellow + "Press e to exist\n" + fg.rs)

    #Select an interface loop
    while (1):
        selectedInterfaceIndex = input("Enter interface index [0]>")
        #if index is not entered, set index to 0
        if selectedInterfaceIndex == "":
            selectedInterfaceIndex = "0"
        if selectedInterfaceIndex == "e":
            os.system('cls' if os.name == 'nt' else 'clear')
            return "e"
           
        #chekc if entered index is a digit
        if selectedInterfaceIndex.isdigit():
            #check if entered index is within the range
            if int(selectedInterfaceIndex) < numberOfInterfaces:
                #check if interface has a mac address
                if allInterfaces[int(selectedInterfaceIndex)]['mac'] == "":
                    print(fg.li_red + 'Interafce has no MAC address. Please select another inteface.' + fg.rs)
                    continue
                return allInterfaces[int(selectedInterfaceIndex)]
            else:
                print(fg.li_red + "Not a valid interface index\n" + fg.rs)
        else:
            print(fg.li_red + "Not a valid interface index\n" + fg.rs)

#gets network and subnet mask from user in 192.168.0.0/24 format. If interface subnet is not passed, default is 192.168.0.0/24
def getNetworkSubnetMask(interfaceSubnet="192.168.0.0"):

    while(1):
        networkSubnetMask = input("Enter subnet and mask " + interfaceSubnet + "/24> ")
            
        if networkSubnetMask == "":
            networkSubnetMask = interfaceSubnet + "/24"
        if networkSubnetMask == "e":
            return "e"

        networkSubnetMaskArray = networkSubnetMask.split("/")
        if len(networkSubnetMaskArray) != 2:
            print(fg.li_red + "Please enter a valid subnet and mask" + fg.rs)
            continue
        if validIp(networkSubnetMaskArray[0]):
            if validMask(networkSubnetMaskArray[1]):
                return networkSubnetMask
            else:
                print(fg.li_red + "Invalid mask. A subnet mask is a number between 1 and 32" + fg.rs)
                continue
        else:
            print(fg.li_red + "Invalid subnet" + fg.rs)

#detects keypress q, and set the stopSend flag to true
def stopSend():
    global stopFlag
    stopFlag = False
    print(fg.li_yellow + "Press q to stop ..." + fg.rs)
    while (not stopFlag):
        try:
            if keyboard.is_pressed('q'):
                stopFlag = True
                os.system('cls' if os.name == 'nt' else 'clear')
                keyboard.write('\b')
                break
        except:
            break

#validates a MAC address. returns tue or false
def validMac(macAddress): # Check if MAC address is valid
    if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", macAddress.lower()):
            return True
    else:
            return False

#validates and IP address. returns true or false.
def validIp(ipAddress): # Check if IP is valid
    try:
        socket.inet_pton(socket.AF_INET,ipAddress)
        return True
    except socket.error:
        return False

#Function to check if subnet mask is valid
def validMask(mask):
    if mask.isdigit():
         mask = int(mask)
         if 1 <= mask <= 32:
            return True
    return False

#validates a UDP/TCP port. returns true or false
def validUdpTcpPort(port):
    if port.isdigit():
        if 0 <= int(port) <= 65535:
            return True
    return False

#send packets, accepts a packet, interface, interval, random source/dest mac, random source/dest ip flags, random source/dest ports
#random flags are optional
def sendPacketInterval(pkt,selectedInterface,sendInterval,rsm=False,rdm=False,rsi=False,rdi=False,rsp=False,rdp=False):
    global stopFlag
    i = 0
    while(1):
        try:
            #send packet using scapy
            sendp(pkt,iface=selectedInterface['name'], verbose=False)
            if i == 0:
                print("")
            #print number of packets sent
            print (str(i) + " packets sent", end="\r")
            i = i + 1

            #sleep based on interval entered
            time.sleep(sendInterval)

            #randominze sourcde mac address and destination mac address if r is entered
            if pkt.haslayer(Ether):
                if rsm:
                    pkt[Ether].src = RandMAC()
                if rdm:
                    pkt[Ether].dst = RandMAC()
            if pkt.haslayer(IP):
                if rsi:
                    pkt[IP].src = RandIP()
                if rdi:
                    pkt[IP].dst = RandIP()
            if pkt.haslayer(UDP):
                if rsp:
                    pkt[UDP].sport = random.randrange(49152,65535)
                if rdp:
                    pkt[UDP].dport = random.randrange(49152,65535)
            if pkt.haslayer(TCP):
                if rsp:
                    pkt[TCP].sport = str(random.randrange(49152,65535))  
                if rdp:
                    pkt[TCP].destport = str(random.randrange(49152,65535)) 

            #if q is pressed stop sending
            if stopFlag == True:
                time.sleep(0.5)
                break
        except Exception as e:
            print(e)

#get packets and send them all in an interval
def sendPacketsInterval(pkts,selectedInterface, sendInterval):
    global stopFlag
    i = 0
    numPackets = str(len(pkts))
    try:
        for pkt in pkts:
            sendp(pkt, iface=selectedInterface['name'], verbose=0)

            if i == 0:
                print("")

            #print number of packets sent
            i = i + 1
            print (fg.li_green + str(i) + "/" + numPackets +" packets sent" + fg.rs, end="\r")
            
            time.sleep(sendInterval)

            #if q is pressed stop sending
            if stopFlag == True:
                time.sleep(0.5)
                return
        print("\n")
    except Exception as e:
        print(e)

    stopFlag = True

#get source MAC from user. accepts interface and returns MAC address and random flag
def getSourceMAC(selectedInterface):
 
    rsm = False
    while(1):    
        sourceMAC = input("Enter source MAC Address:["+selectedInterface['mac']+"]>")
        if sourceMAC == "":
            sourceMAC = selectedInterface['mac']
        if sourceMAC == "r":
            sourceMAC = str(RandMAC())
            rsm = True
        if sourceMAC == "e":
            os.system('cls' if os.name == 'nt' else 'clear')
            return "e", False           
        if (validMac(sourceMAC)):
            return sourceMAC, rsm
        else:
            print(fg.li_red + "Not a valid MAC address format\n" + fg.rs)

#get destination MAC from user. accepts interface and returns MAC address and random flag
def getDestMAC(selectedInterface):
    while(1):
     
        rdm = False
        destMAC = input("Enter destination MAC Address:[01:00:5e:01:01:01]>")
        if destMAC == "":
            destMAC = "01:00:5e:01:01:01"
        if destMAC == "r":
            destMAC = str(RandMAC())
            rdm = True
        if destMAC == "e":
            os.system('cls' if os.name == 'nt' else 'clear')
            return "e", False   
        if (validMac(destMAC)):
            return destMAC, rdm
        else:
            print(fg.li_red + "Not a valid MAC address format\n" + fg.rs)

def getIGMPtype():
    #igmp type #17 query, 18 report 1, 22 report 2, 23 leave
    while(1):
        print("[0] IGMP Query\t\t[1] IGMPv1 Report\n[2] IGMP2 Report\t[3] IGMP Leave")
        igmpType= input("Enter multicast message type[0]>")
        if (igmpType == "" or igmpType == "0"):
            return 17
            break
        if igmpType == "1":
            return 18
            break
        if igmpType == "2":
            return 22
            break
        if igmpType == "3":
            return 23
            break
        if igmpType == "e":
            os.system('cls' if os.name == 'nt' else 'clear')
            return
        else:
                print(fg.li_red + "Enter a valid IGMP type" + fg.rs)

#get source IP from user. accepts interface and returns IP address and random flag
def getSourceIP(selectedInterface):
    
    rsi = False
    while(1):
        sourceIP = input("Enter source IP Address:["+selectedInterface['ips'][1]+"]>")
        if sourceIP == "":
            sourceIP = selectedInterface['ips'][1]
        if sourceIP == "r":
            sourceIP = str(RandIP())
            rsi = True
        if sourceIP == "e":
            os.system('cls' if os.name == 'nt' else 'clear')
            return "e", False   
        if (validIp(sourceIP)):
            return sourceIP, rsi
        else:
            print(fg.li_red + "Not a valid IP address\n" + fg.rs)

#get destination IP from user. accepts interface and returns IP address and random flag
def getDestIP(selectedInterface):
     
    rdi = False
    while(1):
        destIP = input("Enter destination IP Address:[239.1.1.1]>")
        if destIP == "":
            destIP = "239.1.1.1"
        if destIP == "r":
            destIP = str(RandIP())
            rdi = True
        if destIP == "e":
            os.system('cls' if os.name == 'nt' else 'clear')
            return "e", False
        if (validIp(destIP)):
            return destIP, rdi
        else:
            print(fg.li_red + "Not a valid IP address\n" + fg.rs)

def getMulticastIP(selectedInterface):      

    while(1):
        igmpMulticastIP = input("Enter multicast IP Address:[239.1.1.1]>")
        if igmpMulticastIP == "":
            igmpMulticastIP = "239.1.1.1"
        if igmpMulticastIP == "e":
            os.system('cls' if os.name == 'nt' else 'clear')
            return "e"
        if (validIp(igmpMulticastIP)):
            return igmpMulticastIP
        else:
            print(fg.li_red + "Not a valid IP address\n" + fg.rs)

#get source port from user. returns source port and random source port flag
def getSourcePort():

    rsp = False

    while(1):
        sourcePort = input("Enter UDP source port:[1024]>")
        if sourcePort == "":
            sourcePort = "1024"
        if sourcePort == "r":
            sourcePort = str(random.randrange(49152,65535))
            rsp = True
        if sourcePort == "e":
            os.system('cls' if os.name == 'nt' else 'clear')
            return "e", False
        if (validUdpTcpPort(sourcePort)):
            return sourcePort, rsp
        else:
            print(fg.li_red + "Not a valid port\n" + fg.rs) 

#get destination port from user. returns source port and random destination port flag
def getDestPort():
    
    rdp = False

    while(1):
        destPort = input("Enter UDP destination port:[1024]>")
        if destPort == "":
            destPort = "1024"
        if destPort == "r":
            destPort = str(random.randrange(49152,65535))   
            rdp = True
        if destPort == "e":
            os.system('cls' if os.name == 'nt' else 'clear')
            return "e", False  
        if (validUdpTcpPort(destPort)):
            return destPort, rdp
        else:
            print(fg.li_red + "Not a valid port\n" + fg.rs) 

#get send interval. returns interval
def getInterval(interval="1"):
     
    while(1):
            sendInterval = input("Enter send interval in seconds:[" + interval +"]>")
            if sendInterval == "":
                sendInterval = interval
            if sendInterval == "r":
                sendInterval = str(random.randrange(1,5))
            if sendInterval == "e":
                os.system('cls' if os.name == 'nt' else 'clear')
                return "e"
            try:
                sendInterval = float(sendInterval)
                return sendInterval
            except Excepction as e:
                #print(e)
                print(fg.li_red + "Not a valid interval\n" + fg.rs)

#get VLAN ID. returned VLAN ID.
def getVLAN():
     
    while(1):
            vlanID = input("Enter VLAN ID:[2]>")
            if vlanID == "":
                vlanID = "2"
            if vlanID == "e":
                os.system('cls' if os.name == 'nt' else 'clear')
                return "e"
            if vlanID.isdigit():
                if 2 <= int(vlanID) <= 4096:
                    return vlanID
            #print(e)
            print(fg.li_red + "Not a valid VLAN ID\n" + fg.rs)

#get VLAN priority. returned VLAN priority.
def getVLANpriority():
     
    while(1):
            vlanPriority = input("Enter VLAN Priority:[0]>")
            if vlanPriority == "":
                vlanPriority = "0"
            if vlanPriority == "e":
                os.system('cls' if os.name == 'nt' else 'clear')
                return "e"
            if vlanPriority.isdigit():
                if 0 <= int(vlanPriority) <= 7:
                    return vlanPriority
            #print(e)
            print(fg.li_red + "Not a valid VLAN priority value\n" + fg.rs)

#adding VLAN tag to a packet. accepts packet VLAN ID, and priority. Return packet
def addVLANtoPacket(pkt,vlanID, vlanPriority):
    if pkt.haslayer(Ether):
        dot1Q = Dot1Q(vlan=int(vlanID),prio=int(vlanPriority))
        dot1Q.type = pkt[Ether].type
        dot1Q.payload = pkt[Ether].payload
        pkt[Ether].payload = dot1Q
        pkt[Ether].type = 33024
        return pkt
    else:
        return -1

#print script credits. accepts script name, version, and author
def printCredit(scriptName, scriptVersion, scriptAuthor):
    cprint(fg.li_blue + figlet_format(scriptName, font='mini') + " Created by "+ scriptAuthor + "\n" + fg.rs)

#tasks an multicast IP address and returns corrosponding MAC address
def multicastIP2MAC(mcastIP):
    mcastMAC =  '01:00:5e:'
    octets = mcastIP.split('.')
    second_oct = int(octets[1]) & 127
    third_oct = int(octets[2])
    fourth_oct = int(octets[3])
    mcastMAC = mcastMAC + format(second_oct,'02x') + ':' + format(third_oct, '02x') + ':' + format(fourth_oct, '02x')
    return mcastMAC

#accept packet, and print its parameters (layer 2, layer 3, layer 4, ..etc)
def printPacket(pkt,rsm=False,rdm=False,rsi=False,rdi=False,rsp=False,rdp=False):
    if pkt.haslayer(Ether):
        print("" + " " + bg.white + fg.black + " IEEE 802.3 Ethernet                          " + fg.rs + bg.rs)
        print("  " + ">" + " Source MAC Address: " + (fg.li_yellow if rsm else "") + pkt[Ether].src + "\t" + fg.rs)
        print("  " + ">" + " Destination MAC Address: " + (fg.li_yellow if rdm else "") + pkt[Ether].dst + "\t" + fg.rs)
    if pkt.haslayer(IP):
        print("" + " " + bg.white + fg.black + " Internet Protocol v4                         " + fg.rs + bg.rs)
        print("  " + ">" + " Source IP Address: " + (fg.li_yellow if rsi else "") + pkt[IP].src + "\t" + fg.rs)
        print("  " + ">" + " Destination IP Address: " + (fg.li_yellow if rdi else "") +pkt[IP].dst + "\t" + fg.rs)
    if pkt.haslayer(ARP):
        print("" + " " + bg.white + fg.black + " Address Resolution Protocol                  " + fg.rs + bg.rs)
    if pkt.haslayer(UDP):
        print("" + " " + bg.white + fg.black + " User Datagram Protocol                       " + fg.rs + bg.rs)
        print("  " + ">" + " Source UDP Port:" + (fg.li_yellow if rsp else "") + str(pkt[UDP].sport) + "\t\t" + fg.rs)
        print("  " + ">" + " Destination UDP Port: " + (fg.li_yellow if rdp else "") + str(pkt[UDP].dport) + "\t\t" + fg.rs)
    if pkt.haslayer(BOOTP):
        print("" + " " + bg.white + fg.black + " Dynamic Host Configuration Protocol          " + fg.rs + bg.rs)
        if pkt[BOOTP].op == 1:
            print("  " + ">" + " Operation: Discover")
    if pkt.haslayer(sigmp.IGMP):
        igmpType = ""
        if pkt[sigmp.IGMP].type == 17:
            igmpType = " (Group Membership Query)"
        if pkt[sigmp.IGMP].type == 18:
            igmpType = " (Membership Report v1)"
        if pkt[sigmp.IGMP].type == 22:
            igmpType = " (Membership Report v2)"
        if pkt[sigmp.IGMP].type == 23:
            igmpType = " (Leave Group)"
        print("" + " " + bg.white + fg.black + " Internet Group Management Protocol           " + fg.rs + bg.rs)
        print("  " + ">" + " Multicast IP: " + str(pkt[sigmp.IGMP].gaddr))
        print("  " + ">" + " Type: " + str(pkt[sigmp.IGMP].type) + igmpType)
    print("")

#print task title in a nice way
def printTitle(title):
    bar = "+"
    for i in range(len(title)+4):
        bar = bar + "-"
    bar = bar + "+"
    title = "|  " + title + "  |"
    print(bar)
    print(title)
    print(bar)

def printCont():
    var = input("\nPress ENTER to continue ...")