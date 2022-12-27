try:
    #Import general
    import socket, sys, string
    #Import local
    from netlib import *        #common tools
    from dhcpAttack import *    #dhcp attack library
    from arpScan import *       #arp scan library
    from cfm import *
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

def alterPcap(selectedInterface):

    os.system('cls' if os.name == 'nt' else 'clear')
     
    while(1):     
        printTitle("Alter pcap Files")
        print(fg.li_yellow + "Press e to exist\n" + fg.rs)
        addVLAN = False
        removeVLAN = False
        alterSMAC = False
        alterDMAC = False
        alterSIP = False
        alterDIP =  False
        rsm = False
        rdm = False
        rsi = False
        rdi= False

        pkts = getPcap()
        if pkts == "e":
            break

        os.system('cls' if os.name == 'nt' else 'clear')
        printTitle("Alter pcap Files")
        print(fg.li_yellow +  "Press e to exit\n" + fg.rs)

        alterChoise = input("Do you want to alter source MAC? [y]")
        if alterChoise == "e":
                break
        elif (alterChoise == "" or alterChoise == "y"):
            alterSMAC = True
            sourceMAC, rsm = getSourceMAC(selectedInterface)
            if sourceMAC == "e":
                break

        alterChoise = input("Do you want to alter destination MAC? [y]")
        if alterChoise == "e":
                break
        elif (alterChoise == "" or alterChoise == "y"):
            alterDMAC = True
            destMAC, rdm = getDestMAC(selectedInterface)
            if destMAC == "e":
                break

        alterChoise = input("Do you want to alter source IP? [y]")
        if alterChoise == "e":
                break
        elif(alterChoise == "" or alterChoise == "y"):
            alterSIP = True
            sourceIP, rsi = getSourceIP(selectedInterface)
            if sourceIP == "e":
                break

        alterChoise = input("Do you want to alter destination IP? [y]")
        if alterChoise == "e":
                break
        elif(alterChoise == "" or alterChoise == "y"):
            alterDIP = True
            destIP, rdi = getDestIP(selectedInterface)
            if destIP == "e":
                break

        removeVLAN = input("Do you want to remove Dot1Q header? [y]>")
        if removeVLAN == "e":
            break
        elif (removeVLAN == "" or removeVLAN == "y"):
            removeVLAN = True
        else:
            addVLAN = input("Do you want ot add Dot1Q header? [y]>")
            if addVLAN == "e":
                break
            elif (addVLAN == "" or addVLAN =="y"):
                addVLAN = True
                vlanID = getVLAN()
                if vlanID == "e":
                    break
                vlanPriority = getVLANpriority()
                if vlanPriority == "e":
                    break
                     
        for pkt in pkts:
            if (pkt.haslayer(Dot1Q) and removeVLAN):
                pkt[Ether].type = pkt[Dot1Q].type
                pkt.payload = pkt.payload.payload
            if pkt.haslayer(Ether):
                if rsm:
                    pkt[Ether].src = str(RandMAC())
                if alterSMAC:
                    pkt[Ether].src = sourceMAC
                if rdm:
                    pkt[Ether].dst = str(RandMAC())
                if alterDMAC:
                    pkt[Ether].dst = destMAC
                if addVLAN:
                    pkt = addVLANtoPacket(pkt,vlanID,vlanPriority)
            if pkt.haslayer(IP):
                if rsi:
                    pkt[IP].src = str(RandIP())
                if alterSIP:
                    pkt[IP].src = sourceIP
                if rdi:
                    pkt[IP].dst = str(RandIP())
                if alterDIP:
                    pkt[IP].dst = destIP

        #write or send
        os.system('cls' if os.name == 'nt' else 'clear')
        printTitle("Alter pcap Files")
        print("")
        choise = input("Do you want to write packet? [y]>")
        if choise == "e":
            break
        elif (choise == "y" or choise == ""):
            outputFile = input("Enter output file name [output.pcap]>")
            if outputFile == "":
                outputFile = "output.pcap"
            wrpcap(outputFile, pkts, append=True)
            os.system('cls' if os.name == 'nt' else 'clear')
        os.system('cls' if os.name == 'nt' else 'clear')
        printTitle("Alter pcap Files")
        print("")

        choise = input("Do you want to send packets? [y]>")
        if choise == "e":
            break
        elif (choise == "y" or choise == ""):
            pktNo = 1
            for pkt in pkts:                     
                try:
                    sendp(pkt,iface=selectedInterface['name'], verbose=False)
                    pktNo = pktNo + 1
                except Exception as e:
                    print(e)
                    print("Packet not sent")
            print(fg.li_green + str(pktNo-1) + " packet(s) sent" + fg.rs)
            print("")
        print("")

def sendPcap(selectedInterface):   

    os.system('cls' if os.name == 'nt' else 'clear')
  
    while(1):                
        printTitle("Send pcap Files")
        print(fg.li_yellow + "Press e to exist\n" + fg.rs)

        pkts = getPcap()
        if pkts == "e":
            os.system('cls' if os.name == 'nt' else 'clear')
            break
        os.system('cls' if os.name == 'nt' else 'clear')
        printTitle("Send pcap Files")
        print(fg.li_yellow +  "Press e to exit\n" + fg.rs)
        sendInterval =  getInterval()
        if sendInterval == "e":
            os.system('cls' if os.name == 'nt' else 'clear')
            break

        os.system('cls' if os.name == 'nt' else 'clear')
        printTitle("Send pcap Files")

        #start keyboard detection to check if user pressed q
        stopThread = threading.Thread(target=stopSend, args=())
        stopThread.start()
                   
        sendPacketsInterval(pkts,selectedInterface, sendInterval)
