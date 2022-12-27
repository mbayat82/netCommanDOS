# == IMPORT ==
try:
    #Import general
    import socket, sys, string
    #Import local
    from netlib import *        #common tools
    from dhcpAttack import *    #dhcp attack library
    from arpScan import *       #arp scan library
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

sniffFlag = False

def sendCFM(selectedInterface):
    global sniffFlag
    os.system('cls' if os.name == 'nt' else 'clear')

    #CFM Main Loop
    while(1):
        printTitle("Send CFM Packets")
        print(fg.li_yellow + "Press e to exist\n" + fg.rs)

        #Source MAC
        sourceMAC, rsm = getSourceMAC(selectedInterface)
        if sourceMAC == "e":
            return

        #MD Level
        while(1):
                    mdLevel = input("Enter MD level [0]>")
                    if (mdLevel == ""):
                        mdLevel = "0"
                    if mdLevel == "e":
                        return
                    if mdLevel.isdigit():
                        if(0 <= int(mdLevel) <= 7):
                            break
                    print(fg.li_red +  "Enter a valid level\n" + fg.rs)

        while(1):
            CFMtype = input("[0]CCM or [1]LBM? [0]>")

            #CCM
            if (CFMtype == "" or CFMtype == "0"):

                #Interval
                while(1):
                    print("[3]100ms  [4]1s  [5]10s\n[6]1m     [7]10m")
                    ccmInterval = input("Enter CCM Interval [4]>")
                    if ccmInterval == "3":
                        sendInterval = 0.1
                    if ccmInterval == "6":
                        sendInterval = 60
                    if ccmInterval == "7":
                        sendInterval = 600
                    if (ccmInterval == "" or ccmInterval =="4"):
                        ccmInterval = "4"
                        sendInterval = 1
                    if ccmInterval == "e":
                        return
                    if ccmInterval.isdigit():
                        if(3 <= int(ccmInterval) <= 7):
                            break
                    print(fg.li_red +  "Enter a valid interval\n" + fg.rs)
                
                #MEP ID
                while(1):
                    mepID = input("Enter MEP ID [100]>")
                    if (mepID == ""):
                        mepID = "100"
                    if mepID == "e":
                        return
                    if mepID.isdigit():
                        if(1 < int(mepID) < 8191):
                            break
                    print(fg.li_red +  "Enter a valid MEP ID\n" + fg.rs)

                #MD Name
                while(1):
                    mdName = input("Enter MD name []>")
                    if mdName == "e":
                        return
                    break

                #MA Name
                while(1):
                    maName = input("Enter MA name [ma]>")
                    if (maName == ""):
                        maName = "ma"
                    if mdName == "e":
                        return
                    break
                
                destMAC = "01:80:c2:00:00:3" + mdLevel

                pkt = Ether(src=sourceMAC,dst=destMAC,type=35074)/ \
                      CCM(level=int(mdLevel),interval=int(ccmInterval),mep_id=int(mepID),
                          md_length=len(mdName),md_name=mdName,ma_length=len(maName),ma_name=maName)
                               
                os.system('cls' if os.name == 'nt' else 'clear')    
                printTitle("Send CFM Packets")
                print("")
                printCCMpacket(pkt)
                break

            #LBM
            elif (CFMtype == "1"):
                destMAC, rdm = getDestMAC(selectedInterface)
                if destMAC == "e":
                    return

                sendInterval = getInterval()

                pkt = Ether(src=sourceMAC,dst=destMAC,type=35074)/ \
                      LBM(level=int(mdLevel))

                os.system('cls' if os.name == 'nt' else 'clear')      
                printTitle("Send CFM Packets")
                print("")
                printLBMpacket(pkt)

                sniffFlag = True
                sniffLBRThread = threading.Thread(target=sniffLBR, args=(selectedInterface,), daemon=True)
                sniffLBRThread.start()

                break

            elif (CFMtype == "e"):
                return
            else:
                print(fg.li_red +  "Enter a valid message type\n" + fg.rs)       

        #start keyboard detection to check if user pressed q
        stopThread = threading.Thread(target=stopSend, args=())
        stopThread.start()

        sendPacketInterval(pkt,selectedInterface,sendInterval)

#scapy CCM class
class CCM(Packet):
    name = "CCM"
    fields_desc = [ BitField("level", 0, 3),        
                    BitField("version",0,5),        
                    ByteField("op",1),             
                    BitField("rdi",0,1),
                    #BitField("rdi",0,4),
                    BitField("interval",4,3),
                    ByteField("offset",70),
                    BitField("seq", 0, 32),
                    ShortField("mep_id",100),
                    ByteField("md_format", 4),
                    ByteField("md_length", 2),
                    StrField("md_name", "md"),     
                    ByteField("ma_format", 2),
                    ByteField("ma_length", 2),
                    StrField("ma_name", "ma"),
                    BitField("zero_padding", 0, 216),
                    BitField("txfcf", 0, 64),
                    BitField("rxfcb", 0, 64),
                    BitField("txfcb", 0, 64),
                    BitField("reserved", 0, 64),
                    ByteField("tvl", 0)
                  ]

#scapy LBM class
class LBM(Packet):
    name = "LBM"
    fields_desc = [ BitField("level", 0, 3),        
                    BitField("version",0,5),        
                    ByteField("op",3),             
                    ByteField("flags",0),
                    ByteField("offset",4),
                    BitField("trans_id",0,32),
                    ByteField("tlv",0)
                  ]

def printCCMpacket(pkt):
    print(" " + bg.white + fg.black + " IEEE 802.3 Ethernet                          " + fg.rs + bg.rs)
    print("  " + ">" + " Source MAC Address: " + pkt[Ether].src + "\t")
    print("  > Destination MAC Address: " +  pkt[Ether].dst + "\t")
    print(" " + bg.white + fg.black + " CFM EOAM 802.1ag/ITU Protocol CCM            " + fg.rs + bg.rs)
    print("  " + ">" + " MD Level: " + str(pkt[CCM].level) + "\t")
    print("  " + ">" + " MD Name: " + pkt[CCM].md_name.decode("utf-8") + "\t")
    print("  " + ">" + " MA Name: " + pkt[CCM].ma_name.decode("utf-8") + "\t")
    print("  " + ">" + " MEP ID: " + str(pkt[CCM].mep_id) + "\t")
    print("")

def printLBMpacket(pkt):
    print(" " + bg.white + fg.black + " IEEE 802.3 Ethernet                          " + fg.rs + bg.rs)
    print("  " + ">" + " Source MAC Address: " + pkt[Ether].src + "\t")
    print("  > Destination MAC Address: " +  pkt[Ether].dst + "\t")
    print(" " + bg.white + fg.black + " CFM EOAM 802.1ag/ITU Protocol LBM            " + fg.rs + bg.rs)
    print("  " + ">" + " MD Level: " + str(pkt[LBM].level) + "\t")
    print("")

def sniffLBR(selectedInterface):
    global sniffFlag
    while sniffFlag:
        sniffedPkts = sniff(filter="not ip and not arp", iface=selectedInterface['name'], prn=checkLBRSniffedPkts, count=1, timeout=1)

def checkLBRSniffedPkts(pkt):
    global sniffFlag
    if pkt.haslayer(Ether):   
        if pkt[Ether].type == 35074:
            op = str(pkt[Raw])[5:7]
            if op == '02':
                print(fg.li_green + "Loopback Reply from " + pkt[Ether].src + fg.rs)
                sniffFlag = False

