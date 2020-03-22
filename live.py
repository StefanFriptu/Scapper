from scapy.all import *
from Tkinter import *
import threading
import time

def GetMacFromIp(targetip):
    arppacket= Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=targetip)
    targetmac= srp(arppacket, timeout=2 , verbose= False)[0][0][1].hwsrc
    return targetmac

class Application(Frame):
    def __init__(self, master = None):
        Frame.__init__(self, master)

        self.master = master
        self.master.title("Scapper")
        self.grid()

        # Create interface
        self.arp = Button(self, text = "ARP Poisoning", command = self.startArp)
        self.arp.grid(row = 20, column = 1)

        #self.dns = Button(self, text = "DNS Spoofing") # command = self.start dns
        #self.dns.grid(row = 8, column = 4)

        self.grid_columnconfigure(2, minsize = 120)

        self.uExitButton = Button(self, text = "Exit", command = self.exit)
        self.uExitButton.grid(row = 10, column = 2)

        Label(self, text = "IP Victim: ").grid(row = 2)
        Label(self, text = "IP Server: ").grid(row = 6)

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
        
        # Configure self
        self.interceptedPackets = []
        self.networkInterface = "enp0s3"
        self.selfMac = get_if_hwaddr(self.networkInterface)
        self.selfIp = "192.168.56.103"
        
    def startArp(self):
        self.victimIp  = self.uArpEntryIpVictim.get()
        self.victimMac = GetMacFromIp(self.victimIp)
        
    
    def exit(self):
        root.destroy()

        
root = Tk()
app = Application(master = root)
app.mainloop()
