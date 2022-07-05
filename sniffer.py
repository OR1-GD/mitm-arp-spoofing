from threading import Thread
from scapy.all import *
from datetime import datetime, timedelta
from formater import saveJson2file
from osint import look4details

class packet_sniffer(Thread):
    """_summary_
    passive sniffer collecting DATA 
    Args:
        Thread (threading.Thread): 
    """
    def __init__(self, timeout=None, filter=None, iface_name=conf.iface.name, pcap_file = None, test_mode=False, group: None = ..., target: Callable[..., Any] | None = ..., name: str | None = ..., args: Iterable[Any] = ..., kwargs: Mapping[str, Any] | None = ..., *, daemon: bool | None = ...) -> None:
        super(packet_sniffer,self).__init__(group, target, name, args, kwargs, daemon=daemon)
        
        """_summary_

        Args:
            timeout (_type_, optional): _description_. Defaults to None.
            filter (_type_, optional): _description_. Defaults to None.
            iface (_type_, optional): _description_. Defaults to conf.iface.
            pcap_file (_type_, optional): _description_. Defaults to None.
            test_mode (bool, optional): _description_. Defaults to False.
        """
        self.test_mode = test_mode
        self.timeout = timeout
        self.iface = iface_name
        self.filter = filter
        self.pcap_file = pcap_file
        self.data = {
            "creation_time" : str(datetime.now()),
            "start_time" : "",
            "end_time"   : "",
            "if_name": iface_name,
            "devices_spoted": [],
            "captured_packets":0
        }
        if test_mode:
            print("\t[*] test mode activated")
        print("\t[*] initializing sniffer")
        print("\t[+] initializing queue")
        if self.timeout != None:
            print(f"\t[+] set timeout to {self.timeout} sec")
        print(f"\t[+] set sniffer to listen on interface {iface_name}")
        if pcap_file != None:
            print(f"\t[+] set output pcap file path at {pcap_file}")
            print(f"\t[+] filter is setted")
        print("\t[Info] Finished initializing sniffer") 

    def PacketHandler(self, pkt):
        """_summary_

        Args:
            pkt (_type_): _description_
        """
        if self.test_mode :
            pkt.summary()
            
        # find if there are any new unique mac
        if pkt.src not in self.data["devices_spoted"]:
            if not pkt.src == "ff:ff:ff:ff:ff:ff" :
                self.data["devices_spoted"].append(pkt.src)
        if pkt.dst not in self.data["devices_spoted"]:
            if not pkt.dst == "ff:ff:ff:ff:ff:ff":
                self.data["devices_spoted"].append(pkt.dst)

    def run(self):
        start_time = datetime.now()
        print(f"\t[*] {str(start_time)} - start sniffing")
        packets = sniff(prn=self.PacketHandler, timeout=self.timeout)
        end_time = datetime.now()
        self.data["start_time"] = str(start_time)
        self.data["end_time"] = str(end_time)
        print(f"\t[*] sniffer finished")
        if self.pcap_file != None:
            print("\t[*] saving pcap")
            wrpcap(self.pcap_file, packets)
            print(f"\t[Info] pcap file created at {self.pcap_file}")
        if self.test_mode:
            print("\t[*] creating summary file")
            self.data["devices_spoted"] = look4details(self.data["devices_spoted"])
            saveJson2file(self.data, "summary.yaml", "YAML")
            print(f"\t[Info] succsesfuly yaml created at summary.yaml")
        # Next step: print the amount of packets sniffed
        # print(f"\t[Info] {self.queue} packets sniffed")
        # print(self.queue)

def test():
    print("[Info] Create Test sniffer")
    creation_time = datetime.now()
    sniffer = packet_sniffer(timeout=10, pcap_file="ori.pcap", test_mode=True)
    sniffer.daemon = True
    finish_time = datetime.now()
    print(f"[Info] sniffer created in: {finish_time - creation_time}")
    print("[Info] test sniffer is ready")
    sniffer.start()

    while sniffer.is_alive(): continue


if __name__ == '__main__':
    test()
