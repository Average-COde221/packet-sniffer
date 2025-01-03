import sys
from scapy.all import *

def find_packet(packet,log):
    if packet.haslayer(TCP):
        src_ip=packet[IP].src
        dst_ip=packet[IP].dst
        src_port=packet[TCP].sport
        dst_port=packet[TCP].dport
        log.write(f"TCP conenction found from {src_ip}:{src_port} --> {dst_ip}:{dst_port}")
    elif packet.haslayer(UDP):
        src_ip=packet[IP].src
        dst_ip=packet[IP].dst
        src_port=packet[UDP].sport
        dst_port=packet[UDP].dport
        log.write(f"TCP conenction found from {src_ip}:{src_port} --> {dst_ip}:{dst_port}")
    elif packet.haslayer(ICMP):
        src_ip=packet[IP].src
        dst_ip=packet[IP].dst
        src_port=packet[ICMP].sport
        dst_port=packet[ICMP].dport
        log.write(f"TCP conenction found from {src_ip}:{src_port} --> {dst_ip}:{dst_port}")
    elif packet.haslayer(HTTP):
        src_ip=packet[IP].src
        dst_ip=packet[IP].dst
        src_port=packet[HTTP].sport
        dst_port=packet[HTTP].dport
        log.write(f"TCP conenction found from {src_ip}:{src_port} --> {dst_ip}:{dst_port}")
    elif packet.haslayer(HTTPS):
        src_ip=packet[IP].src
        dst_ip=packet[IP].dst
        src_port=packet[HTTPS].sport
        dst_port=packet[HTTPS].dport
        log.write(f"TCP conenction found from {src_ip}:{src_port} --> {dst_ip}:{dst_port}")
def main(interface):
    log_name=f"packet_sniff{interface}.txt"
    with open(log_name, "w") as log:
        try:
            if verbose:
                sniff(iface=interface,prn=lambda pkt:find_packet(pkt,log_name),store=0,verbose=verbose)
            else:
                sniff(iface=interface,prn=lambda pkt: find_packet(pkt,log),store=0)
        
        except KeyboardInterrupt:
            sysv.exit(0)
    print(f"Log saved as {log_name}")
    
if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python sniffer.py <interface> [verbose]")
        sys.exit(1)
    verbose = False
    if len(sys.argv) == 3 and sys.argv[2].lower() == "verbose":
        verbose = True
    main(sys.argv[1], verbose)

    
        
