import random
from scapy.all import *
random.seed(11)
pkts = []
t = 1000.0
for f in range(2000):
    a = "10.%d.%d.%d" % (f // 254, f % 254, 10)
    b = "172.%d.%d.%d" % (f % 200, f % 13 + 1, f % 250 + 3)
    sport = 20000 + f
    n = random.choice([5, 20, 60, 200])
    for i in range(n):
        sz = random.choice([0, 48, 300, 1200, 1460])
        pkts.append(Ether()/IP(src=a, dst=b)/TCP(sport=sport, dport=443)/("D"*sz) if sz else Ether()/IP(src=a, dst=b)/TCP(sport=sport, dport=443)/"")
        if i % 5 == 4:
            pkts.append(Ether()/IP(src=b, dst=a)/TCP(sport=443, dport=sport)/("S"*random.choice([50, 700, 1440])))
wrpcap("synth_2000flows.pcap", pkts, append=False)
print("wrote", len(pkts))
