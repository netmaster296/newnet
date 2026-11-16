import random
from scapy.all import *
random.seed(7)
pkts = []
t = 1000.0
# 40 flows: TCP-ish with heavy-tail sizes + bursts, UDP VoIP-ish constant small, DNS queries
for f in range(40):
    a = "10.0.%d.%d" % (f // 4, f % 4 + 10)
    b = "93.184.%d.%d" % (f % 7, f % 11 + 20)
    sport = 20000 + f
    if f % 4 == 0:  # voip-like
        for i in range(200):
            pkts.append(Ether()/IP(src=a, dst=b)/UDP(sport=sport, dport=5060)/("V"*20))
            pkts.append(Ether()/IP(src=b, dst=a)/UDP(sport=5060, dport=sport)/("R"*21))
            t += 0.02
    elif f % 4 == 1:  # dns-like
        for i in range(50):
            pkts.append(Ether()/IP(src=a, dst="8.8.8.8")/UDP(sport=sport, dport=53)/("Q"*(40 + i % 30)))
            pkts.append(Ether()/IP(src="8.8.8.8", dst=a)/UDP(sport=53, dport=sport)/("A"*(120 + i % 400)))
            t += 0.3
    else:  # web/tcp-like: burst of big packets + acks
        for i in range(300):
            if i % 20 == 0:
                t += random.uniform(0.5, 2.0)  # burst gap
            pkts.append(Ether()/IP(src=b, dst=a)/TCP(sport=80, dport=sport)/("D"*random.choice([120, 600, 1400, 1400, 1460])))
            pkts.append(Ether()/IP(src=a, dst=b)/TCP(sport=sport, dport=80)/"")  # pure ack
wrpcap("synth_40flows.pcap", pkts, append=False)
print("wrote", len(pkts), "packets")
