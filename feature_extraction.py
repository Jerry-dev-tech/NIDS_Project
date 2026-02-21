from scapy.all import IP, IPv6, TCP, UDP, ICMP

def pkt_to_basic_features(pkt):
    """
    Return a dict used by the app:
    - proto_tcp / proto_udp / proto_icmp / proto_other (one-hot)
    - ip_version_4 / ip_version_6
    - src_bytes (packet length) , dst_bytes (0 here)
    - tcp_flags (int) if TCP layer present
    - pkt_len (general length)
    """

    out = {}

    # Packet length
    try:
        pkt_len = len(pkt)
    except Exception:
        pkt_len = 0

    out['pkt_len'] = pkt_len
    out['src_bytes'] = pkt_len
    out['dst_bytes'] = 0

    # IP Version Detection

    ip_v4 = 1 if pkt.haslayer(IP) else 0
    ip_v6 = 1 if pkt.haslayer(IPv6) else 0

    out['ip_version_4'] = ip_v4
    out['ip_version_6'] = ip_v6


    # Protocol Detection

    proto_tcp = proto_udp = proto_icmp = 0
    tcp_flags = 0

    if pkt.haslayer(TCP):
        proto_tcp = 1
        tcp_flags = int(pkt.getlayer(TCP).flags)

    elif pkt.haslayer(UDP):
        proto_udp = 1

    elif pkt.haslayer(ICMP):
        proto_icmp = 1

    out['proto_tcp'] = proto_tcp
    out['proto_udp'] = proto_udp
    out['proto_icmp'] = proto_icmp
    out['proto_other'] = 0 if (proto_tcp or proto_udp or proto_icmp) else 1
    out['tcp_flags'] = tcp_flags

    return out
