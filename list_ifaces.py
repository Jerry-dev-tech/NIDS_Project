from scapy.all import get_if_list, conf
print("get_if_list():")
print(get_if_list())
print("\nconf.ifaces keys and pcap names:")
for k, obj in conf.ifaces.items():
    try:
        print("KEY:", k)
        print("  name       :", obj.name)
        print("  desc       :", getattr(obj, "description", None))
        print("  ip         :", getattr(obj, "ip", None))
        print("  mac        :", getattr(obj, "mac", None))
        print("  pcap_name  :", getattr(obj, "pcap_name", None))
    except Exception as e:
        print("  error reading iface:", e)
