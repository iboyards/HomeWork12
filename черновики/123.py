import pyshark
import pandas as pd
import matplotlib.pyplot as plt

pcap_file = "dynDNS_winupdatedurchServer.pcap"

cap = pyshark.FileCapture(
    pcap_file,
    display_filter="dns && dns.flags.response == 0",  # только DNS-запросы
    keep_packets=False,
    use_json=True
)

dns_requests = []

for p in cap:
    try:
        # безопасно достаём src/dst для IPv4/IPv6
        if hasattr(p, "ip"):
            src_ip, dst_ip = p.ip.src, p.ip.dst
        elif hasattr(p, "ipv6"):
            src_ip, dst_ip = p.ipv6.src, p.ipv6.dst
        else:
            src_ip = dst_ip = None

        dns_requests.append({
            "time": p.sniff_time,
            "domain": str(p.dns.qry_name),
            "src_ip": src_ip,
            "dst_ip": dst_ip
        })
    except Exception:
        continue

cap.close()

df_dns = pd.DataFrame(dns_requests)

if df_dns.empty:
    print("DNS-запросов не найдено (в этом pcap, похоже, только DHCP).")
else:
    print(df_dns.head())

    domain_counts = df_dns["domain"].value_counts()
    print(domain_counts.head(10))

    df_dns["time"] = pd.to_datetime(df_dns["time"])
    df_dns["minute"] = df_dns["time"].dt.floor("min")

    dns_by_time = df_dns.groupby("minute").size()

    plt.figure()
    dns_by_time.plot()
    plt.xlabel("Время")
    plt.ylabel("Количество DNS-запросов")
    plt.title("DNS-запросы по времени")
    plt.show()