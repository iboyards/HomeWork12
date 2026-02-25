import pyshark
import pandas as pd
import matplotlib.pyplot as plt

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"
PCAP_FILE   = r"dynDNS_winupdatedurchServer.pcap"

domains = []

cap = pyshark.FileCapture(
    PCAP_FILE,
    tshark_path=TSHARK_PATH,
    display_filter="dns && dns.flags.response==0",
    custom_parameters=["-d", "udp.port==53,dns"],
    keep_packets=False
)

for p in cap:
    try:
        domains.append(str(p.dns.qry_name).strip("."))
    except:
        pass

cap.close()

if not domains:
    print("DNS-запросы не найдены.")
    exit()

df = pd.DataFrame(domains, columns=["domain"])
counts = df["domain"].value_counts()

plt.figure()
counts.plot(kind="bar")
plt.xlabel("Домен")
plt.ylabel("Количество DNS-запросов")
plt.title("Частота DNS-запросов по доменам")
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("dns_frequency_by_domain.png")
plt.show()