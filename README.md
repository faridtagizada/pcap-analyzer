# PCAP Analyzer

Python və **scapy** ilə yazılmış sadə şəbəkə trafiki analizatoru. PCAP/PCAPNG faylını oxuyur, protokol və IP statistikası çıxarır, DNS sorğularını göstərir və **port scan** cəhdlərini aşkarlayır. Nəticəni terminal, JSON, CSV və qrafik şəklində verir.

## Funksiyalar
- Ümumi statistika: paket sayı, ölçü, müddət
- Protokol paylanması (TCP, UDP, ICMP, DNS, ARP)
- Ən aktiv mənbə/hədəf IP-lər və ən çox əlaqə quran cütlər
- Ən çox hədəflənən portlar
- DNS sorğularının siyahısı
- **Port scan aşkarlanması**: bir IP eyni hədəfdə N-dən çox fərqli porta SYN göndərərsə (default 15)
- Böyük fayllar üçün `PcapReader` ilə axın (streaming) oxuma
- Çıxış: terminal, JSON, CSV, PNG qrafik
- `argparse` CLI və `pytest` testləri

## Quraşdırma
```bash
git clone https://github.com/<istifadəçi_adın>/pcap-analyzer.git
cd pcap-analyzer
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## İstifadə
```bash
# Nümunə PCAP yarat və analiz et
python samples/generate_sample.py
python -m pcapanalyzer samples/sample.pcap

# Öz tutduğun trafiki analiz et (tcpdump / Wireshark)
sudo tcpdump -i eth0 -c 500 -w capture.pcap
python -m pcapanalyzer capture.pcap --top 5

# JSON + CSV + qrafik
python -m pcapanalyzer capture.pcap --json out.json --csv out.csv --chart out.png

# Port scan həssaslığını dəyiş
python -m pcapanalyzer capture.pcap --scan-threshold 25
```

| Parametr | Təsvir | Default |
|---|---|---|
| `--top N` | Cədvəllərdə sətir sayı | 10 |
| `--scan-threshold N` | Port scan üçün fərqli port həddi | 15 |
| `--json FAYL` | JSON çıxışı | – |
| `--csv FAYL` | CSV çıxışı | – |
| `--chart FAYL.png` | Qrafik | – |

### Nümunə çıxış
```
== Protokollar ==
  Protokol  Paket
  TCP       60
  DNS       4
  ICMP      3

== Şübhəli aktivlik ==
  [!] Port scan şübhəsi: 10.0.0.66 -> 192.168.1.10 (30 fərqli port)
```
> Real PCAP üzərində işlətdiyin çıxışın ekran görüntüsü ilə əvəz et.

## Layihə strukturu
```
pcap-analyzer/
├── pcapanalyzer/
│   ├── analyzer.py   # scapy ilə PCAP analizi
│   ├── report.py     # terminal / JSON / CSV / qrafik
│   └── cli.py        # argparse CLI
├── samples/generate_sample.py
├── tests/test_analyzer.py
└── requirements.txt
```

## Testlər
```bash
pytest -v
```

## Məhdudiyyətlər
- Yalnız SYN-əsaslı port scan aşkarlanır (UDP scan və yavaş scan yox).
- Şifrələnmiş trafikin (HTTPS) məzmunu analiz olunmur, yalnız metadata.
- IPv6 əsas səviyyədə dəstəklənir.

## Gələcək planlar
- [ ] Zaman üzrə trafik qrafiki (paket/saniyə)
- [ ] SYN flood və ARP spoofing aşkarlanması
- [ ] HTTP sorğularının çıxarılması
- [ ] GeoIP / IP reputation inteqrasiyası

## Lisenziya
MIT
