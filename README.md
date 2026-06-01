# 📡 Wi-Fi Security Toolkit — Sessions 1–4

> *"With great antenna comes great responsibility."*
> — Someone who definitely said this at some point.

An educational Wi-Fi security toolkit covering the full arc — 802.11
fundamentals, passive reconnaissance, active attacks, and defense — built for
the CYBERS3C Ethical Hacking Postgrad, Wi-Fi Module, Sessions 1–4.

---

## ⚠️ Legal Disclaimer (please read, we know you won't)

These scripts are for **authorized security testing**, **CTF competitions**,
and **educational purposes only**.

Using them on networks you don't own is illegal in most countries, frowned
upon in all countries, and will make your professor very disappointed in you.
Not angry. *Disappointed.* Which is worse.

You have been warned. In bold. With an emoji.

---

## 🧰 What's in the box

Scripts are grouped by topic; numbering is sequential **within each folder**.
Slide demos (📐) are the minimal, slide-sized versions of bigger tools.

### 🔧 `01_setup/` — get on the air

| Script | What it does | Energy level |
|--------|-------------|-------------|
| `01_preflight_check.py` | Verifies your machine is actually ready before class starts | 🔧 Zero coffee, all pragmatism |
| `02_setup_monitor.py` | Enables / disables monitor mode | ☕ One coffee |
| `03_channel_hopper.py` | Hops channels so capture tools never miss a packet (Terminal A) | ☕☕ Two coffees |

### 📡 `02_recon/` — passive reconnaissance (sends nothing)

| Script | What it does | Energy level |
|--------|-------------|-------------|
| `01_frame_classifier.py` | Live tally of mgmt/control/data frames by subtype (Session 1) | 📚 Zero coffee, day one |
| `02_discover_networks.py` 📐 | Discover networks by sniffing beacons | ☕ One coffee |
| `03_client_pnl.py` 📐 | Collect client PNLs from probe requests — shows *why* KARMA works | ☕ One coffee |
| `04_probe_analyzer.py` | Reads the travel diary in every phone nearby | ☕☕☕ Three coffees |
| `05_ap_scanner.py` | Real-time AP map with encryption, channel, vendor, signal | ☕ One coffee |
| `06_hidden_ssid_hunter.py` | Reveals hidden SSIDs by waiting for their clients to talk | ☕ One coffee + patience |
| `07_beacon_fingerprint.py` | Deep beacon analysis — Wi-Fi gen, WPS, PMF, ciphers | ☕☕ Two coffees + curiosity |
| `08_karma_detector.py` | Detects KARMA-style attacks — APs that respond to any probe | 🛡️ Defensive, paranoid, correct |
| `09_gps_wardriver.py` | Logs APs with GPS to a WiGLE-1.4 CSV (feeds `06_analysis/04_wigle_enricher.py`) | 🚗 One tank of fuel |
| `10_client_tracker.py` | Live map of which client is associated to which AP | ☕ One coffee |
| `11_rssi_locator.py` | A Wi-Fi "Geiger counter" — homes in on a target by signal | 📡 One coffee + good shoes |
| `12_channel_survey.py` | Per-channel congestion survey — find the quiet (or busy) channels | ☕ One coffee, very practical |

### 🎯 `03_capture/` — grab handshakes / read captures

| Script | What it does | Energy level |
|--------|-------------|-------------|
| `01_handshake_catcher.py` | Catches WPA2 handshakes without sending a single packet | 🍵 Herbal tea (very zen) |
| `02_pcap_recon.py` | Full offline recon over a saved `.pcap`. **No adapter needed** | 💿 Coffee optional, hardware not |

### ⚡ `04_attacks/` — active (authorization required)

| Script | What it does | Energy level |
|--------|-------------|-------------|
| `01_fake_ap.py` 📐 | Announce a fake AP (beacon flood) | ⚡ Adrenaline-lite |
| `02_deauth_demo.py` 📐 | The deauth "kick" that pushes a client to your twin | ⚡ Adrenaline-lite |
| `03_deauth.py` | Sends deauth frames to force reconnection | ⚡ Adrenaline |
| `04_pmkid_extractor.py` | Grabs PMKID from EAPOL M1 — no client needed | ☕ One coffee, elegant attack |
| `05_evil_twin.py` | Generates Evil Twin AP config | ☕☕☕ + a signed piece of paper |
| `06_handshake_to_hashcat.py` | Converts a captured `.pcap` to hashcat `-m 22000`, validated | 🔑 The bridge to cracking |
| `07_csa_attack.py` | Forges Channel Switch Announcements to herd clients off-channel | ⚡ The quiet cousin of deauth |
| `08_wps_pixiedust.py` | WPS Pixie Dust attack — recovers the PIN offline (reaver wrapper) | 💨 The exploit `05_defense/02` warns about |

### 🛡️ `05_defense/` — WPA3, enterprise, detection

| Script | What it does | Energy level |
|--------|-------------|-------------|
| `01_wids_sensor.py` | Detects deauth floods, evil twins, probe floods, MAC churn | 🍵 Calm, defensive, smug |
| `02_wps_scanner.py` | Identifies WPS-enabled APs and rates their vulnerability | ☕ One coffee, many sighs |
| `03_wpa3_detector.py` | Detects WPA3/SAE/OWE and the dangerous WPA3 transition mode | 🔐 The downgrade hunter |
| `04_pmf_detector.py` | Maps which APs enforce PMF (802.11w) and which are deauth-able | 🛡️ Knows who's immune |
| `05_enterprise_recon.py` | Recon of 802.1X/EAP networks + clear-text EAP identities | 🏢 Two coffees, one NDA |

### 🔬 `06_analysis/` — offline / correlation

| Script | What it does | Energy level |
|--------|-------------|-------------|
| `01_ie_fingerprinter.py` | Identifies OS from probe IE structure — survives MAC randomization | 🧠 Zero coffee, pure maths |
| `02_probe_timeline.py` | Visualises probe bursts and device wake/sleep cycles as ASCII art | ☕ One coffee, strangely satisfying |
| `03_pnl_correlator.py` | Cross-correlates PNLs to find devices likely owned by the same person | ☕☕ Two coffees, mild existential dread |
| `04_wigle_enricher.py` | Queries WiGLE to geolocate SSIDs from a captured PNL | 🌍 One API key and a sense of power |

### 📝 `07_reporting/`

| Script | What it does | Energy level |
|--------|-------------|-------------|
| `01_report_generator.py` | Merges the suite's JSON outputs into one Markdown report | 📝 The part nobody enjoys |

> `wifi_utils.py` (repo root) is the shared library — MAC/IE/RSN/EAPOL parsing,
> monitor-mode checks, vendor lookup, JSON I/O. Imported by the scripts, not run directly.

---

## 🔌 Requirements

```bash
# The only dependency that matters
pip install scapy

# Also: a Wi-Fi adapter that supports monitor mode.
# The TP-Link you've been using since 2013 probably doesn't.
# An Alfa adapter is the classic choice. No, we don't get a commission.
```

Tested on **Kali Linux**. Should work on any Debian-based system with
a Wi-Fi adapter that isn't held together with electrical tape.
(If it *is* held together with electrical tape, it might still work. Alfa cards are resilient.)

---

## 🚀 Usage

### Step 0 — Figure out what interface you have

```bash
lsusb          # "what did I plug in"
iw dev         # "what does the kernel think I plugged in"
dmesg | tail   # "why is the kernel upset about what I plugged in"
```

### Step 1 — Enable monitor mode

```bash
sudo python3 01_setup/02_setup_monitor.py start wlan1 --channel 6
```

> **Note:** scripts live in topic folders (`01_setup/`, `02_recon/`, `03_capture/`,
> `04_attacks/`, `05_defense/`, `06_analysis/`, `07_reporting/`) but are always run **from
> the repo root** — e.g. `sudo python3 02_recon/05_ap_scanner.py …` — so the shared
> `wifi_utils.py` resolves correctly.

The script will:
- Kill NetworkManager (it's in the way)
- Kill wpa_supplicant (also in the way)
- Put your card in monitor mode
- Validate the result so you don't spend 20 minutes wondering why nothing works

To go back to normal human being mode:

```bash
sudo python3 01_setup/02_setup_monitor.py stop wlan1
```

### Step 2 — Start the channel hopper (Terminal A)

```bash
sudo python3 01_setup/03_channel_hopper.py --iface wlan1 --band 2.4
```

This hops through all 13 channels every ~6.5 seconds.
Your capture tool in Terminal B will see everything on all channels.
This is the Wi-Fi equivalent of looking both ways before crossing the street.

### Step 3 — Analyze probe requests (Terminal B)

```bash
sudo python3 02_recon/04_probe_analyzer.py --iface wlan1 --output room.json
```

Every phone in range is loudly announcing every Wi-Fi network it has
ever connected to. We are just listening politely.

Sample output (real data masked, obviously):

```
══════════════════════════════════════════════════════════════════════
  CLIENTS AND PNL — 47 unique clients
══════════════════════════════════════════════════════════════════════
  CLIENT MAC           RND    #    VENDOR              SSIDS PROBED
──────────────────────────────────────────────────────────────────────
  3C:22:FB:**:**:**         328  Apple               MEO-XXXX, Marriott_Lisbon...
  A4:5E:60:**:**:**         192  Samsung             Vodafone-Home, FCT_WiFi...
  B2:55:01:**:**:**    🎲    12  (random)            (randomized — this one knows)
  DC:A6:32:**:**:**         445  Raspberry Pi        lab_internal, dev_net...
──────────────────────────────────────────────────────────────────────
  [stat] Randomized MACs : 18/47 (38%)
```

The Raspberry Pi with 445 probes is always the most fun to explain to people.

### Step 4 — Catch a WPA2 handshake (passive)

```bash
sudo python3 03_capture/01_handshake_catcher.py \
    --iface wlan1 \
    --bssid AA:BB:CC:DD:EE:FF \
    --channel 6 \
    --output lab.pcap
```

Lock to the target channel, specify the BSSID, and wait.
Every time a device reconnects naturally (wakes from sleep, walks back in range),
it re-runs the 4-way handshake. We catch it. We send nothing.

```
[✓] COMPLETE (crackable) HANDSHAKE — 14:32:07
    BSSID  : aa:bb:cc:dd:ee:ff
    STA    : 3c:22:fb:11:22:33
    SSID   : CYBERS3C_LAB
    Msgs   : M12
```

The `.pcap` is ready for Session 3 (offline cracking with hashcat).

---

## 🔍 The 4-way handshake, explained badly

```
AP  ──M1──►  STA    "Hey, prove you know the password. Here's a nonce."
AP  ◄──M2──  STA    "Sure. Here's MY nonce and a MIC. I totally know it."
AP  ──M3──►  STA    "Verified. Here's the group key. Install it."
AP  ◄──M4──  STA    "Done. Let's go."
```

We need M1+M2 (or M2+M3) to attempt offline cracking.
That's it. That's the whole vulnerability.
The password never travels over the air — but enough information does
that we can test guesses offline at billions of attempts per second.

`rockyou.txt` was a hint. `password123` is a prayer.

---

## 🎲 MAC Randomization

Devices flagged with 🎲 are using locally-administered (randomized) MAC addresses.
Introduced by iOS 14, Android 10, and Windows 10 because vendors realized
that broadcasting a globally unique identifier everywhere is… not great.

Detection: if `mac[0] & 0x02 == 1` → randomized.

```
MAC: B2:55:01:XX:XX:XX
     ↑
     └── B2 = 0xB2 = 1011 0010
                        ↑
                        bit 1 set → locally administered → randomized
```

Spoiler: most IoT devices, smart TVs, printers, and that one ancient
laptop from 2011 still broadcast their real MAC without shame.

---

## 🗺️ OUI Fingerprinting

The first 3 bytes of any MAC address identify the manufacturer.
The IEEE assigns these. Wireshark maintains a list of ~50,000 of them.

```bash
# On Kali, it lives here:
/usr/share/wireshark/manuf

# Usage: see who made it
grep -i "DC:A6:32" /usr/share/wireshark/manuf
# DC:A6:32  Raspberry Pi Trading Ltd.
# (it's always a Raspberry Pi)
```

Vendor + probed SSIDs = surprisingly complete profile of a stranger.
Think about that next time you leave your Wi-Fi on while wandering around a conference.

---

## 🕵️ What a passive capture reveals

Without sending a single packet, in a 10-minute capture in any office or cafe:

- Number of unique devices in range
- Manufacturer of each device (OUI)
- Every Wi-Fi network each device has ever connected to
- Whether the device uses MAC randomization (and how well)
- Signal strength (approximate distance)
- Whether there's a Raspberry Pi doing something suspicious

This is why the slide says:
> *"The most dangerous attacker is the one who never transmits."*

---

## 📁 File structure

Scripts are grouped by topic. Run them **from the repo root**
(e.g. `sudo python3 02_recon/05_ap_scanner.py …`).

```
.
├── wifi_utils.py               # Shared library (MAC/IE/RSN/EAPOL parsing, checks, JSON I/O)
├── README.md                   # You are here
│
├── 01_setup/                      # Get on the air
│   ├── 01_preflight_check.py   #   Run this first. Every session. No exceptions.
│   ├── 02_setup_monitor.py     #   Monitor mode on/off
│   └── 03_channel_hopper.py    #   Channel hopper — Terminal A
│
├── 02_recon/                      # Passive reconnaissance (sends nothing)
│   ├── 01_frame_classifier.py #   Live 802.11 frame-type tally (Session 1 demo)
│   ├── 02_discover_networks.py#   Slide demo: discover networks via beacons
│   ├── 03_client_pnl.py       #   Slide demo: collect client PNLs (probe requests)
│   ├── 04_probe_analyzer.py    #   Probe request analyzer — Terminal B
│   ├── 05_ap_scanner.py        #   Real-time AP map
│   ├── 06_hidden_ssid_hunter.py#   Hidden SSID revealer
│   ├── 07_beacon_fingerprint.py#   Deep beacon analysis and AP fingerprinting
│   ├── 08_karma_detector.py    #   Detect KARMA rogue AP attacks
│   ├── 09_gps_wardriver.py     #   GPS wardriving → WiGLE-1.4 CSV
│   ├── 10_client_tracker.py    #   Live client↔AP association map
│   ├── 11_rssi_locator.py      #   Locate a target by live RSSI (Geiger counter)
│   └── 12_channel_survey.py    #   Per-channel congestion / site survey
│
├── 03_capture/                    # Grab handshakes / read captures
│   ├── 01_handshake_catcher.py #   WPA2 handshake capture (passive)
│   └── 02_pcap_recon.py        #   Offline recon over a saved .pcap (no adapter needed)
│
├── 04_attacks/                    # Active — authorization required
│   ├── 01_fake_ap.py          #   Slide demo: fake AP / beacon flood
│   ├── 02_deauth_demo.py      #   Slide demo: deauth "kick" mechanics
│   ├── 03_deauth.py            #   Deauth frames
│   ├── 04_pmkid_extractor.py   #   PMKID extraction from EAPOL M1
│   ├── 05_evil_twin.py         #   Evil twin config generator
│   ├── 06_handshake_to_hashcat.py # .pcap → hashcat -m 22000 (the cracking bridge)
│   ├── 07_csa_attack.py        #   Channel Switch Announcement attack
│   └── 08_wps_pixiedust.py     #   WPS Pixie Dust attack
│
├── 05_defense/                    # WPA3, enterprise, detection
│   ├── 01_wids_sensor.py       #   Wireless Intrusion Detection System
│   ├── 02_wps_scanner.py       #   WPS vulnerability scanner
│   ├── 03_wpa3_detector.py     #   WPA3/SAE/OWE + transition-mode downgrade detector
│   ├── 04_pmf_detector.py      #   802.11w (PMF) — who's immune to deauth
│   └── 05_enterprise_recon.py  #   802.1X/EAP recon + clear-text EAP identities
│
├── 06_analysis/                   # Offline / correlation
│   ├── 01_ie_fingerprinter.py  #   OS fingerprint from probe IE sequence
│   ├── 02_probe_timeline.py    #   Device wake/sleep timeline + burst analysis
│   ├── 03_pnl_correlator.py    #   Cross-correlate PNLs — find same-person devices
│   └── 04_wigle_enricher.py    #   Geolocate SSIDs via WiGLE API
│
└── 07_reporting/
    └── 01_report_generator.py  #   Merge JSON outputs → Markdown report
```

---

## 🎓 Course context

**CYBERS3C — Ethical Hacking Postgrad — Wi-Fi Module**

| Session | Topic | Folders |
|---------|-------|---------|
| 1 | 802.11 standards, frame types, WEP/WPA/WPA2/WPA3 overview | `02_recon/01` |
| 2 | Reconnaissance & passive capture | `01_setup/` · `02_recon/` · `03_capture/` · `06_analysis/` |
| 3 | Active attacks: deauth, MDK4, PMKID, offline cracking | `04_attacks/` |
| 4 | WPA3, enterprise Wi-Fi, defenses | `05_defense/` |
| — | Tooling | `07_reporting/` · `wifi_utils.py` |

---

## 📚 Further reading

- [A Study of MAC Address Randomization in Mobile Devices](https://arxiv.org/abs/1703.02874) — Martin et al., 2017
- [IEEE 802.11-2020](https://standards.ieee.org/ieee/802.11/7028/) — the spec that started it all (warning: 4000+ pages)
- [Wireshark 802.11 filters](https://wiki.wireshark.org/Wi-Fi) — keep this open at all times
- [WiGLE](https://wigle.net) — global database of geolocated BSSIDs, because apparently we mapped the entire planet's Wi-Fi

---

## 🤝 Contributing

Found a bug? Open an issue.
Want to add a feature? Open a PR.
Want to tell us you used this for something illegal? Please don't.

---

*Built with caffeine and mild concern for privacy.*
