# Wi-Fi Checkup

A free, **read-only** tool that checks your home Wi-Fi and internet connection,
explains in plain language what's slowing it down, and lists every device on your
network so you can spot anyone using it without your permission.

It **never changes any settings** on your computer or your router. It only reads
information and sends ordinary network traffic (pings, a few DNS lookups and a speed test).

It answers three questions:

| Question | What it measures |
|---|---|
| **How strong and healthy is my Wi-Fi?** | Signal strength, 2.4 / 5 / 6 GHz band, channel and how crowded it is by neighbours, link speed, Wi-Fi generation, encryption type |
| **Why is my internet slow, and whose fault is it?** | Response time and packet loss to your router (the Wi-Fi part) and to the internet (the provider part), DNS speed compared with public DNS, download and upload speed, and lag while the line is busy ("bufferbloat") |
| **Is anyone using my Wi-Fi without permission?** | Every device that's online right now, with its name where the device reveals one. It remembers what it saw, so the next run flags any **new** device |

---

## 1. Run it

You need **Python 3.8 or newer** and a computer connected to your home Wi-Fi.
A laptop works best, used in the room where the internet feels slow.
Turn off any VPN first.

### Windows

1. Install Python from <https://www.python.org/downloads/>. During setup, tick
   **"Add python.exe to PATH"**.
2. Download this `wifi-checkup` folder (or just `wifi_checkup.py` and `run_wifi_checkup.bat`).
3. **Windows 11 only:** Windows hides Wi-Fi details unless Location is allowed. Open
   *Settings → Privacy & security → Location* and turn on **Location services** and
   **Let desktop apps access your location**. You can turn them off again afterwards.
4. Double-click **`run_wifi_checkup.bat`**.

   Or open *Command Prompt* in the folder and type `py wifi_checkup.py`.

If Windows asks whether Python may use the network, choose *Private networks* and
**Allow**. This lets the tool hear replies from devices, so more devices show their names.

### Mac

1. Open **Terminal** (Applications → Utilities).
2. Type `python3 --version`. If macOS offers to install developer tools, accept.
3. Go to the folder and run it:
   ```
   cd ~/Downloads/wifi-checkup
   python3 wifi_checkup.py
   ```
   If the speed test reports a *certificate* error, open *Applications → Python 3.x* and
   double-click **Install Certificates.command**, then run it again.
   If macOS asks whether Python may accept incoming connections, either answer is fine.
   **Allow** finds more device names.

### Linux

```
python3 wifi_checkup.py
```
Having `iw` and NetworkManager (`nmcli`) installed gives the most Wi-Fi detail.

### Useful options

```
python3 wifi_checkup.py --plan 100 --plan-up 20   # compare with what you pay for (Mbps)
python3 wifi_checkup.py --no-speed                # skip the speed test (saves mobile data)
python3 wifi_checkup.py --quick                   # shorter run, less precise
python3 wifi_checkup.py --vendors                 # look up who made each device (see Privacy)
python3 wifi_checkup.py --name aa:bb:cc:dd:ee:ff "Living room TV"   # name a device
```

A full run takes 1 to 2 minutes. The report appears on screen and is saved in a
`wifi-checkup` folder in your home folder, as a `.txt` file you can read and a
`.json` file with the details.

> **Tip:** run it twice, once next to the router and once where the Wi-Fi feels bad.
> If it's only bad far away, the fix is coverage (router placement or mesh). If it's
> bad even next to the router, look at the router, the channel or the provider.

---

## 2. Is someone using my Wi-Fi?

1. **Run the checkup once.** Section 5 of the report lists every device that's
   awake right now. This first list is saved as your starting point.
2. **Identify each device.** Names like `Kitchen-iPad` or `LAPTOP-AB12` make it easy.
   For the rest, compare the hardware (MAC) address with your devices'
   *Settings → About → Wi-Fi address*, or switch devices off one at a time and scan again.
   Name the ones you recognise:
   `python3 wifi_checkup.py --no-speed --name 3c:22:fb:12:34:56 "My phone"`
3. **Later runs mark any newcomer as `NEW`.**
4. **Also check the router's own list.** It includes sleeping devices that a scan can't
   see. Log in to the router (the address is in section 6 of the report, usually
   `192.168.0.1`, `192.168.1.1` or `10.0.0.1`) and look for *Attached devices*,
   *DHCP clients*, *Client list* or *Device list*. If your router came from your internet
   provider, the provider's app often shows the same list.
5. **If you find a device you can't explain:**
   - Change the **Wi-Fi password** to a long new one (12+ characters; a few random
     words works well) and make sure security is **WPA2-Personal (AES)** or **WPA3**.
     This disconnects everyone. Reconnect only your own devices.
   - Turn **WPS off**. It's a common way in.
   - Change the router's **admin password** (the login for the settings page; not the
     Wi-Fi password) if it's still the one printed on the sticker.
   - Blocking one device ("MAC filtering") is only a stop-gap. Devices can fake their address.

**Not every unknown device is an intruder.** Phones and laptops often use a *private*
(randomised) address that can change. The report marks these `private address`.
Smart TVs, plugs, cameras, speakers and printers count too. Most homes have more
devices than people expect.

---

## 3. Make it faster and stronger: what usually helps most

Work down this list. The report tells you which of these apply to you.

**Quick wins (free, minutes):**
1. **Restart the modem and router.** Unplug for 30 seconds, plug the modem in first,
   then the router.
2. **Move the router.** Put it somewhere central, high and in the open. Keep it out of
   cupboards, away from the floor and from behind the TV. Keep it away from microwaves,
   cordless phones, baby monitors, mirrors, fish tanks and thick or metal walls.
   Point any antennas straight up.
3. **Use the 5 GHz band** for nearby devices. It's usually several times faster than
   2.4 GHz. Connect to the router's "5G" network, or turn on *Smart Connect* /
   *band steering*.
4. **Pick a quieter channel.** On 2.4 GHz use only **1, 6 or 11**, whichever the report
   says is least crowded. On 5 GHz, try another channel if many neighbours share yours.
5. **Pause heavy users** while you need speed: big downloads, game updates,
   4K streaming, and cloud backups such as photo, OneDrive or iCloud uploads.
6. **Plug in what doesn't move.** TVs, desktop PCs and game consoles are faster and steadier
   on an Ethernet cable, and that frees up Wi-Fi for everything else.

**Router settings (5–15 minutes):**
1. **Update the router's firmware.** Turn on automatic updates if offered.
2. **Turn on QoS / Smart Queue Management (SQM)** if the report shows lag while busy.
   Enter about 90% of your plan's speeds.
3. **Use a faster DNS** if the report suggests one. Set the router's DNS to `1.1.1.1`
   (Cloudflare), `8.8.8.8` (Google) or `9.9.9.9` (Quad9) so every device benefits.
4. **Use WPA2-AES or WPA3, never WPA/TKIP.** Old TKIP encryption also caps Wi-Fi speed.

**If it's still not enough:**
- **Weak in some rooms only:** a **mesh Wi-Fi system**, or a second access point
  connected to the router by cable, beats a plug-in range extender.
- **Slow even next to the router, or on a cable:** test with a cable. If it's still
  well below your plan, call your provider with the report's numbers. Mention
  *packet loss* if the report found it.
- **Router or device older than Wi-Fi 5:** with plans over ~100 Mbps, an old router (or an
  old Wi-Fi adapter in the computer) is often the limit.

---

## 4. Security checklist (once)

Log in to your router's admin page and check:

- [ ] Admin password changed from the default on the sticker
- [ ] Wi-Fi security: **WPA2-Personal (AES)** or **WPA3**. Never WEP, WPA/TKIP or Open
- [ ] **WPS** off
- [ ] **Remote management** (access from the internet) off
- [ ] Firmware up to date
- [ ] **Guest network** for visitors and smart gadgets
- [ ] **UPnP** off, unless a game console or app needs it
- [ ] **Telnet** and unused USB file sharing off. The report flags these if it sees them

---

## 5. Privacy: what leaves your computer

- **Speed test:** downloads and uploads test data from `speed.cloudflare.com`, the
  service behind Cloudflare's own speed test. It also reads which test location you
  were connected to. A full test can use a few hundred MB on a fast line; use
  `--no-speed` on metered connections.
- **Response times:** pings to your router, `1.1.1.1` (Cloudflare) and `8.8.8.8` (Google).
- **DNS check:** looks up a few popular websites (google.com, youtube.com, …) through your
  current DNS, Cloudflare, Google and Quad9.
- **Device scan:** stays inside your home network. It sends one tiny message to each
  address so devices reveal themselves, and asks devices for their names.
- **`--vendors` (off by default):** sends only the **manufacturer half** of each
  device's hardware address (for example `3c:22:fb`) to `api.macvendors.com`, to show
  who made it. The device-specific half is never sent.
- Everything else, including the reports and the list of your devices, is stored
  **only on your computer** in the `wifi-checkup` folder in your home folder.

---

## 6. Troubleshooting

| Message | Fix |
|---|---|
| *"Windows only shows Wi-Fi details to programs when Location is allowed"* | See step 3 of the Windows instructions above. |
| *"macOS hid the Wi-Fi network name"* | Harmless. Signal, channel and security are still measured. To see the name, allow Location for Terminal in *System Settings → Privacy & Security → Location Services*. |
| *"Your internet traffic seems to go through a VPN"* | Turn off the VPN and run again. |
| *"The device scan was skipped"* | You're on a network that isn't a normal home network, such as a mobile hotspot or some VPNs. |
| Speed test *certificate* error on Mac | Run *Install Certificates.command* (see Mac instructions). |
| Fewer devices than the router lists | Normal. Sleeping phones and gadgets don't answer. The router's list is the complete one. |

## For developers

Only the Python standard library is used. Run the tests from this folder:

```
python3 -m unittest discover -s tests -v
```

The tests feed the tool's readers sample output from Windows (`netsh`, `route`, `arp`,
`ipconfig`, `ping`, including translated versions), macOS (`system_profiler`, `airport`,
`route`, `ifconfig`, `arp`) and Linux (`iw`, `nmcli`, `/proc`). They also check DNS,
mDNS, NetBIOS and UPnP message handling against local stand-in servers. The speed test
is checked against a local server with a set speed limit.
