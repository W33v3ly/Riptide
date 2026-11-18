# 🌊 Riptide

**A fast, single-file TCP port scanner written in pure C.**
No dependencies, no installer, no runtime. One `.c` file that builds on Windows, Linux and macOS.

```
$ riptide 192.168.1.10 -p all -b
scanning 192.168.1.10 (192.168.1.10): 65535 ports, 500 concurrent, timeout 1000ms, banners on

PORT       STATE     SERVICE         BANNER
22/tcp     open      ssh             SSH-2.0-OpenSSH_9.6
80/tcp     open      http            HTTP/1.0 200 OK | Server: nginx/1.24.0
3389/tcp   open      rdp
8080/tcp   open      http-proxy      HTTP/1.1 200 OK | Server: Jetty(9.4.z)

4 open, 65531 closed, 0 filtered  |  65535 ports in 2.15s (30441 ports/s)
```

---

## ✨ Features

- **Fast**: up to 4,096 simultaneous non-blocking connections. A full 65,535-port sweep of a local host takes about 2 seconds.
- **Three port states**:
  - `open`: something is listening
  - `closed`: the host actively refused
  - `filtered`: no reply before the timeout (usually a firewall dropping packets)
- **Banner grabbing**: reads what the service sends first (SSH, FTP, SMTP…). On web ports it sends a `HEAD` request and shows the `Server:` header.
- **Low-noise mode**:
  - ports are scanned in randomized order by default
  - optional rate limiting and random jitter between connections
- **Clean teardown**: sockets are closed with a reset, not a normal shutdown, so they don't pile up in `TIME_WAIT` and slow the scan down.
- **IPv4 and IPv6**, hostnames resolved automatically.
- **Portable**: Winsock on Windows, POSIX sockets elsewhere, in the same source file.

---

## 🔧 Building

**Windows (MSVC)**: run from a Developer Command Prompt:
```bat
cl /O2 riptide.c ws2_32.lib
```

**Windows (MinGW)**
```bash
gcc -O2 riptide.c -o riptide.exe -lws2_32
```

**Linux / macOS**
```bash
gcc -O2 riptide.c -o riptide
```

---

## 🚀 Usage

```
riptide <host> [options]
```

| Option | Description | Default |
|---|---|---|
| `-p <ports>` | Ports to scan: `22,80,1000-2000`, `top`, or `all` | `top` |
| `-c <n>` | Concurrent connections | `500` |
| `-t <ms>` | Connect timeout | `1000` |
| `-b` | Grab service banners | off |
| `-B <ms>` | Banner read timeout | `1500` |
| `-r <n>` | Max new connections per second | unlimited |
| `-j <ms>` | Random extra delay (0..ms) between connections | `0` |
| `-s` | Scan ports in sequential order | randomized |
| `-a` | Also list closed and filtered ports | open only |
| `-q` | Hide the progress line | shown |

`top` is a built-in list of about 70 commonly used ports (SSH, HTTP, SMB, RDP, databases, etc.).

### Examples

```bash
# Quick look at common ports
riptide 192.168.1.10

# Full range, high concurrency, with banners
riptide myserver.local -p all -c 1000 -b

# Specific ports and ranges
riptide 10.0.0.5 -p 22,80,443,8000-8100

# Slow and quiet: ~20 connections/sec, random gaps, few at a time
riptide 10.0.0.5 -p 1-1024 -r 20 -j 200 -c 10

# Show everything, including closed and filtered
riptide 10.0.0.5 -p 1-100 -a
```

---

## ⚙️ How it works

1. The target is resolved once with `getaddrinfo`.
2. The port list is built and shuffled (Fisher–Yates with a xorshift64 RNG).
3. A pool of connection slots is filled with non-blocking `connect()` calls.
4. The scanner waits for events with `select()` on Windows and `poll()` everywhere else.
   - On Windows, failed connects show up in the *except* set, so it watches that too.
5. Each socket ends up in one of three states:
   - **Connected** → `open`. With `-b`, it then waits briefly for a banner.
   - **Refused** → `closed`.
   - **No answer before `-t`** → `filtered`.
6. Finished slots are refilled right away, so the pipeline stays full.

### Tuning tips

- **LAN targets**: lower the timeout (`-t 300`) and raise concurrency (`-c 2000`).
- **Internet targets**: keep the timeout around `1000`–`2000` ms so slow hosts aren't marked filtered.
- **Linux**: concurrency above ~1000 may hit the default open-file limit. Raise it with `ulimit -n 10000`.

---

## ⚠️ Limitations

- **This is a connect scan.** On open ports the target sees a completed TCP handshake, which services and firewalls may log.
- **No SYN ("half-open") scan.** That needs raw packets, and Windows has blocked sending raw TCP since XP SP2. A future version could add it through [Npcap](https://npcap.com/).
- **TCP only.** There's no UDP scanning.
- **One target per run.** CIDR ranges and host lists aren't supported yet.

## 🗺️ Roadmap

- [ ] CIDR / multi-host targets (`192.168.1.0/24`)
- [ ] SYN scan via Npcap (Windows) and raw sockets (Linux)
- [ ] JSON / CSV output
- [ ] UDP probes for common services (DNS, SNMP, NTP)
- [ ] Better service fingerprinting

---

## ⚖️ Legal

Riptide is for **network administration, learning, and authorized security testing**.
Only scan systems you own or have explicit permission to test. Unauthorized port scanning may break the law or your provider's terms of service where you live.

## 📄 License

MIT. Do what you like, just keep the copyright notice.
