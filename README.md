lookTroughTunnel
Desktop Traffic Interceptor

**lookThrough** is a lightweight desktop application designed to **capture, log, and analyze network traffic** from any desktop application in real-time.  
Think of it as a بull of potential and extensible alternative to tools like **Wireshark** or **Burp Suite**, but optimized for **desktop apps traffic monitoring**.

---

Features
- **Real-time traffic interception** – capture packets directly from your selected network interface.  
- **Dynamic device switching** – change your active network device without restarting the program.  
- **Logging system** – view and store captured packets for later analysis.  
- **Lightweight C++ core** – built with `libpcap/Npcap` for high performance.  
- **Cross-platform ready** – designed to be portable and extendable.  

---

Getting Started

  Prerequisites
- [Npcap](https://nmap.org/npcap/) (for Windows) or `libpcap` (Linux/macOS)  
- A modern C++ compiler (MSVC, g++, clang++)  

  Build
```bash
git clone https://github.com/<your-username>/BSCore.git
cd BSCore
mkdir build && cd build
```
cmake ..
make
