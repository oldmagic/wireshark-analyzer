# Wireshark Packet Capture Parser

A Node.js library for parsing Wireshark and tshark exported packet capture files. It extracts packet details, generates statistics, and provides insights into network traffic.

## Features

- **Multi-format Support**: Automatically detects and parses:
  - Wireshark GUI exports (File → Export Packet Dissections → As Plain Text)
  - tshark verbose output (`tshark -V`)
  - Generic packet capture text formats

- **Encoding Detection**: Handles multiple file encodings:
  - UTF-8 (with and without BOM)
  - UTF-16 LE (Little Endian)
  - UTF-16 BE (Big Endian)

- **Comprehensive Packet Parsing**: Extracts:
  - Frame number, timestamp, and length
  - Source/Destination IP addresses
  - Source/Destination MAC addresses
  - Source/Destination ports
  - Protocol layers (Ethernet, IP, TCP, UDP, TLS, HTTP, DNS, etc.)
  - TCP flags (SYN, ACK, FIN, RST, etc.)
  - TTL (Time to Live)
  - Application-layer info (HTTP requests, DNS queries, TLS records, etc.)

- **Traffic Analysis & Statistics**:
  - **Protocol Distribution**: Packet count and byte usage per protocol
  - **Top Talkers**: Most active IP addresses by traffic volume
  - **Conversations**: Communication pairs with packet counts and data snippets
  - **Timeline**: Packets-per-second distribution over time

## Installation

```bash
npm install
```

## Usage

```javascript
const { parseWiresharkFile } = require("./wireshark-parser");

async function analyze() {
  const result = await parseWiresharkFile("capture.txt", (progress) => {
    console.log(`Parsing: ${progress}%`);
  });

  console.log(`Total Packets: ${result.summary.totalPackets}`);
  console.log(`Total Bytes: ${result.summary.totalBytes}`);
  console.log(`Unique IPs: ${result.summary.uniqueIPs}`);
  console.log(`Protocols:`, result.summary.protocolStats);
  console.log(`Top Talkers:`, result.summary.topTalkers);
}

analyze();
```

## Generating Compatible Input Files

### From Wireshark GUI
1. Open your `.pcap` or `.pcapng` file in Wireshark
2. Go to **File → Export Packet Dissections → As Plain Text**
3. Select "All packets" and check "Packet details"
4. Save the file

### From tshark (CLI)
```bash
# Verbose output with full packet details
tshark -r capture.pcap -V > capture.txt

# With specific fields
tshark -r capture.pcap -V -O tcp,http > capture.txt
```

## Output Structure

```javascript
{
  packets: [
    {
      number: 1,
      time: "2024-01-05 10:30:00.123456",
      timeRaw: 1704450600.123456,
      source: "192.168.1.100",
      destination: "192.168.1.1",
      srcPort: 54321,
      dstPort: 443,
      srcMac: "aa:bb:cc:dd:ee:ff",
      dstMac: "11:22:33:44:55:66",
      protocol: "TLS",
      length: 1500,
      info: "Application Data",
      layers: ["Ethernet", "IPv4", "TCP", "TLS"],
      tcpFlags: ["ACK", "PSH"],
      ttl: 64,
      raw: "..." // Original text from file
    },
    // ... more packets
  ],
  summary: {
    totalPackets: 1000,
    totalBytes: 1500000,
    uniqueIPs: 25,
    startTime: "2024-01-05 10:30:00",
    endTime: "2024-01-05 10:35:00",
    protocolStats: [
      { protocol: "TLS", count: 500, bytes: 750000, percentage: "50.00" },
      { protocol: "TCP", count: 300, bytes: 450000, percentage: "30.00" },
      // ...
    ],
    topTalkers: [
      { ip: "192.168.1.100", sent: 500000, received: 250000, total: 750000, packets: 400 },
      // ...
    ],
    conversations: [
      {
        endpoints: "192.168.1.1 ↔ 192.168.1.100",
        packets: 200,
        bytes: 300000,
        protocols: ["TCP", "TLS"],
        dataSnippets: [/* packet summaries */]
      },
      // ...
    ],
    timeline: [
      { time: "0.0s", count: 50 },
      { time: "1.0s", count: 75 },
      // ...
    ]
  }
}
```

## Supported Protocols

| Category       | Protocols                                      |
|----------------|------------------------------------------------|
| Link Layer     | Ethernet, ARP                                  |
| Network Layer  | IPv4, IPv6, ICMP, ICMPv6                       |
| Transport      | TCP, UDP, QUIC                                 |
| Security       | TLS, SSL, SSH                                  |
| Application    | HTTP, HTTPS, DNS, DHCP, NTP, FTP, SMTP, IMAP   |
| File Sharing   | SMB, SMB2, NetBIOS                             |
| Remote Access  | RDP, RDPUDP                                    |
| Messaging      | MQTT, AMQP, SIP, RTP, RTCP                     |
| Directory      | LDAP, SNMP                                     |
| Web            | WebSocket                                      |

## API Reference

### `parseWiresharkFile(filePath, onProgress)`

| Parameter    | Type       | Description                                           |
|--------------|------------|-------------------------------------------------------|
| `filePath`   | `string`   | Path to the exported Wireshark/tshark text file       |
| `onProgress` | `function` | Callback receiving progress percentage (0-100)        |

**Returns:** `Promise<Object>` containing `packets` array and `summary` object.

## Requirements

- Node.js 14.x or higher
- No external dependencies (uses only built-in `fs` module)

## License

MIT
