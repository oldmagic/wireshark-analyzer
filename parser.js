const fs = require("fs");

async function parseWiresharkFile(filePath, onProgress) {
  // Read file with proper encoding detection
  const buffer = fs.readFileSync(filePath);
  let content;

  // Check for BOM and encoding
  if (buffer[0] === 0xff && buffer[1] === 0xfe) {
    console.log("Detected UTF-16 LE encoding");
    content = buffer.toString("utf16le").replace(/^\ufeff/, "");
  } else if (buffer[0] === 0xfe && buffer[1] === 0xff) {
    console.log("Detected UTF-16 BE encoding");
    content = buffer.swap16().toString("utf16le").replace(/^\ufeff/, "");
  } else if (buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf) {
    console.log("Detected UTF-8 with BOM");
    content = buffer.toString("utf8").replace(/^\ufeff/, "");
  } else {
    console.log("Assuming UTF-8 encoding");
    content = buffer.toString("utf8");
  }

  const lines = content.split(/\r?\n/);
  console.log(`Total lines in file: ${lines.length}`);

  // Detect format type
  const formatType = detectFormat(lines);
  console.log(`Detected format: ${formatType}`);

  let result;
  if (formatType === "wireshark-export") {
    result = parseWiresharkExportFormat(lines, onProgress);
  } else if (formatType === "tshark-verbose") {
    result = parseTsharkVerboseFormat(lines, onProgress);
  } else {
    result = parseGenericFormat(lines, onProgress);
  }

  return result;
}

// Detect which format the file is in
function detectFormat(lines) {
  const first100 = lines.slice(0, 100).join("\n");

  // Wireshark GUI export: has "No.     Time" header lines
  if (/^No\.\s+Time\s+Source/m.test(first100)) {
    return "wireshark-export";
  }

  // tshark -V format: starts with "Frame N:" with lots of indented details
  if (/^Frame\s+\d+:.*bytes on wire/m.test(first100)) {
    // Check for deep indentation (tshark -V style)
    if (/^\s{4,}.*:/m.test(first100)) {
      return "tshark-verbose";
    }
    return "wireshark-export";
  }

  return "generic";
}

// Parse Wireshark GUI Export format (with summary lines)
function parseWiresharkExportFormat(lines, onProgress) {
  console.log("Parsing Wireshark GUI export format...");

  const packets = [];
  const protocolStats = {};
  const ipStats = {};
  const conversations = {};
  const timelineBuckets = {};

  let currentPacket = null;
  let rawLines = [];
  let pendingSummary = null;

  // Pattern for summary line: "      1 0.000000       192.168.112.6         192.168.111.104       TLSv1.2  196    Application Data"
  const summaryPattern = /^\s*(\d+)\s+([\d.]+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(.*)$/;

  // Pattern for "No.     Time" header
  const headerPattern = /^No\.\s+Time\s+Source/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Progress
    if (i % 5000 === 0) {
      onProgress(Math.min(99, Math.floor((i / lines.length) * 100)));
    }

    // Skip header lines
    if (headerPattern.test(line)) {
      continue;
    }

    // Check for summary line
    const summaryMatch = line.match(summaryPattern);
    if (summaryMatch && !line.startsWith("Frame")) {
      // Save previous packet
      if (currentPacket) {
        currentPacket.raw = rawLines.join("\n");
        finalizePacket(currentPacket);
        packets.push(currentPacket);
        updateStats(currentPacket, protocolStats, ipStats, conversations, timelineBuckets);
      }

      // Create new packet from summary line
      currentPacket = {
        number: parseInt(summaryMatch[1]),
        time: summaryMatch[2],
        timeRaw: parseFloat(summaryMatch[2]),
        source: summaryMatch[3],
        destination: summaryMatch[4],
        protocol: summaryMatch[5],
        length: parseInt(summaryMatch[6]),
        info: summaryMatch[7].trim(),
        srcMac: "",
        dstMac: "",
        protocols: [],
        srcPort: null,
        dstPort: null,
        layers: [summaryMatch[5]],
        flags: [],
        tcpFlags: [],
        raw: "",
        ttl: null,
        streamIndex: null,
      };

      // Extract ports from info if available (e.g., "3389 → 58695 [ACK]")
      const portMatch = currentPacket.info.match(/(\d+)\s*(?:→|->)+\s*(\d+)/);
      if (portMatch) {
        currentPacket.srcPort = parseInt(portMatch[1]);
        currentPacket.dstPort = parseInt(portMatch[2]);
      }

      // Extract TCP flags from info
      const flagsMatch = currentPacket.info.match(/\[([A-Z,\s]+)\]/);
      if (flagsMatch) {
        currentPacket.tcpFlags = flagsMatch[1].split(",").map(f => f.trim()).filter(f => f);
      }

      rawLines = [line];
      continue;
    }

    // Frame line - add extra details
    const frameMatch = line.match(/^Frame\s+(\d+):/);
    if (frameMatch) {
      if (currentPacket && currentPacket.number === parseInt(frameMatch[1])) {
        rawLines.push(line);
      }
      continue;
    }

    // Collect additional details for current packet
    if (currentPacket) {
      rawLines.push(line);
      parseDetailLine(line, currentPacket);
    }
  }

  // Don't forget last packet
  if (currentPacket) {
    currentPacket.raw = rawLines.join("\n");
    finalizePacket(currentPacket);
    packets.push(currentPacket);
    updateStats(currentPacket, protocolStats, ipStats, conversations, timelineBuckets);
  }

  console.log(`Parsed ${packets.length} packets`);
  onProgress(100);

  return buildResult(packets, protocolStats, ipStats, conversations, timelineBuckets);
}

// Parse tshark -V format (verbose with deep indentation)
function parseTsharkVerboseFormat(lines, onProgress) {
  console.log("Parsing tshark verbose format...");

  const packets = [];
  const protocolStats = {};
  const ipStats = {};
  const conversations = {};
  const timelineBuckets = {};

  let currentPacket = null;
  let rawLines = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Progress
    if (i % 5000 === 0) {
      onProgress(Math.min(99, Math.floor((i / lines.length) * 100)));
    }

    // New frame/packet
    const frameMatch = line.match(/^Frame\s+(\d+):\s+.*?(\d+)\s+bytes/i);
    if (frameMatch) {
      // Save previous packet
      if (currentPacket) {
        currentPacket.raw = rawLines.join("\n");
        finalizePacket(currentPacket);
        packets.push(currentPacket);
        updateStats(currentPacket, protocolStats, ipStats, conversations, timelineBuckets);
      }

      currentPacket = {
        number: parseInt(frameMatch[1]),
        length: parseInt(frameMatch[2]),
        time: null,
        timeRaw: null,
        source: "",
        destination: "",
        srcMac: "",
        dstMac: "",
        protocol: "Unknown",
        protocols: [],
        srcPort: null,
        dstPort: null,
        info: "",
        layers: [],
        flags: [],
        tcpFlags: [],
        raw: "",
        ttl: null,
        streamIndex: null,
      };
      rawLines = [line];
      continue;
    }

    if (!currentPacket) continue;

    rawLines.push(line);
    parseDetailLine(line, currentPacket);
  }

  // Don't forget last packet
  if (currentPacket) {
    currentPacket.raw = rawLines.join("\n");
    finalizePacket(currentPacket);
    packets.push(currentPacket);
    updateStats(currentPacket, protocolStats, ipStats, conversations, timelineBuckets);
  }

  console.log(`Parsed ${packets.length} packets`);
  onProgress(100);

  return buildResult(packets, protocolStats, ipStats, conversations, timelineBuckets);
}

// Generic fallback parser
function parseGenericFormat(lines, onProgress) {
  console.log("Using generic parser...");
  return parseTsharkVerboseFormat(lines, onProgress);
}

// Parse a detail line and extract information
function parseDetailLine(line, packet) {
  // Arrival Time
  const arrivalMatch = line.match(/^\s*Arrival Time:\s*(.+)/i);
  if (arrivalMatch) {
    packet.time = arrivalMatch[1].trim();
  }

  // Epoch time
  const epochMatch = line.match(/^\s*Epoch Arrival Time:\s*([\d.]+)/i);
  if (epochMatch) {
    packet.timeRaw = parseFloat(epochMatch[1]);
  }

  // Frame Length fallback
  const frameLenMatch = line.match(/^\s*Frame Length:\s*(\d+)/i);
  if (frameLenMatch && !packet.length) {
    packet.length = parseInt(frameLenMatch[1]);
  }

  // Protocols in frame
  const protocolsMatch = line.match(/^\s*\[Protocols in frame:\s*([^\]]+)\]/i);
  if (protocolsMatch) {
    packet.protocols = protocolsMatch[1].split(":").map((p) => p.trim());
    packet.layers = packet.protocols.map(mapProtocol);
    if (packet.protocol === "Unknown") {
      packet.protocol = mapProtocol(packet.protocols[packet.protocols.length - 1]);
    }
  }

  // Ethernet header (one-line format)
  const ethMatch = line.match(
    /^Ethernet II,\s+Src:\s+([^\s(]+).*?,\s+Dst:\s+([^\s(]+)/i
  );
  if (ethMatch) {
    packet.srcMac = ethMatch[1];
    packet.dstMac = ethMatch[2];
  }

  // IPv4/IPv6 one-line format
  const ipLineMatch = line.match(
    /^Internet Protocol Version \d,\s+Src:\s+([^,]+),\s+Dst:\s+(.+)/i
  );
  if (ipLineMatch) {
    if (!packet.source) packet.source = ipLineMatch[1].trim();
    if (!packet.destination) packet.destination = ipLineMatch[2].trim();
  }

  // Source Address (indented detail)
  const srcAddrMatch = line.match(/^\s+Source(?: Address)?:\s+([0-9a-f.:]+)/i);
  if (srcAddrMatch && !packet.source) {
    packet.source = srcAddrMatch[1];
  }

  // Destination Address (indented detail)
  const dstAddrMatch = line.match(/^\s+Destination(?: Address)?:\s+([0-9a-f.:]+)/i);
  if (dstAddrMatch && !packet.destination) {
    packet.destination = dstAddrMatch[1];
  }

  // TCP one-line format
  const tcpLineMatch = line.match(
    /^Transmission Control Protocol,\s+Src Port:\s+(\d+),\s+Dst Port:\s+(\d+)/i
  );
  if (tcpLineMatch) {
    if (!packet.srcPort) packet.srcPort = parseInt(tcpLineMatch[1]);
    if (!packet.dstPort) packet.dstPort = parseInt(tcpLineMatch[2]);
    if (!packet.layers.includes("TCP")) packet.layers.push("TCP");
  }

  // UDP one-line format
  const udpLineMatch = line.match(
    /^User Datagram Protocol,\s+Src Port:\s+(\d+),\s+Dst Port:\s+(\d+)/i
  );
  if (udpLineMatch) {
    if (!packet.srcPort) packet.srcPort = parseInt(udpLineMatch[1]);
    if (!packet.dstPort) packet.dstPort = parseInt(udpLineMatch[2]);
    if (!packet.layers.includes("UDP")) packet.layers.push("UDP");
  }

  // Source Port (indented detail)
  const srcPortMatch = line.match(/^\s+Source Port:\s+(\d+)/i);
  if (srcPortMatch && !packet.srcPort) {
    packet.srcPort = parseInt(srcPortMatch[1]);
  }

  // Destination Port (indented detail)
  const dstPortMatch = line.match(/^\s+Destination Port:\s+(\d+)/i);
  if (dstPortMatch && !packet.dstPort) {
    packet.dstPort = parseInt(dstPortMatch[1]);
  }

  // TCP Flags (0x018 format)
  const flagsMatch = line.match(/^\s+Flags:\s+0x[0-9a-f]+\s+\(([^)]+)\)/i);
  if (flagsMatch && packet.tcpFlags.length === 0) {
    packet.tcpFlags = flagsMatch[1].split(",").map((f) => f.trim());
  }

  // TTL
  const ttlMatch = line.match(/^\s+Time to Live:\s+(\d+)/i);
  if (ttlMatch) {
    packet.ttl = parseInt(ttlMatch[1]);
  }

  // TLS/SSL
  const tlsMatch = line.match(/^\s*(TLSv[\d.]+|SSLv[\d.]+)\s+Record Layer:\s+(.+)/i);
  if (tlsMatch && !packet.info) {
    packet.info = `${tlsMatch[1]}: ${tlsMatch[2]}`;
  }

  // HTTP Request
  const httpReqMatch = line.match(/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s]+)\s+HTTP/i);
  if (httpReqMatch) {
    packet.info = `${httpReqMatch[1]} ${httpReqMatch[2]}`;
    packet.protocol = "HTTP";
  }

  // HTTP Response
  const httpRespMatch = line.match(/^HTTP\/[\d.]+\s+(\d+)\s+(.+)/i);
  if (httpRespMatch) {
    packet.info = `HTTP ${httpRespMatch[1]} ${httpRespMatch[2]}`;
    packet.protocol = "HTTP";
  }

  // DNS
  const dnsQueryMatch = line.match(/^\s+Name:\s+(\S+)/i);
  if (dnsQueryMatch && packet.protocols.includes("dns") && !packet.info) {
    packet.info = `DNS Query: ${dnsQueryMatch[1]}`;
  }

  // ARP
  const arpMatch = line.match(/^Address Resolution Protocol\s+\(([^)]+)\)/i);
  if (arpMatch) {
    packet.info = `ARP ${arpMatch[1]}`;
    packet.protocol = "ARP";
  }

  // ICMP type
  const icmpTypeMatch = line.match(/^\s+Type:\s+\d+\s+\(([^)]+)\)/i);
  if (icmpTypeMatch && (packet.protocols.includes("icmp") || packet.protocol === "ICMP")) {
    packet.info = `ICMP ${icmpTypeMatch[1]}`;
  }
}

// Map protocol shortnames to display names
function mapProtocol(proto) {
  if (!proto) return "Unknown";
  const p = proto.toLowerCase().trim();
  const mapping = {
    eth: "Ethernet",
    ethertype: "Ethernet",
    ip: "IP",
    ipv4: "IPv4",
    ipv6: "IPv6",
    tcp: "TCP",
    udp: "UDP",
    tls: "TLS",
    ssl: "SSL",
    http: "HTTP",
    https: "HTTPS",
    dns: "DNS",
    arp: "ARP",
    icmp: "ICMP",
    icmpv6: "ICMPv6",
    dhcp: "DHCP",
    ntp: "NTP",
    ssh: "SSH",
    ftp: "FTP",
    "ftp-data": "FTP-DATA",
    smtp: "SMTP",
    imap: "IMAP",
    pop: "POP3",
    sip: "SIP",
    rtp: "RTP",
    rtcp: "RTCP",
    snmp: "SNMP",
    ldap: "LDAP",
    smb: "SMB",
    smb2: "SMB2",
    nbss: "NetBIOS",
    nbns: "NBNS",
    rdp: "RDP",
    rdpudp: "RDPUDP",
    "ms-rdp": "RDP",
    data: "DATA",
    quic: "QUIC",
    websocket: "WebSocket",
    mqtt: "MQTT",
    amqp: "AMQP",
  };
  return mapping[p] || proto.toUpperCase();
}

// Finalize packet - ensure all fields have reasonable values
function finalizePacket(packet) {
  // Generate info if not set
  if (!packet.info) {
    if (packet.srcPort && packet.dstPort) {
      const flags = packet.tcpFlags.length ? ` [${packet.tcpFlags.join(", ")}]` : "";
      packet.info = `${packet.srcPort} → ${packet.dstPort}${flags}`;
    } else if (packet.protocol && packet.protocol !== "Unknown") {
      packet.info = packet.protocol;
    } else {
      packet.info = "";
    }
  }

  // Determine best protocol name if still unknown
  if (packet.protocol === "Unknown" && packet.layers.length > 0) {
    const priority = [
      "HTTP", "HTTPS", "TLS", "SSL", "DNS", "SSH", "RDP", "RDPUDP",
      "SMB", "SMB2", "FTP", "SMTP", "DHCP", "NTP", "QUIC", "WebSocket",
      "ICMP", "ARP", "TCP", "UDP", "IP", "IPv4", "IPv6",
    ];
    for (const p of priority) {
      if (packet.layers.includes(p)) {
        packet.protocol = p;
        break;
      }
    }
  }

  // Map protocol to consistent naming
  packet.protocol = mapProtocol(packet.protocol);
}

// Update statistics
function updateStats(packet, protocolStats, ipStats, conversations, timelineBuckets) {
  const proto = packet.protocol || "Unknown";

  // Protocol stats
  if (!protocolStats[proto]) {
    protocolStats[proto] = { count: 0, bytes: 0 };
  }
  protocolStats[proto].count++;
  protocolStats[proto].bytes += packet.length || 0;

  // IP stats
  if (packet.source) {
    if (!ipStats[packet.source]) {
      ipStats[packet.source] = { sent: 0, received: 0, packets: 0 };
    }
    ipStats[packet.source].sent += packet.length || 0;
    ipStats[packet.source].packets++;
  }

  if (packet.destination) {
    if (!ipStats[packet.destination]) {
      ipStats[packet.destination] = { sent: 0, received: 0, packets: 0 };
    }
    ipStats[packet.destination].received += packet.length || 0;
  }

  // Conversations
  if (packet.source && packet.destination) {
    const endpoints = [packet.source, packet.destination].sort().join(" ↔ ");
    if (!conversations[endpoints]) {
      conversations[endpoints] = {
        packets: 0,
        bytes: 0,
        protocols: new Set(),
        packetNumbers: [],
        dataSnippets: [],
      };
    }
    conversations[endpoints].packets++;
    conversations[endpoints].bytes += packet.length || 0;
    conversations[endpoints].protocols.add(packet.protocol);
    conversations[endpoints].packetNumbers.push(packet.number);

    // Collect data snippets (limit to prevent memory issues)
    if (conversations[endpoints].dataSnippets.length < 100) {
      conversations[endpoints].dataSnippets.push({
        num: packet.number,
        time: packet.time,
        src: packet.source,
        dst: packet.destination,
        srcPort: packet.srcPort,
        dstPort: packet.dstPort,
        protocol: packet.protocol,
        info: packet.info,
        flags: packet.tcpFlags,
        length: packet.length,
      });
    }
  }

  // Timeline
  if (packet.timeRaw !== null && packet.timeRaw !== undefined) {
    const bucket = Math.floor(packet.timeRaw);
    if (!timelineBuckets[bucket]) {
      timelineBuckets[bucket] = { count: 0 };
    }
    timelineBuckets[bucket].count++;
  }
}

// Build final result object
function buildResult(packets, protocolStats, ipStats, conversations, timelineBuckets) {
  // Top talkers
  const topTalkers = Object.entries(ipStats)
    .map(([ip, data]) => ({
      ip,
      sent: data.sent,
      received: data.received,
      total: data.sent + data.received,
      packets: data.packets,
    }))
    .sort((a, b) => b.total - a.total)
    .slice(0, 20);

  // Conversations list
  const conversationList = Object.entries(conversations)
    .map(([key, data]) => ({
      endpoints: key,
      packets: data.packets,
      bytes: data.bytes,
      protocols: [...data.protocols],
      packetNumbers: data.packetNumbers.slice(0, 100),
      dataSnippets: data.dataSnippets,
    }))
    .sort((a, b) => b.packets - a.packets)
    .slice(0, 100);

  // Timeline
  const timeline = Object.entries(timelineBuckets)
    .map(([time, data]) => ({ time: parseFloat(time), count: data.count }))
    .sort((a, b) => a.time - b.time);

  const normalizedTimeline = normalizeTimeline(timeline);

  return {
    packets,
    summary: {
      totalPackets: packets.length,
      totalBytes: packets.reduce((sum, p) => sum + (p.length || 0), 0),
      protocolStats: Object.entries(protocolStats)
        .map(([protocol, data]) => ({
          protocol,
          count: data.count,
          bytes: data.bytes,
          percentage: packets.length > 0
            ? ((data.count / packets.length) * 100).toFixed(2)
            : "0.00",
        }))
        .sort((a, b) => b.count - a.count),
      topTalkers,
      conversations: conversationList,
      timeline: normalizedTimeline,
      uniqueIPs: Object.keys(ipStats).length,
      startTime: packets[0]?.time || "N/A",
      endTime: packets[packets.length - 1]?.time || "N/A",
    },
  };
}

// Normalize timeline for display
function normalizeTimeline(timeline) {
  if (timeline.length === 0) return [];

  const startTime = timeline[0].time;
  return timeline.map((t) => ({
    time: (t.time - startTime).toFixed(1) + "s",
    count: t.count,
  }));
}

module.exports = { parseWiresharkFile };