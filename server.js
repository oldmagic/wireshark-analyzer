const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { parseWiresharkFile } = require("./parser");

const app = express();
const PORT = 3000;

// Ensure uploads directory exists
if (!fs.existsSync("./uploads")) {
  fs.mkdirSync("./uploads");
}

// Configure multer for large files
const storage = multer.diskStorage({
  destination: "./uploads/",
  filename: (req, file, cb) => {
    cb(null, `capture-${Date.now()}.txt`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 500 * 1024 * 1024 }, // 500MB limit
});

app.use(express.static("public"));
app.use(express.json());

// Store parsed data in memory (for demo; use DB for production)
let analysisData = null;
let parseProgress = 0;

// Upload and parse file
app.post("/api/upload", upload.single("capture"), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "No file uploaded" });
  }

  try {
    parseProgress = 0;
    const filePath = req.file.path;

    console.log(`Parsing file: ${filePath} (${req.file.size} bytes)`);

    analysisData = await parseWiresharkFile(filePath, (progress) => {
      parseProgress = progress;
    });

    // Clean up uploaded file
    fs.unlinkSync(filePath);

    res.json({
      success: true,
      summary: analysisData.summary,
      totalPackets: analysisData.packets.length,
    });
  } catch (error) {
    console.error("Parse error:", error);
    res.status(500).json({ error: error.message });
  }
});

// Get parse progress
app.get("/api/progress", (req, res) => {
  res.json({ progress: parseProgress });
});

// Get summary statistics
app.get("/api/summary", (req, res) => {
  if (!analysisData) {
    return res.status(404).json({ error: "No data loaded" });
  }
  res.json(analysisData.summary);
});

// Get packets with pagination
app.get("/api/packets", (req, res) => {
  if (!analysisData) {
    return res.status(404).json({ error: "No data loaded" });
  }

  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 100;
  const filter = req.query.filter || "";
  const protocol = req.query.protocol || "";

  let packets = analysisData.packets;

  // Apply filters
  if (protocol) {
    packets = packets.filter((p) =>
      p.protocol.toLowerCase().includes(protocol.toLowerCase())
    );
  }

  if (filter) {
    const filterLower = filter.toLowerCase();
    packets = packets.filter(
      (p) =>
        p.source.toLowerCase().includes(filterLower) ||
        p.destination.toLowerCase().includes(filterLower) ||
        p.info.toLowerCase().includes(filterLower)
    );
  }

  const start = (page - 1) * limit;
  const paginatedPackets = packets.slice(start, start + limit);

  res.json({
    packets: paginatedPackets,
    total: packets.length,
    page,
    totalPages: Math.ceil(packets.length / limit),
  });
});

// Get single packet details
app.get("/api/packets/:id", (req, res) => {
  if (!analysisData) {
    return res.status(404).json({ error: "No data loaded" });
  }

  const packet = analysisData.packets.find(
    (p) => p.number === parseInt(req.params.id)
  );

  if (!packet) {
    return res.status(404).json({ error: "Packet not found" });
  }

  res.json(packet);
});

// Get protocol statistics
app.get("/api/stats/protocols", (req, res) => {
  if (!analysisData) {
    return res.status(404).json({ error: "No data loaded" });
  }
  res.json(analysisData.summary.protocolStats);
});

// Get timeline data
app.get("/api/stats/timeline", (req, res) => {
  if (!analysisData) {
    return res.status(404).json({ error: "No data loaded" });
  }
  res.json(analysisData.summary.timeline);
});

// Get top talkers
app.get("/api/stats/talkers", (req, res) => {
  if (!analysisData) {
    return res.status(404).json({ error: "No data loaded" });
  }
  res.json(analysisData.summary.topTalkers);
});

// Get conversations
app.get("/api/conversations", (req, res) => {
  if (!analysisData) {
    return res.status(404).json({ error: "No data loaded" });
  }
  res.json(analysisData.summary.conversations);
});

app.listen(PORT, () => {
  console.log(`🚀 Wireshark Analyzer running at http://localhost:${PORT}`);
});