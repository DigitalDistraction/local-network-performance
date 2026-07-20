const express = require('express');
const { exec, spawn } = require('child_process');
const dns = require('dns').promises;
const path = require('path');
const crypto = require('crypto');
const dgram = require('dgram');
const fs = require('fs').promises;

const app = express();
const PORT = process.env.PORT || 3000;

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// Helper to execute commands and return a promise
function runCommand(command) {
  return new Promise((resolve, reject) => {
    exec(command, { maxBuffer: 1024 * 1024 * 5 }, (error, stdout, stderr) => {
      if (error) {
        reject(error);
      } else {
        resolve(stdout);
      }
    });
  });
}

// 1. IP and Adapter Info Diagnostics
app.get('/api/diagnostics', async (req, res) => {
  try {
    const ipconfigRaw = await runCommand('ipconfig /all');
    let wlanRaw = '';
    try {
      wlanRaw = await runCommand('netsh wlan show interfaces');
    } catch (e) {
      wlanRaw = 'Wi-Fi interface not available or disabled.';
    }

    const adapters = parseIpConfig(ipconfigRaw);
    const wifiInfo = parseNetshWlan(wlanRaw);
    
    // Fetch external IP info to get ISP (Frontier)
    let externalIpInfo = { isp: 'Unknown', query: 'Unknown', org: 'Unknown' };
    try {
      const response = await fetch('http://ip-api.com/json/');
      if (response.ok) {
        externalIpInfo = await response.json();
      }
    } catch (err) {
      console.error('Failed to fetch external IP info:', err.message);
    }

    res.json({
      success: true,
      adapters,
      wifi: wifiInfo,
      external: externalIpInfo
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 2. DNS Resolution Speed Shootout
app.post('/api/dns-benchmark', async (req, res) => {
  const { servers, domains } = req.body;
  
  if (!servers || !domains) {
    return res.status(400).json({ error: 'Please provide servers and domains arrays' });
  }

  try {
    const results = [];
    for (const server of servers) {
      const result = await benchmarkDNS(server.ip, server.name, domains);
      results.push(result);
    }
    res.json({ success: true, results });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 3. Adaptive Streaming Speed Test - Download
app.get('/api/speedtest/download', async (req, res) => {
  // Use Cloudflare's speedtest file (100MB max, aborted at 5 seconds)
  const downloadUrl = 'https://speed.cloudflare.com/__down?bytes=100000000';
  const controller = new AbortController();
  const timeoutId = setTimeout(() => {
    controller.abort();
  }, 5000); // Limit speed test to 5 seconds

  let bytesDownloaded = 0;
  const startTime = Date.now();

  try {
    const response = await fetch(downloadUrl, { signal: controller.signal });
    if (!response.ok) throw new Error('Cloudflare speedtest endpoint failed');
    
    for await (const chunk of response.body) {
      bytesDownloaded += chunk.length;
    }
  } catch (err) {
    // If aborted, that's expected
    if (err.name !== 'AbortError') {
      clearTimeout(timeoutId);
      return res.status(500).json({ success: false, error: err.message });
    }
  } finally {
    clearTimeout(timeoutId);
  }

  const durationMs = Date.now() - startTime;
  const durationSec = durationMs / 1000;
  const speedMbps = ((bytesDownloaded * 8) / (1024 * 1024)) / durationSec;

  res.json({
    success: true,
    bytesDownloaded,
    durationMs,
    speedMbps: parseFloat(speedMbps.toFixed(2))
  });
});

// 4. Streaming Speed Test - Upload
app.post('/api/speedtest/upload', async (req, res) => {
  const { downloadSpeedMbps } = req.body;
  
  // Adaptive chunk size based on download speed (Frontier Fiber can be very fast)
  let bufferSize = 5 * 1024 * 1024; // Default 5MB
  if (downloadSpeedMbps > 500) {
    bufferSize = 25 * 1024 * 1024; // 25MB for high speed fiber
  } else if (downloadSpeedMbps > 200) {
    bufferSize = 15 * 1024 * 1024; // 15MB
  } else if (downloadSpeedMbps < 50) {
    bufferSize = 2 * 1024 * 1024;  // 2MB for slower connections
  }

  const buffer = crypto.randomBytes(bufferSize);
  let bytesUploaded = 0;
  const startTime = Date.now();
  
  // We upload in loops for up to 5 seconds
  try {
    while (Date.now() - startTime < 5000) {
      const resUpload = await fetch('https://speed.cloudflare.com/__up', {
        method: 'POST',
        body: buffer,
        headers: { 'Content-Type': 'application/octet-stream' }
      });
      await resUpload.text(); // Consume response
      bytesUploaded += buffer.length;
    }
  } catch (err) {
    console.error('Upload warning:', err.message);
  }

  const durationMs = Date.now() - startTime;
  const durationSec = durationMs / 1000;
  const speedMbps = ((bytesUploaded * 8) / (1024 * 1024)) / durationSec;

  res.json({
    success: true,
    bytesUploaded,
    durationMs,
    speedMbps: parseFloat(speedMbps.toFixed(2))
  });
});

// 5. Ping & Jitter API
app.get('/api/ping-test', async (req, res) => {
  const target = req.query.target || '1.1.1.1';
  
  // Input Sanitization: Only allow valid hostnames or IP addresses (alphanumeric, dots, dashes)
  if (!/^[a-zA-Z0-9.-]+$/.test(target) || target.length > 253) {
    return res.status(400).json({ success: false, error: 'Invalid target hostname or IP address' });
  }

  try {
    // Run 8 pings to calculate jitter and packet loss
    const pingRaw = await runCommand(`ping -n 8 ${target}`);
    const pingResults = parsePing(pingRaw);
    res.json({ success: true, target, ...pingResults });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 6. Real-time Traceroute (SSE)
app.get('/api/traceroute', (req, res) => {
  const target = req.query.target || '1.1.1.1';
  
  // Input Sanitization: Only allow valid hostnames or IP addresses
  if (!/^[a-zA-Z0-9.-]+$/.test(target) || target.length > 253) {
    return res.status(400).json({ success: false, error: 'Invalid target hostname or IP address' });
  }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  // -d: Do not resolve addresses to hostnames
  // -h 15: Max 15 hops for speed
  const tracert = spawn('tracert', ['-d', '-h', '15', target]);

  tracert.stdout.on('data', (data) => {
    const lines = data.toString().split('\r\n');
    for (const line of lines) {
      if (line.trim()) {
        res.write(`data: ${JSON.stringify({ line: line.trim() })}\n\n`);
      }
    }
  });

  tracert.stderr.on('data', (data) => {
    res.write(`data: ${JSON.stringify({ error: data.toString().trim() })}\n\n`);
  });

  tracert.on('close', () => {
    res.write('data: [DONE]\n\n');
    res.end();
  });

  req.on('close', () => {
    tracert.kill();
  });
});

// Helper to encode a service name for mDNS binary query
function encodeName(name) {
  const parts = name.split('.');
  const buffers = parts.map(part => {
    const buf = Buffer.alloc(1 + part.length);
    buf.writeUInt8(part.length, 0);
    buf.write(part, 1);
    return buf;
  });
  return Buffer.concat([...buffers, Buffer.from([0])]);
}

// mDNS Smart Home Scan API
app.get('/api/iot-scan', async (req, res) => {
  const client = dgram.createSocket('udp4');
  const discovered = [];

  client.on('message', (msg, rinfo) => {
    const rawStr = msg.toString('ascii');
    let deviceType = null;
    let name = 'Smart Home Device';
    
    if (rawStr.includes('_meshcop')) {
      deviceType = 'Thread Border Router / Nest Wifi Pro';
      name = 'Nest Wifi Pro Node';
    } else if (rawStr.includes('_matter')) {
      deviceType = 'Matter Smart Device';
      const match = rawStr.match(/([A-Za-z0-9-]+)\._matter/);
      name = match ? match[1] : 'Matter Endpoint';
    } else if (rawStr.includes('_googlecast')) {
      deviceType = 'Google Nest Hub / Cast Device';
      const match = rawStr.match(/fn=([^'\x00-\x1f]+)/);
      name = match ? match[1] : 'Google Hub / Cast';
    } else if (rawStr.includes('_hap')) {
      deviceType = 'Apple HomeKit Accessory';
      const match = rawStr.match(/md=([^'\x00-\x1f]+)/);
      name = match ? match[1] : 'HomeKit Device';
    } else if (rawStr.includes('_spotify-connect')) {
      deviceType = 'Spotify Speaker';
      name = 'Spotify Cast Speaker';
    }

    if (deviceType) {
      const entry = {
        name,
        ip: rinfo.address,
        type: deviceType
      };

      if (!discovered.some(d => d.ip === entry.ip && d.type === entry.type)) {
        discovered.push(entry);
      }
    }
  });

  client.bind(0, () => {
    try {
      client.setMulticastTTL(255);
      
      const header = Buffer.alloc(12);
      header.writeUInt16BE(0, 0); // ID
      header.writeUInt16BE(0, 2); // Flags
      header.writeUInt16BE(4, 4); // 4 questions
      
      const q1 = Buffer.concat([encodeName('_meshcop._udp.local'), Buffer.from([0, 0x0c, 0, 0x01])]);
      const q2 = Buffer.concat([encodeName('_matter._tcp.local'), Buffer.from([0, 0x0c, 0, 0x01])]);
      const q3 = Buffer.concat([encodeName('_googlecast._tcp.local'), Buffer.from([0, 0x0c, 0, 0x01])]);
      const q4 = Buffer.concat([encodeName('_hap._tcp.local'), Buffer.from([0, 0x0c, 0, 0x01])]);
      
      const packet = Buffer.concat([header, q1, q2, q3, q4]);
      
      client.send(packet, 0, packet.length, 5353, '224.0.0.251', (err) => {
        if (err) console.error('mDNS scan send error:', err);
      });
    } catch (err) {
      console.error('mDNS setup fail:', err);
    }
  });

  // Limit scan duration to 2.5 seconds
  setTimeout(() => {
    try {
      client.close();
    } catch (e) {}
    res.json({ success: true, count: discovered.length, devices: discovered });
  }, 2500);
});

// --- SPEED TEST HISTORY STORAGE ---
const HISTORY_FILE = path.join(__dirname, 'history.json');

async function readHistory() {
  try {
    const data = await fs.readFile(HISTORY_FILE, 'utf8');
    return JSON.parse(data);
  } catch (e) {
    return [];
  }
}

async function writeHistory(history) {
  try {
    await fs.writeFile(HISTORY_FILE, JSON.stringify(history, null, 2), 'utf8');
  } catch (e) {
    console.error('Failed to save history:', e.message);
  }
}

// GET Speed Test History
app.get('/api/history', async (req, res) => {
  const history = await readHistory();
  res.json({ success: true, history });
});

// POST Record Speed Test Run
app.post('/api/history', async (req, res) => {
  const entry = {
    id: Date.now().toString(),
    timestamp: new Date().toISOString(),
    ...req.body
  };
  const history = await readHistory();
  history.unshift(entry); // Add newest first
  if (history.length > 50) history.pop(); // Max 50 items
  await writeHistory(history);
  res.json({ success: true, entry, history });
});

// DELETE Speed Test History
app.delete('/api/history', async (req, res) => {
  await writeHistory([]);
  res.json({ success: true, history: [] });
});

// --- DNS LEAK DETECTOR ---
app.get('/api/dns-leak', async (req, res) => {
  try {
    const ednsRes = await fetch('https://edns.ip-api.com/json');
    let ednsData = {};
    if (ednsRes.ok) {
      ednsData = await ednsRes.json();
    }

    const dnsServerIp = ednsData.dns?.ip || 'Unknown';
    const dnsServerGeo = ednsData.dns?.geo || 'Unknown Resolver';

    let dnsIspInfo = { isp: dnsServerGeo, org: dnsServerGeo, country: 'Unknown' };
    if (dnsServerIp !== 'Unknown') {
      try {
        const ipRes = await fetch(`http://ip-api.com/json/${dnsServerIp}`);
        if (ipRes.ok) {
          dnsIspInfo = await ipRes.json();
        }
      } catch (e) {}
    }

    const resolverOrg = (dnsIspInfo.org || dnsIspInfo.isp || dnsServerGeo).toLowerCase();
    const isFrontier = resolverOrg.includes('frontier');
    
    let detectedProvider = 'Custom / Router Default DNS';
    if (resolverOrg.includes('cloudflare')) detectedProvider = 'Cloudflare DNS';
    else if (resolverOrg.includes('google')) detectedProvider = 'Google Public DNS';
    else if (resolverOrg.includes('cisco') || resolverOrg.includes('opendns')) detectedProvider = 'OpenDNS (Cisco)';
    else if (resolverOrg.includes('quad9')) detectedProvider = 'Quad9 DNS';
    else if (resolverOrg.includes('adguard')) detectedProvider = 'AdGuard DNS';
    else if (isFrontier) detectedProvider = 'Frontier ISP Default DNS';

    res.json({
      success: true,
      resolverIp: dnsServerIp,
      resolverOrg: dnsIspInfo.org || dnsIspInfo.isp || dnsServerGeo,
      country: dnsIspInfo.country || 'United States',
      provider: detectedProvider,
      isLeakingToIsp: isFrontier
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Start the server (bind strictly to 127.0.0.1 for local security)
app.listen(PORT, '127.0.0.1', () => {
  console.log(`Server is running at http://127.0.0.1:${PORT}`);
});

/* ==========================================
   HELPER PARSING FUNCTIONS
   ========================================== */

function parseIpConfig(text) {
  const lines = text.split(/\r?\n/);
  const adapters = [];
  let currentAdapter = null;
  let currentKey = null;

  for (const line of lines) {
    if (!line.trim()) continue;

    // Check for Adapter headers (no indentation, ends in ':')
    if (line.match(/^[^\s].*:/)) {
      if (currentAdapter) {
        adapters.push(currentAdapter);
      }
      currentAdapter = {
        name: line.replace(/:$/, '').trim(),
        details: {}
      };
      currentKey = null;
      continue;
    }

    if (currentAdapter) {
      // Look for keys like "IPv4 Address . . . . . . . . . . . : 192.168.86.100(Preferred)"
      const match = line.match(/^\s{3,8}([^.:]+?)\s*[\s.]*\.+\s*:\s*(.*)$/);
      if (match) {
        const key = match[1].trim();
        let val = match[2].trim();
        // Clean preferred tags
        if (key.includes('IP') && val.includes('Preferred')) {
          val = val.replace('(Preferred)', '').trim();
        }
        currentAdapter.details[key] = val;
        currentKey = key;
      } else if (currentKey && line.startsWith(' '.repeat(8))) {
        // Multi-line value (e.g. multiple DNS servers)
        const val = line.trim();
        if (Array.isArray(currentAdapter.details[currentKey])) {
          currentAdapter.details[currentKey].push(val);
        } else {
          currentAdapter.details[currentKey] = [currentAdapter.details[currentKey], val];
        }
      }
    }
  }
  if (currentAdapter) {
    adapters.push(currentAdapter);
  }
  return adapters;
}

function parseNetshWlan(text) {
  const lines = text.split(/\r?\n/);
  const wlanInfo = {};
  for (const line of lines) {
    const match = line.match(/^\s*([^:]+?)\s*:\s*(.*)$/);
    if (match) {
      const key = match[1].trim();
      const val = match[2].trim();
      wlanInfo[key] = val;
    }
  }
  return wlanInfo;
}

function parsePing(text) {
  const lines = text.split(/\r?\n/);
  const replies = [];
  let min = null, max = null, avg = null, lossPercent = 0;

  for (const line of lines) {
    // Parse single reply: e.g. "Reply from 1.1.1.1: bytes=32 time=5ms TTL=57"
    // Also support IPv6 reply format: "Reply from 2606:4700:4700::1111: time=6ms"
    const replyMatch = line.match(/time[=<](\d+)ms/i);
    if (replyMatch) {
      replies.push(parseInt(replyMatch[1]));
    }

    // Parse packet loss percentage: "Lost = 0 (0% loss)"
    const lossMatch = line.match(/Lost\s*=\s*\d+\s*\((\d+)%\s*loss\)/i);
    if (lossMatch) {
      lossPercent = parseInt(lossMatch[1]);
    }

    // Parse approximate RTT: "Minimum = 5ms, Maximum = 8ms, Average = 6ms"
    const rttMatch = line.match(/Minimum\s*=\s*(\d+)ms,\s*Maximum\s*=\s*(\d+)ms,\s*Average\s*=\s*(\d+)ms/i);
    if (rttMatch) {
      min = parseInt(rttMatch[1]);
      max = parseInt(rttMatch[2]);
      avg = parseInt(rttMatch[3]);
    }
  }

  // Calculate Jitter manually based on consecutive RTT differences
  let jitter = 0;
  if (replies.length > 1) {
    let diffSum = 0;
    for (let i = 1; i < replies.length; i++) {
      diffSum += Math.abs(replies[i] - replies[i - 1]);
    }
    jitter = parseFloat((diffSum / (replies.length - 1)).toFixed(2));
  }

  // Fallbacks if RTT matching failed but we got replies
  if (replies.length > 0 && avg === null) {
    min = Math.min(...replies);
    max = Math.max(...replies);
    avg = Math.round(replies.reduce((a, b) => a + b, 0) / replies.length);
  }

  return {
    replies,
    lossPercent,
    min,
    max,
    avg,
    jitter
  };
}

async function benchmarkDNS(dnsServer, serverName, domains) {
  const resolver = new dns.Resolver();
  resolver.setServers([dnsServer]);
  
  let totalTime = 0;
  let successCount = 0;
  const details = [];

  for (const domain of domains) {
    const start = performance.now();
    try {
      await resolver.resolve4(domain);
      const end = performance.now();
      const duration = end - start;
      totalTime += duration;
      successCount++;
      details.push({ domain, timeMs: Math.round(duration), success: true });
    } catch (err) {
      details.push({ domain, timeMs: null, success: false, error: err.message });
    }
  }

  return {
    name: serverName,
    ip: dnsServer,
    averageMs: successCount > 0 ? Math.round(totalTime / successCount) : 9999, // high fallback for display
    successRate: Math.round((successCount / domains.length) * 100),
    details
  };
}
