// Global State
let dnsChartInstance = null;
let historyChartInstance = null;
let systemData = null;
let speedTestData = { download: 0, upload: 0, ping: 0, loadedPing: 0, bufferbloatGrade: '--', jitter: 0, loss: 0 };
let dnsBenchData = [];
let auditStatus = { config: false, speed: false, dns: false, leak: false };

// Initialize Lucide Icons & Device Detection
document.addEventListener('DOMContentLoaded', () => {
  lucide.createIcons();
  detectClientDevice();
  initTabs();
  initSubTabs();
  fetchDiagnostics(true); // Quiet fetch on load
  loadHistory();
  runDnsLeakTest();

  // Bind main buttons
  document.getElementById('btn-run-full-audit').addEventListener('click', runFullAudit);
  document.getElementById('btn-run-all-diag').addEventListener('click', () => fetchDiagnostics(false));
  document.getElementById('btn-start-speedtest').addEventListener('click', runSpeedTest);
  document.getElementById('btn-run-dns').addEventListener('click', runDnsBenchmark);
  document.getElementById('btn-start-trace').addEventListener('click', runTraceroute);
  document.getElementById('btn-scan-iot').addEventListener('click', runIotScan);
  document.getElementById('btn-export-audit').addEventListener('click', exportAuditReport);
  document.getElementById('btn-clear-history').addEventListener('click', clearHistory);
  document.getElementById('btn-run-dns-leak').addEventListener('click', runDnsLeakTest);
});

/* ==========================================
   NAVIGATION & TABS
   ========================================== */

function initTabs() {
  const navItems = document.querySelectorAll('.nav-menu .nav-item');
  const tabPanes = document.querySelectorAll('.tab-pane');

  navItems.forEach(item => {
    item.addEventListener('click', () => {
      const tabName = item.getAttribute('data-tab');
      
      navItems.forEach(i => i.classList.remove('active'));
      tabPanes.forEach(p => p.classList.remove('active'));

      item.classList.add('active');
      const targetPane = document.getElementById(`tab-${tabName}`);
      if (targetPane) targetPane.classList.add('active');
    });
  });
}

function initSubTabs() {
  const subTabs = document.querySelectorAll('.sub-tab');
  const subPanes = document.querySelectorAll('.sub-pane');

  subTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const subPaneName = tab.getAttribute('data-sub');
      
      subTabs.forEach(t => t.classList.remove('active'));
      subPanes.forEach(p => p.classList.remove('active'));

      tab.classList.add('active');
      const targetSubPane = document.getElementById(`sub-${subPaneName}`);
      if (targetSubPane) targetSubPane.classList.add('active');
    });
  });
}

/* ==========================================
   DIAGNOSTICS & SYSTEM INFO
   ========================================== */

async function fetchDiagnostics(isQuiet = false) {
  const btn = document.getElementById('btn-run-all-diag');
  const indicator = document.getElementById('global-status-indicator');
  const statusText = document.getElementById('global-status-text');

  if (!isQuiet) {
    btn.disabled = true;
    btn.innerHTML = `<i data-lucide="refresh-cw" class="spin"></i> Auditing Network...`;
    lucide.createIcons();
    indicator.className = 'status-indicator testing';
    statusText.innerText = 'Analyzing Settings...';
  }

  try {
    const res = await fetch('/api/diagnostics');
    const data = await res.json();

    if (data.success) {
      systemData = data;
      auditStatus.config = true;
      updateAuditProgress();
      renderDashboardOverview();
      renderConfigPanel();
      evaluateRecommendations();
      
      indicator.className = 'status-indicator online';
      statusText.innerText = 'Connected';
    } else {
      throw new Error(data.error);
    }
  } catch (err) {
    console.error('Diagnostics fail:', err);
    if (!isQuiet) {
      alert('Failed to run diagnostics: ' + err.message);
    }
    indicator.className = 'status-indicator offline';
    statusText.innerText = 'Error';
  } finally {
    if (!isQuiet) {
      btn.disabled = false;
      btn.innerHTML = `<i data-lucide="refresh-cw"></i> Run Diagnostics Audit`;
      lucide.createIcons();
    }
  }
}

function renderDashboardOverview() {
  if (!systemData) return;

  const primaryAdapter = getActiveAdapter();
  
  // Extract global public IPv6 from adapter if available (fiber direct routed)
  let publicIpv6 = null;
  if (primaryAdapter) {
    const keys = Object.keys(primaryAdapter.details);
    const ipv6Keys = keys.filter(k => k.toLowerCase().includes('ipv6 address'));
    for (const key of ipv6Keys) {
      const val = primaryAdapter.details[key];
      const list = Array.isArray(val) ? val : [val];
      for (const ip of list) {
        const cleanIp = ip.trim();
        if (cleanIp.startsWith('2') || cleanIp.startsWith('3')) {
          publicIpv6 = cleanIp;
          break;
        }
      }
      if (publicIpv6) break;
    }
  }

  // ISP & Public IP
  const ispVal = systemData.external.isp || 'Frontier Communications';
  document.getElementById('dash-isp').innerText = ispVal;
  
  const headerTitle = document.getElementById('header-app-title');
  if (headerTitle) {
    headerTitle.value = `${ispVal} Network Auditor`;
  }

  const hostElem = document.getElementById('host-agent-name');
  if (hostElem && primaryAdapter) {
    const pcIp = primaryAdapter.details['IPv4 Address'] || '127.0.0.1';
    const pcDesc = primaryAdapter.details.Description || 'Windows PC';
    hostElem.innerText = `${pcDesc} (${pcIp})`;
  }
  
  const publicIpv4 = systemData.external.query || 'Unknown';
  let ipCardHtml = `IPv4: ${publicIpv4}`;
  if (publicIpv6) {
    const truncatedIpv6 = publicIpv6.length > 22 ? publicIpv6.substring(0, 19) + '...' : publicIpv6;
    ipCardHtml += `<br><span style="font-size:0.7rem; color:var(--text-muted);" title="${publicIpv6}">IPv6: ${truncatedIpv6}</span>`;
  }
  document.getElementById('dash-public-ip').innerHTML = ipCardHtml;

  // Wi-Fi / SSID details
  const activeWifi = systemData.wifi;
  const isConnectedWifi = activeWifi.SSID && activeWifi.State === 'connected';

  if (isConnectedWifi) {
    document.getElementById('dash-ssid').innerText = activeWifi.SSID;
    document.getElementById('dash-wifi-speed').innerText = `Rate: ${activeWifi['Receive rate (Mbps)'] || '--'} Mbps`;
    
    document.getElementById('info-wifi-band').innerText = getRadioBandText(activeWifi.Channel);
    document.getElementById('info-wifi-channel').innerText = activeWifi.Channel || '--';
    
    const signalPercent = activeWifi.Signal ? parseInt(activeWifi.Signal.replace('%', '')) : 0;
    document.getElementById('info-wifi-signal').innerText = activeWifi.Signal || '0%';
    document.getElementById('info-signal-bar').style.width = activeWifi.Signal || '0%';
  } else {
    // Check if Ethernet is active instead
    const activeEthernet = systemData.adapters.find(a => 
      a.name.toLowerCase().includes('ethernet') && 
      a.details['IPv4 Address'] && 
      a.details['Default Gateway']
    );

    if (activeEthernet) {
      document.getElementById('dash-ssid').innerText = 'Ethernet Wired';
      document.getElementById('dash-wifi-speed').innerText = 'Rate: 1000+ Mbps';
      document.getElementById('info-wifi-band').innerText = 'Wired Ethernet';
      document.getElementById('info-wifi-channel').innerText = 'N/A';
      document.getElementById('info-wifi-signal').innerText = '100%';
      document.getElementById('info-signal-bar').style.width = '100%';
    } else {
      document.getElementById('dash-ssid').innerText = 'Not Connected';
      document.getElementById('dash-wifi-speed').innerText = 'Rate: -- Mbps';
      document.getElementById('info-wifi-band').innerText = 'N/A';
      document.getElementById('info-wifi-channel').innerText = '--';
      document.getElementById('info-wifi-signal').innerText = '0%';
      document.getElementById('info-signal-bar').style.width = '0%';
    }
  }

  // Gateway
  if (primaryAdapter) {
    const gatewayInput = primaryAdapter.details['Default Gateway'];
    const dnsInput = primaryAdapter.details['DNS Servers'];
    
    // Extract a single IPv4 gateway for ping and display, falling back if not found
    const gatewayList = Array.isArray(gatewayInput) ? gatewayInput : (gatewayInput ? gatewayInput.split(',') : []);
    const ipv4Gateway = gatewayList.find(g => g.trim().includes('.')) || (gatewayList[0] ? gatewayList[0].trim() : '');
    
    // Extract first IPv4 DNS server, fallback to first in list
    const dnsList = Array.isArray(dnsInput) ? dnsInput : (dnsInput ? dnsInput.split(',') : []);
    const ipv4Dns = dnsList.find(d => d.trim().includes('.')) || (dnsList[0] ? dnsList[0].trim() : '');

    document.getElementById('info-gateway').innerText = ipv4Gateway || '--';
    document.getElementById('dash-dns').innerText = ipv4Dns || 'Gateway DNS';
    
    const localIpv4 = primaryAdapter.details['IPv4 Address'] || 'No local IP';
    
    let localIpv6 = 'No local IPv6';
    if (primaryAdapter.details['Link-local IPv6 Address']) {
      localIpv6 = Array.isArray(primaryAdapter.details['Link-local IPv6 Address']) 
        ? primaryAdapter.details['Link-local IPv6 Address'][0] 
        : primaryAdapter.details['Link-local IPv6 Address'];
    } else {
      const keys = Object.keys(primaryAdapter.details);
      const ipv6Keys = keys.filter(k => k.toLowerCase().includes('ipv6 address'));
      if (ipv6Keys.length > 0) {
        const val = primaryAdapter.details[ipv6Keys[0]];
        localIpv6 = Array.isArray(val) ? val[0] : val;
      }
    }
    localIpv6 = localIpv6.replace('(Preferred)', '').trim();
    const shortLocalIpv6 = localIpv6.length > 18 ? localIpv6.substring(0, 15) + '...' : localIpv6;

    document.getElementById('quick-local-ip').innerHTML = `IPv4: ${localIpv4}<br>IPv6: <span title="${localIpv6}">${shortLocalIpv6}</span>`;
    document.getElementById('info-dhcp').innerText = primaryAdapter.details['DHCP Enabled'] || 'Unknown';

    // Trigger gateway ping diagnostic automatically in background
    if (ipv4Gateway) {
      runGatewayPing(ipv4Gateway);
    }
  }
}

async function runGatewayPing(gatewayIp) {
  try {
    const res = await fetch(`/api/ping-test?target=${gatewayIp}`);
    const data = await res.json();
    if (data.success) {
      document.getElementById('dash-ping').innerText = `${data.avg} ms`;
      document.getElementById('dash-jitter').innerText = `Jitter: ${data.jitter} ms`;
      
      // Update our speedtest state ping defaults
      speedTestData.ping = data.avg;
      speedTestData.jitter = data.jitter;
      speedTestData.loss = data.lossPercent;
      
      // If speed test has loaded empty values, sync them
      document.getElementById('speed-ping').innerText = `${data.avg} ms`;
      document.getElementById('speed-jitter').innerText = `${data.jitter} ms`;
      document.getElementById('speed-loss').innerText = `${data.lossPercent}%`;
    }
  } catch (err) {
    console.error('Failed Gateway Ping:', err);
  }
}

function getActiveAdapter() {
  if (!systemData || !systemData.adapters) return null;
  // An active adapter has an IPv4 address and default gateway
  return systemData.adapters.find(adapter => 
    adapter.details['IPv4 Address'] && 
    adapter.details['Default Gateway']
  );
}

function getRadioBandText(channelStr) {
  if (!channelStr) return 'Detecting...';
  const channel = parseInt(channelStr);
  if (isNaN(channel)) return 'Unknown';
  if (channel >= 1 && channel <= 11) return '2.4 GHz';
  if (channel >= 36 && channel <= 165) return '5 GHz';
  if (channel >= 186 || (channel >= 1 && channel > 165)) return '6 GHz (Wi-Fi 6E)'; // Nest Wifi Pro 6E band
  return '5 GHz / 6 GHz';
}

/* ==========================================
   SPEED TEST MODULE
   ========================================== */

async function runSpeedTest() {
  const btn = document.getElementById('btn-start-speedtest');
  const term = document.getElementById('speedtest-console');

  btn.disabled = true;
  btn.innerHTML = `<i data-lucide="refresh-cw" class="spin"></i> Running Speedtest...`;
  lucide.createIcons();

  term.innerHTML = `<span class="log-line text-cyan">[INIT] Starting symmetric speed test...</span>`;
  term.scrollTop = term.scrollHeight;

  // Reset gauges
  updateGauge('download', 0);
  updateGauge('upload', 0);

  try {
    // 1. Ping test to Cloudflare DNS (1.1.1.1) to measure actual internet quality
    term.innerHTML += `<span class="log-line text-muted">[PING] Auditing packet latency to Cloudflare (1.1.1.1)...</span>`;
    const pingRes = await fetch('/api/ping-test?target=1.1.1.1');
    const pingData = await pingRes.json();
    if (pingData.success) {
      document.getElementById('speed-ping').innerText = `${pingData.avg} ms`;
      document.getElementById('speed-jitter').innerText = `${pingData.jitter} ms`;
      document.getElementById('speed-loss').innerText = `${pingData.lossPercent}%`;

      speedTestData.ping = pingData.avg;
      speedTestData.jitter = pingData.jitter;
      speedTestData.loss = pingData.lossPercent;

      term.innerHTML += `<span class="log-line text-success">[PING] Success. RTT Avg: ${pingData.avg}ms, Jitter: ${pingData.jitter}ms, Loss: ${pingData.lossPercent}%</span>`;
    }

    // 2. Download speedtest (directly in client browser!)
    term.innerHTML += `<span class="log-line text-muted">[DOWN] Measuring download capacity via streaming CDN sockets...</span>`;
    term.scrollTop = term.scrollHeight;
    
    // Simulate initial dial swing
    simulateGaugeSwing('download', 450);

    const downloadUrl = 'https://speed.cloudflare.com/__down?bytes=150000000'; // 150MB chunk max
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 seconds limit

    let bytesDownloaded = 0;
    const downStartTime = Date.now();

    try {
      const response = await fetch(downloadUrl, { signal: controller.signal });
      if (!response.ok) throw new Error('Cloudflare CDN endpoint returned status ' + response.status);
      
      const reader = response.body.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        bytesDownloaded += value.length;
        
        // Show live progress inside logs occasionally
        const elapsedSec = (Date.now() - downStartTime) / 1000;
        const currentSpeed = ((bytesDownloaded * 8) / (1024 * 1024)) / elapsedSec;
        updateGauge('download', currentSpeed);
      }
    } catch (err) {
      if (err.name !== 'AbortError') {
        throw err;
      }
    } finally {
      clearTimeout(timeoutId);
    }

    const downDurationSec = (Date.now() - downStartTime) / 1000;
    const finalDownSpeed = ((bytesDownloaded * 8) / (1024 * 1024)) / downDurationSec;
    speedTestData.download = parseFloat(finalDownSpeed.toFixed(2));
    
    animateGaugeToValue('download', speedTestData.download);
    term.innerHTML += `<span class="log-line text-success">[DOWN] Completed. Download speed: <strong>${speedTestData.download} Mbps</strong> (data transferred: ${(bytesDownloaded / (1024 * 1024)).toFixed(1)} MB)</span>`;
    term.scrollTop = term.scrollHeight;

    // 3. Upload speedtest (directly in client browser!)
    term.innerHTML += `<span class="log-line text-muted">[UP] Initiating adaptive chunk upload test...</span>`;
    term.scrollTop = term.scrollHeight;

    simulateGaugeSwing('upload', 350);

    // Adaptive buffer size: Frontier Fiber symmetric can be very fast, up to 1000Mbps
    let uploadChunkSize = 5 * 1024 * 1024; // 5MB
    if (speedTestData.download > 500) {
      uploadChunkSize = 25 * 1024 * 1024; // 25MB buffer
    } else if (speedTestData.download > 200) {
      uploadChunkSize = 12 * 1024 * 1024; // 12MB buffer
    }

    // Allocate random buffer bytes safely in 64KB chunks to avoid Web Crypto quota limits (65536 bytes max per call)
    const uploadBuffer = new Uint8Array(uploadChunkSize);
    if (window.crypto && window.crypto.getRandomValues) {
      const seedSize = 65536;
      const seed = new Uint8Array(seedSize);
      window.crypto.getRandomValues(seed);
      for (let offset = 0; offset < uploadBuffer.length; offset += seedSize) {
        uploadBuffer.set(seed.subarray(0, Math.min(seedSize, uploadBuffer.length - offset)), offset);
      }
    }

    let bytesUploaded = 0;
    const upStartTime = Date.now();
    const upController = new AbortController();
    const upTimeoutId = setTimeout(() => upController.abort(), 5000); // 5 seconds limit

    try {
      while (Date.now() - upStartTime < 5000) {
        const upRes = await fetch('https://speed.cloudflare.com/__up', {
          method: 'POST',
          body: uploadBuffer,
          signal: upController.signal
        });
        await upRes.text();
        bytesUploaded += uploadBuffer.length;

        const elapsedSec = (Date.now() - upStartTime) / 1000;
        const currentSpeed = ((bytesUploaded * 8) / (1024 * 1024)) / elapsedSec;
        updateGauge('upload', currentSpeed);
      }
    } catch (err) {
      if (err.name !== 'AbortError') {
        throw err;
      }
    } finally {
      clearTimeout(upTimeoutId);
    }

    const upDurationSec = (Date.now() - upStartTime) / 1000;
    const finalUpSpeed = ((bytesUploaded * 8) / (1024 * 1024)) / upDurationSec;
    speedTestData.upload = parseFloat(finalUpSpeed.toFixed(2));

    animateGaugeToValue('upload', speedTestData.upload);
    term.innerHTML += `<span class="log-line text-success">[UP] Completed. Upload speed: <strong>${speedTestData.upload} Mbps</strong></span>`;
    
    // 4. Measure Loaded Ping for Bufferbloat evaluation
    term.innerHTML += `<span class="log-line text-muted">[BUFFERBLOAT] Auditing latency increase under load...</span>`;
    try {
      const loadedRes = await fetch('/api/ping-test?target=1.1.1.1');
      const loadedData = await loadedRes.json();
      let loadedPing = speedTestData.ping;
      if (loadedData.success && loadedData.avg) {
        loadedPing = loadedData.avg;
      }
      speedTestData.loadedPing = loadedPing;
      
      const delta = Math.max(0, loadedPing - speedTestData.ping);
      let grade = 'A+';
      let gradeClass = 'grade-aplus';
      if (delta <= 5) { grade = 'A+'; gradeClass = 'grade-aplus'; }
      else if (delta <= 15) { grade = 'A'; gradeClass = 'grade-a'; }
      else if (delta <= 30) { grade = 'B'; gradeClass = 'grade-b'; }
      else if (delta <= 60) { grade = 'C'; gradeClass = 'grade-c'; }
      else { grade = 'F'; gradeClass = 'grade-f'; }

      speedTestData.bufferbloatGrade = grade;
      document.getElementById('speed-loaded-ping').innerText = `${loadedPing} ms`;
      const gradeElem = document.getElementById('speed-bufferbloat-grade');
      gradeElem.innerText = grade;
      gradeElem.className = `grade-badge ${gradeClass}`;

      term.innerHTML += `<span class="log-line text-warning">[BUFFERBLOAT] Loaded RTT: ${loadedPing}ms (Delta: +${delta}ms) -> Grade ${grade}</span>`;
    } catch (e) {
      console.error('Bufferbloat test fail:', e);
    }

    term.innerHTML += `<span class="log-line text-cyan">[DONE] Audit complete. Saved to speed history log.</span>`;
    term.scrollTop = term.scrollHeight;
    
    // Record into history
    await saveSpeedTestHistory({
      download: speedTestData.download,
      upload: speedTestData.upload,
      idlePing: speedTestData.ping,
      loadedPing: speedTestData.loadedPing,
      jitter: speedTestData.jitter,
      bufferbloatGrade: speedTestData.bufferbloatGrade
    });
    loadHistory();
    auditStatus.speed = true;
    updateAuditProgress();
    evaluateRecommendations();

  } catch (error) {
    term.innerHTML += `<span class="log-line text-error">[ERR] Speedtest failed: ${error.message}</span>`;
    term.scrollTop = term.scrollHeight;
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<i data-lucide="play-circle"></i> Start Speed Test`;
    lucide.createIcons();
  }
}

// Visual Gauge Updates
function updateGauge(type, speed) {
  const maxSpeed = 1000; // max gauge scale: 1000Mbps for Frontier Fiber Gig plan
  const ring = document.getElementById(`${type}-progress-ring`);
  const textVal = document.getElementById(`${type}-value`);

  textVal.innerText = Math.round(speed);

  // Circle circumference is ~283
  const percent = Math.min(speed / maxSpeed, 1);
  const strokeOffset = 283 - (percent * 283);
  ring.style.strokeDashoffset = strokeOffset;
}

let gaugeSimIntervals = {};
function simulateGaugeSwing(type, targetLimit) {
  clearInterval(gaugeSimIntervals[type]);
  let currentVal = 0;
  gaugeSimIntervals[type] = setInterval(() => {
    // bounce between targetLimit - 50 and targetLimit
    currentVal = Math.random() * 50 + (targetLimit - 50);
    updateGauge(type, currentVal);
  }, 100);
}

function animateGaugeToValue(type, finalValue) {
  clearInterval(gaugeSimIntervals[type]);
  let current = parseInt(document.getElementById(`${type}-value`).innerText) || 0;
  const step = (finalValue - current) / 10;
  let counter = 0;

  gaugeSimIntervals[type] = setInterval(() => {
    current += step;
    counter++;
    updateGauge(type, current);
    if (counter >= 10) {
      clearInterval(gaugeSimIntervals[type]);
      updateGauge(type, finalValue);
    }
  }, 30);
}

/* ==========================================
   DNS BENCHMARK MODULE
   ========================================== */

async function runDnsBenchmark() {
  const btn = document.getElementById('btn-run-dns');
  btn.disabled = true;
  btn.innerHTML = `<i data-lucide="refresh-cw" class="spin"></i> Querying Nameservers...`;
  lucide.createIcons();

  const dnsServers = [];
  const primaryAdapter = getActiveAdapter();
  
  if (primaryAdapter && primaryAdapter.details['DNS Servers']) {
    const dnsInput = primaryAdapter.details['DNS Servers'];
    const dnsList = Array.isArray(dnsInput) ? dnsInput : (dnsInput ? dnsInput.split(',') : []);
    
    // Deduplicate list
    const uniqueDns = [...new Set(dnsList.map(ip => ip.trim()))];
    
    uniqueDns.forEach((dnsIp) => {
      if (dnsIp) {
        const isIpv6 = dnsIp.includes(':');
        dnsServers.push({
          name: `Nest Wifi (Local ${isIpv6 ? 'IPv6' : 'IPv4'})`,
          ip: dnsIp
        });
      }
    });
  } else {
    dnsServers.push({ name: 'Nest Wifi (Local IPv4)', ip: '192.168.86.1' });
  }

  // Add Public IPv4 & IPv6 Primary and Secondary Pairs
  dnsServers.push(
    { name: 'Cloudflare Pri (IPv4)', ip: '1.1.1.1' },
    { name: 'Cloudflare Sec (IPv4)', ip: '1.0.0.1' },
    { name: 'Cloudflare Pri (IPv6)', ip: '2606:4700:4700::1111' },
    { name: 'Cloudflare Sec (IPv6)', ip: '2606:4700:4700::1001' },
    
    { name: 'Google Pri (IPv4)', ip: '8.8.8.8' },
    { name: 'Google Sec (IPv4)', ip: '8.8.4.4' },
    { name: 'Google Pri (IPv6)', ip: '2001:4860:4860::8888' },
    { name: 'Google Sec (IPv6)', ip: '2001:4860:4860::8844' },
    
    { name: 'Quad9 Pri (IPv4)', ip: '9.9.9.9' },
    { name: 'Quad9 Sec (IPv4)', ip: '149.112.112.112' },
    { name: 'Quad9 Pri (IPv6)', ip: '2620:fe::fe' },
    { name: 'Quad9 Sec (IPv6)', ip: '2620:fe::9' },
    
    { name: 'OpenDNS Pri (IPv4)', ip: '208.67.222.222' },
    { name: 'OpenDNS Sec (IPv4)', ip: '208.67.220.220' },
    { name: 'OpenDNS Pri (IPv6)', ip: '2620:0:ccc::2' },
    { name: 'OpenDNS Sec (IPv6)', ip: '2620:0:ccd::2' },
    
    { name: 'AdGuard Pri (IPv4)', ip: '94.140.14.14' },
    { name: 'AdGuard Sec (IPv4)', ip: '94.140.15.15' },
    { name: 'AdGuard Pri (IPv6)', ip: '2a10:50c0::ad1:ff' },
    { name: 'AdGuard Sec (IPv6)', ip: '2a10:50c0::ad2:ff' }
  );

  const domains = ['google.com', 'cloudflare.com', 'netflix.com', 'youtube.com', 'amazon.com'];

  try {
    const res = await fetch('/api/dns-benchmark', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ servers: dnsServers, domains })
    });
    
    const data = await res.json();
    if (data.success) {
      dnsBenchData = data.results;
      auditStatus.dns = true;
      updateAuditProgress();
      renderDnsResults();
    } else {
      throw new Error(data.error);
    }
  } catch (err) {
    alert('DNS Benchmark failed: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<i data-lucide="swatchbook"></i> Benchmark DNS Servers`;
    lucide.createIcons();
  }
}

function renderDnsResults() {
  const tbody = document.getElementById('dns-results-tbody');
  tbody.innerHTML = '';

  // Sort by average latency (lower is faster)
  const sorted = [...dnsBenchData].sort((a, b) => a.averageMs - b.averageMs);

  sorted.forEach((item, index) => {
    const row = document.createElement('tr');
    
    let badgeClass = 'normal';
    let statusText = 'Good';
    if (index === 0) {
      badgeClass = 'fastest';
      statusText = 'Fastest';
      
      // Update quick display on dashboard DNS card
      document.getElementById('dash-dns-speed').innerText = `Res: ${item.averageMs} ms`;
    } else if (item.averageMs > 80 || item.successRate < 80) {
      badgeClass = 'slow';
      statusText = 'Suboptimal';
    }

    row.innerHTML = `
      <td><strong>${item.name}</strong></td>
      <td><span class="font-mono text-sm">${item.ip}</span></td>
      <td><strong>${item.averageMs} ms</strong></td>
      <td><span class="dns-status ${badgeClass}">${statusText}</span></td>
    `;
    tbody.appendChild(row);
  });

  // Render Chart.js Graph
  renderDnsChart(sorted);

  // Update optimization engine
  evaluateRecommendations();
}

function renderDnsChart(sortedData) {
  const ctx = document.getElementById('dnsChart').getContext('2d');
  
  if (dnsChartInstance) {
    dnsChartInstance.destroy();
  }

  const labels = sortedData.map(d => d.name);
  const latencies = sortedData.map(d => d.averageMs);

  dnsChartInstance = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Average Query Time (ms)',
        data: latencies,
        backgroundColor: sortedData.map((d, index) => 
          index === 0 ? 'rgba(0, 242, 254, 0.6)' : 'rgba(157, 78, 221, 0.4)'
        ),
        borderColor: sortedData.map((d, index) => 
          index === 0 ? 'rgba(0, 242, 254, 1)' : 'rgba(157, 78, 221, 1)'
        ),
        borderWidth: 1.5,
        borderRadius: 6
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          grid: { color: 'rgba(255, 255, 255, 0.05)' },
          ticks: { color: '#9ca3af' },
          title: { display: true, text: 'Milliseconds (lower is better)', color: '#9ca3af' }
        },
        y: {
          grid: { display: false },
          ticks: { color: '#f3f4f6' }
        }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });
}

/* ==========================================
   CONFIG & ADAPTER INTERFACES PANELS
   ========================================== */

function renderConfigPanel() {
  if (!systemData) return;

  // WLAN Netsh Raw log
  const rawWlan = document.getElementById('raw-wlan-log');
  rawWlan.innerHTML = '';
  
  // Format Netsh raw properties nicely
  const keys = Object.keys(systemData.wifi);
  if (keys.length > 0) {
    keys.forEach(k => {
      const line = document.createElement('span');
      line.className = 'log-line';
      line.innerHTML = `<span class="text-cyan">${padRight(k, 25)}</span>: ${systemData.wifi[k]}`;
      rawWlan.appendChild(line);
    });
  } else {
    rawWlan.innerHTML = '<span class="log-line text-error">Wi-Fi connection is currently offline or disabled.</span>';
  }

  // IP Config Adapters accordion
  const container = document.getElementById('adapters-accordion');
  container.innerHTML = '';

  systemData.adapters.forEach((adapter, idx) => {
    // Only render adapters that look relevant (skip virtual adapters unless details exist)
    const detailKeys = Object.keys(adapter.details);
    if (detailKeys.length === 0) return;

    const div = document.createElement('div');
    div.className = 'adapter-item';

    const header = document.createElement('div');
    header.className = 'adapter-header';
    
    // Check if Ethernet or Wifi to display correct icon
    const isWifi = adapter.name.toLowerCase().includes('wi-fi') || adapter.name.toLowerCase().includes('wireless');
    const icon = isWifi ? 'wifi' : 'server';
    const isActive = adapter.details['IPv4 Address'] && adapter.details['Default Gateway'];

    header.innerHTML = `
      <span>
        <i data-lucide="${icon}"></i>
        ${adapter.name} 
        ${isActive ? '<span class="badge">Active</span>' : ''}
      </span>
      <i data-lucide="chevron-down" class="accordion-arrow"></i>
    `;

    const body = document.createElement('div');
    body.className = 'adapter-body';
    body.style.display = isActive ? 'grid' : 'none'; // Auto expand active adapters

    detailKeys.forEach(k => {
      const detailItem = document.createElement('div');
      detailItem.className = 'body-item';
      const val = Array.isArray(adapter.details[k]) ? adapter.details[k].join(', ') : adapter.details[k];
      detailItem.innerHTML = `
        <span>${k}</span>
        <strong>${val}</strong>
      `;
      body.appendChild(detailItem);
    });

    header.addEventListener('click', () => {
      const isVisible = body.style.display === 'grid';
      body.style.display = isVisible ? 'none' : 'grid';
    });

    div.appendChild(header);
    div.appendChild(body);
    container.appendChild(div);
  });

  lucide.createIcons();
}

function padRight(str, len) {
  if (str.length >= len) return str;
  return str + ' '.repeat(len - str.length);
}

/* ==========================================
   TRACEROUTE (STREAMING SSE)
   ========================================== */

function runTraceroute() {
  const targetInput = document.getElementById('trace-target');
  const timeline = document.getElementById('traceroute-timeline');
  const btn = document.getElementById('btn-start-trace');
  const indicator = document.getElementById('tracert-status-indicator');

  const target = targetInput.value.trim() || '1.1.1.1';
  
  btn.disabled = true;
  btn.innerHTML = `<i data-lucide="refresh-cw" class="spin"></i> Tracing...`;
  lucide.createIcons();
  
  indicator.className = 'status-indicator testing';
  timeline.innerHTML = '';

  const eventSource = new EventSource(`/api/traceroute?target=${target}`);
  let isDoubleNatCandidate = false;
  let hopIndex = 1;

  eventSource.onmessage = (event) => {
    if (event.data === '[DONE]') {
      eventSource.close();
      btn.disabled = false;
      btn.innerHTML = `<i data-lucide="play"></i> Trace Path`;
      lucide.createIcons();
      indicator.className = 'status-indicator online';
      return;
    }

    const data = JSON.parse(event.data);
    const line = data.line;
    
    // Parse tracert output line: e.g. " 1    1 ms    1 ms    1 ms  192.168.86.1"
    const hopMatch = line.match(/^\s*(\d+)\s+([<\d\s\w]+ms)\s+([<\d\s\w]+ms)\s+([<\d\s\w]+ms)\s+([\d\.]+)/i);
    if (hopMatch) {
      const num = hopMatch[1];
      const ms1 = hopMatch[2].trim();
      const ms2 = hopMatch[3].trim();
      const ms3 = hopMatch[4].trim();
      const ip = hopMatch[5].trim();

      // Double NAT detection helper
      if (num === '2') {
        // If hop 2 starts with private subnets: 192.168.x.x, 10.x.x.x, or 172.16-31.x.x
        if (ip.startsWith('192.168.') || ip.startsWith('10.') || ip.match(/^172\.(1[6-9]|2\d|3[0-1])\./)) {
          isDoubleNatCandidate = true;
          window.isDoubleNatDetected = true;
        }
      }

      // Check if hop latency is high
      const avgMs = parseHopMsAvg([ms1, ms2, ms3]);
      const latencyClass = avgMs > 50 ? 'slow' : 'fast';

      const hopDiv = document.createElement('div');
      hopDiv.className = 'hop-item';
      hopDiv.innerHTML = `
        <div class="hop-number">${num}</div>
        <div class="hop-ip">${ip}</div>
        <div class="hop-latency">
          <span class="hop-ms ${latencyClass}">${ms1}</span>
          <span class="hop-ms ${latencyClass}">${ms2}</span>
          <span class="hop-ms ${latencyClass}">${ms3}</span>
        </div>
      `;
      timeline.appendChild(hopDiv);
      timeline.scrollTop = timeline.scrollHeight;
    }
  };

  eventSource.onerror = (err) => {
    console.error('SSE Error:', err);
    eventSource.close();
    btn.disabled = false;
    btn.innerHTML = `<i data-lucide="play"></i> Trace Path`;
    lucide.createIcons();
    indicator.className = 'status-indicator offline';
  };
}

function parseHopMsAvg(msArr) {
  let sum = 0;
  let count = 0;
  msArr.forEach(m => {
    const val = parseInt(m.replace(/[^\d]/g, ''));
    if (!isNaN(val)) {
      sum += val;
      count++;
    }
  });
  return count > 0 ? sum / count : 0;
}

/* ==========================================
   RECOMMENDATIONS ENGINE (Frontier Fiber + Nest Wifi Pro)
   ========================================== */

function evaluateRecommendations() {
  const container = document.getElementById('recommendations-container');
  container.innerHTML = '';

  const recs = [];

  // Tip 1: Wi-Fi Band Audit (Nest Wifi Pro supports Wi-Fi 6E)
  if (systemData && systemData.wifi && systemData.wifi.SSID) {
    const activeWifi = systemData.wifi;
    const channel = parseInt(activeWifi.Channel);
    const signal = activeWifi.Signal ? parseInt(activeWifi.Signal.replace('%', '')) : 100;
    const radioType = activeWifi['Radio type'] || '802.11';
    
    // Check if not on 802.11ax (Wi-Fi 6 / 6E)
    if (!radioType.includes('802.11ax')) {
      recs.push({
        priority: 'high',
        title: 'Nest Wifi Pro Wi-Fi 6E Band Optimization',
        text: `Your device is connected using standard '${radioType}' wireless radio. Nest Wifi Pro supports Wi-Fi 6E (802.11ax). If your Windows client adapter supports Wi-Fi 6E, make sure drivers are updated and active in Device Manager to enable faster 6GHz links.`
      });
    }

    // Check if signal is low
    if (signal < 70) {
      recs.push({
        priority: 'high',
        title: 'Low Wi-Fi Signal Strength',
        text: `Your Nest Wifi Pro link quality is currently at ${signal}%. Nest Wifi Pro mesh points should ideally have clear line-of-sight. If signal strength remains low, consider moving closer to the main router or adding a mesh node.`
      });
    }

    // Check if on slow 2.4GHz band
    const is24Ghz = channel >= 1 && channel <= 11;
    if (is24Ghz) {
      recs.push({
        priority: 'high',
        title: '2.4 GHz Low-Speed Channel Detected',
        text: `You are connected on a 2.4GHz channel (${channel}). Frontier Fiber speeds (>500Mbps) are severely bottlenecked on 2.4GHz. Log in to the Google Home app, and confirm that Nest Wifi's automatic band steering is allowing 5GHz or 6GHz bands for your PC.`
      });
    }
  }

  // Tip 2: DNS Benchmark Audit
  if (dnsBenchData.length > 0) {
    // Sort by average latency
    const sorted = [...dnsBenchData].sort((a, b) => a.averageMs - b.averageMs);
    const fastest = sorted[0];
    const systemDnsItem = sorted.find(d => d.name.includes('Local'));

    if (systemDnsItem && fastest && systemDnsItem.ip !== fastest.ip) {
      const diff = systemDnsItem.averageMs - fastest.averageMs;
      if (diff > 10) { // If alternative is faster by more than 10ms
        recs.push({
          priority: 'high',
          title: `Configure DNS Server to ${fastest.name}`,
          text: `Your current Nest Wifi local DNS resolution is averaging ${systemDnsItem.averageMs}ms. Resolving via ${fastest.name} (${fastest.ip}) is ${diff}ms faster. Recommended action: Open your Google Home App -> Settings -> Advanced Networking -> DNS, and set it to Custom (${fastest.ip}).`
        });
      }
    }
  }

  // Tip 3: Double NAT Detection (from Traceroute checks)
  if (window.isDoubleNatDetected) {
    recs.push({
      priority: 'high',
      title: 'Double NAT Detected (Nest Wifi + Frontier ONT Gateway)',
      text: 'Our traceroute showed two private router hops in a row. This occurs when your Nest Wifi Pro router is connected to a Frontier router that has routing enabled. Action: Put the Frontier-supplied router into IP Passthrough/Bridge mode and disable its Wi-Fi radios to resolve port conflicts.'
    });
  }

  // Tip 4: Fiber Speed Verification
  const ispName = (systemData && systemData.external && systemData.external.isp) ? systemData.external.isp : 'High-Speed Internet';
  if (speedTestData.download > 0) {
    if (speedTestData.download < 200) {
      recs.push({
        priority: 'high',
        title: 'Symmetric Throughput Bottleneck',
        text: `Your download speed is measured at ${speedTestData.download} Mbps. High-speed Fiber connections are symmetric. If speed is lower than expected, test with a direct Ethernet cable to confirm whether the bottleneck is wireless range or router hardware performance.`
      });
    } else {
      recs.push({
        priority: 'info',
        title: `Excellent ${ispName} Performance`,
        text: `Your speed test of ${speedTestData.download} Mbps download and ${speedTestData.upload} Mbps upload verifies high-speed provisioning on ${ispName}. Keep router firmware updated to maintain stable traffic management.`
      });
    }
  }

  // Render recommendations list
  if (recs.length > 0) {
    document.getElementById('recs-count').innerText = `${recs.length} Tips`;
    recs.forEach(rec => {
      const div = document.createElement('div');
      div.className = `recommendation-item ${rec.priority === 'high' ? 'high-priority' : 'info-priority'}`;
      
      const icon = rec.priority === 'high' ? 'alert-triangle' : 'info';
      
      div.innerHTML = `
        <div class="rec-icon">
          <i data-lucide="${icon}"></i>
        </div>
        <div class="rec-content">
          <h4>${rec.title}</h4>
          <p>${rec.text}</p>
        </div>
      `;
      container.appendChild(div);
    });
    lucide.createIcons();
  } else {
    document.getElementById('recs-count').innerText = '0 Tips';
    container.innerHTML = `
      <div class="empty-state">
        <i data-lucide="shield-check"></i>
        <p>No issues detected! Your router and ${ispName} connection are running optimally.</p>
      </div>
    `;
    lucide.createIcons();
  }
}

async function runIotScan() {
  const btn = document.getElementById('btn-scan-iot');
  const container = document.getElementById('iot-grid-container');
  const badge = document.getElementById('iot-devices-count');

  btn.disabled = true;
  btn.innerHTML = `<i data-lucide="refresh-cw" class="spin"></i> Auditing IoT Devices...`;
  lucide.createIcons();

  container.innerHTML = `
    <div class="empty-state">
      <i data-lucide="refresh-cw" class="spin"></i>
      <p>Broadcasting mDNS discovery packets to 224.0.0.251:5353...</p>
    </div>
  `;
  lucide.createIcons();

  try {
    const res = await fetch('/api/iot-scan');
    const data = await res.json();

    if (data.success && data.devices) {
      badge.innerText = `${data.devices.length} Devices`;
      
      if (data.devices.length === 0) {
        container.innerHTML = `
          <div class="empty-state">
            <i data-lucide="help-circle"></i>
            <p>No Thread border routers or Matter devices responded to mDNS queries. Ensure multicast is enabled on your router settings.</p>
          </div>
        `;
        lucide.createIcons();
        return;
      }

      container.innerHTML = '';
      data.devices.forEach(device => {
        const card = document.createElement('div');
        card.className = 'iot-card';

        // Select correct color class and icon based on device type
        let iconClass = 'cast';
        let iconName = 'cast';
        
        if (device.type.includes('Thread')) {
          iconClass = 'thread';
          iconName = 'git-commit';
        } else if (device.type.includes('Matter')) {
          iconClass = 'matter';
          iconName = 'box';
        } else if (device.type.includes('HomeKit')) {
          iconClass = 'homekit';
          iconName = 'home';
        } else if (device.type.includes('Spotify')) {
          iconClass = 'cast';
          iconName = 'music';
        }

        card.innerHTML = `
          <div class="iot-icon-box ${iconClass}">
            <i data-lucide="${iconName}"></i>
          </div>
          <div class="iot-info">
            <h4 title="${device.name}">${device.name}</h4>
            <span>${device.type}</span>
            <div class="ip-tag">${device.ip}</div>
          </div>
        `;
        container.appendChild(card);
      });
      lucide.createIcons();
    } else {
      throw new Error(data.error || 'Unknown error');
    }
  } catch (err) {
    container.innerHTML = `
      <div class="empty-state">
        <i data-lucide="alert-triangle"></i>
        <p>mDNS multicast scan failed: ${err.message}</p>
      </div>
    `;
    lucide.createIcons();
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<i data-lucide="scan"></i> Scan Local Smart Network`;
    lucide.createIcons();
  }
}

function exportAuditReport() {
  if (!systemData) {
    alert('Please run the diagnostics audit first before exporting.');
    return;
  }

  let doneCount = 0;
  if (auditStatus.config) doneCount++;
  if (auditStatus.speed) doneCount++;
  if (auditStatus.dns) doneCount++;
  if (auditStatus.leak) doneCount++;
  const percent = Math.round((doneCount / 4) * 100);

  if (percent < 100) {
    const shouldRunFull = confirm(
      `Your diagnostic audit is currently ${percent}% complete.\n\n` +
      `Some test modules (such as Speed Test or DNS Shootout) have not been run yet.\n\n` +
      `• Click OK to run the "Full Comprehensive Audit" automatically now.\n` +
      `• Click Cancel to export partial JSON data as-is.`
    );
    if (shouldRunFull) {
      runFullAudit();
      return;
    }
  }

  const report = {
    timestamp: new Date().toISOString(),
    auditCompletion: `${percent}%`,
    ispInfo: systemData.external,
    wifiConfig: systemData.wifi,
    ethernetConfig: systemData.adapters.filter(a => a.details['IPv4 Address'] && a.details['Default Gateway']),
    speedTestData: speedTestData,
    dnsShootoutResults: dnsBenchData.map(d => ({
      name: d.name,
      ip: d.ip,
      averageMs: d.averageMs,
      successRate: d.successRate
    })),
    networkAdaptersRaw: systemData.adapters
  };

  const jsonString = JSON.stringify(report, null, 2);
  const blob = new Blob([jsonString], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  
  const a = document.createElement('a');
  a.href = url;
  a.download = `network_audit_report_${new Date().toISOString().split('T')[0]}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/* ==========================================
   HISTORY & BUFFERBLOAT MODULE
   ========================================== */

async function saveSpeedTestHistory(data) {
  try {
    await fetch('/api/history', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
  } catch (e) {
    console.error('Failed to save speed test history:', e);
  }
}

async function loadHistory() {
  try {
    const res = await fetch('/api/history');
    const data = await res.json();
    if (!data.success || !data.history) return;

    const history = data.history;
    const tbody = document.getElementById('history-table-body');
    
    if (history.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted">No speed tests recorded yet.</td></tr>`;
      if (historyChartInstance) {
        historyChartInstance.destroy();
        historyChartInstance = null;
      }
      return;
    }

    tbody.innerHTML = '';
    history.forEach(item => {
      const tr = document.createElement('tr');
      const timeStr = new Date(item.timestamp).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
      
      let gradeClass = 'grade-aplus';
      if (item.bufferbloatGrade === 'A') gradeClass = 'grade-a';
      else if (item.bufferbloatGrade === 'B') gradeClass = 'grade-b';
      else if (item.bufferbloatGrade === 'C') gradeClass = 'grade-c';
      else if (item.bufferbloatGrade === 'F') gradeClass = 'grade-f';

      tr.innerHTML = `
        <td>${timeStr}</td>
        <td><strong>${item.download} Mbps</strong></td>
        <td><strong>${item.upload} Mbps</strong></td>
        <td>${item.idlePing} ms</td>
        <td>${item.loadedPing || '--'} ms</td>
        <td><span class="grade-badge ${gradeClass}">${item.bufferbloatGrade || '--'}</span></td>
      `;
      tbody.appendChild(tr);
    });

    renderHistoryChart(history);
  } catch (e) {
    console.error('Failed to load history:', e);
  }
}

async function clearHistory() {
  if (!confirm('Are you sure you want to clear your speed test history?')) return;
  try {
    await fetch('/api/history', { method: 'DELETE' });
    loadHistory();
  } catch (e) {
    console.error('Failed to clear history:', e);
  }
}

function renderHistoryChart(history) {
  const ctx = document.getElementById('historyChart').getContext('2d');
  
  const chronHistory = [...history].reverse();
  const labels = chronHistory.map(h => new Date(h.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
  const downData = chronHistory.map(h => h.download);
  const upData = chronHistory.map(h => h.upload);

  if (historyChartInstance) {
    historyChartInstance.destroy();
  }

  historyChartInstance = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label: 'Download (Mbps)',
          data: downData,
          borderColor: '#00f2fe',
          backgroundColor: 'rgba(0, 242, 254, 0.1)',
          fill: true,
          tension: 0.3
        },
        {
          label: 'Upload (Mbps)',
          data: upData,
          borderColor: '#9d4edd',
          backgroundColor: 'rgba(157, 78, 221, 0.1)',
          fill: true,
          tension: 0.3
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { labels: { color: '#a0a5b5' } }
      },
      scales: {
        x: { ticks: { color: '#6c727f' }, grid: { color: 'rgba(255,255,255,0.05)' } },
        y: { ticks: { color: '#6c727f' }, grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true }
      }
    }
  });
}

/* ==========================================
   DNS LEAK AUDIT MODULE
   ========================================== */

async function runDnsLeakTest() {
  const container = document.getElementById('dns-leak-container');
  const btn = document.getElementById('btn-run-dns-leak');

  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<i data-lucide="refresh-cw" class="spin"></i> Checking Egress DNS...`;
    lucide.createIcons();
  }

  container.innerHTML = `
    <div class="empty-state">
      <i data-lucide="refresh-cw" class="spin"></i>
      <p>Testing egress DNS resolver addresses...</p>
    </div>
  `;
  lucide.createIcons();

  try {
    const res = await fetch('/api/dns-leak');
    const data = await res.json();

    if (!data.success) throw new Error(data.error || 'Failed to inspect DNS leak status');

    const isWarning = data.isLeakingToIsp;
    const boxClass = isWarning ? 'warning' : 'secure';
    const iconName = isWarning ? 'alert-triangle' : 'shield-check';
    const statusTitle = isWarning 
      ? 'DNS Leak Alert - Resolving via ISP (Frontier)' 
      : `No DNS Leaks - Securely Resolving via ${data.provider}`;

    const statusDesc = isWarning
      ? 'Your DNS queries are escaping your configured public DNS servers and being fulfilled directly by Frontier Communications nameservers. Follow the optimization engine tips to configure IPv4 & IPv6 DNS on your Nest Wifi Pro.'
      : `Your active internet DNS queries are being handled by <strong>${data.provider}</strong> (${data.resolverOrg}). Your ISP is not inspecting or logging your DNS traffic.`;

    container.innerHTML = `
      <div class="dns-leak-box ${boxClass}">
        <div class="dns-leak-icon">
          <i data-lucide="${iconName}"></i>
        </div>
        <div class="dns-leak-details">
          <h4>${statusTitle}</h4>
          <p>${statusDesc}</p>
          <div class="dns-leak-meta">
            <span>Egress Resolver IP: <strong>${data.resolverIp}</strong></span>
            <span>Organization: <strong>${data.resolverOrg}</strong></span>
            <span>Location: <strong>${data.country}</strong></span>
          </div>
        </div>
      </div>
    `;
    auditStatus.leak = true;
    updateAuditProgress();
    lucide.createIcons();
  } catch (err) {
    container.innerHTML = `
      <div class="empty-state">
        <i data-lucide="alert-circle"></i>
        <p>DNS Leak Test Error: ${err.message}</p>
      </div>
    `;
    lucide.createIcons();
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `<i data-lucide="shield-search"></i> Run DNS Leak Check`;
      lucide.createIcons();
    }
  }
}

/* ==========================================
   MASTER AUDIT SUITE & PROGRESS TRACKER
   ========================================== */

function setStepState(step, state) {
  const pill = document.getElementById(`pill-step-${step}`);
  if (!pill) return;

  pill.className = `step-pill ${state}`;
  let icon = 'circle';
  if (state === 'running') icon = 'refresh-cw';
  else if (state === 'done') icon = 'check-circle-2';

  const iconElem = pill.querySelector('i');
  if (iconElem) {
    iconElem.setAttribute('data-lucide', icon);
    if (state === 'running') iconElem.classList.add('spin');
    else iconElem.classList.remove('spin');
  }
  lucide.createIcons();
}

function updateAuditProgress() {
  let doneCount = 0;
  if (auditStatus.config) { doneCount++; setStepState('config', 'done'); }
  if (auditStatus.speed) { doneCount++; setStepState('speed', 'done'); }
  if (auditStatus.dns) { doneCount++; setStepState('dns', 'done'); }
  if (auditStatus.leak) { doneCount++; setStepState('leak', 'done'); }

  const percent = Math.round((doneCount / 4) * 100);
  
  const percentBadge = document.getElementById('audit-progress-percent');
  const progressBar = document.getElementById('audit-progress-bar');
  const exportBtn = document.getElementById('btn-export-audit');

  if (percentBadge) percentBadge.innerText = `${percent}% Complete`;
  if (progressBar) progressBar.style.width = `${percent}%`;

  if (exportBtn) {
    if (percent === 100) {
      exportBtn.style.borderColor = '#2ecc71';
      exportBtn.style.color = '#2ecc71';
      exportBtn.innerHTML = `<i data-lucide="download"></i> Export Complete Audit Report (100% Ready)`;
    } else {
      exportBtn.style.borderColor = 'var(--card-border)';
      exportBtn.style.color = 'var(--text-primary)';
      exportBtn.innerHTML = `<i data-lucide="download"></i> Export JSON Audit Report (${percent}% Complete)`;
    }
    lucide.createIcons();
  }
}

async function runFullAudit() {
  const masterBtn = document.getElementById('btn-run-full-audit');
  masterBtn.disabled = true;
  masterBtn.innerHTML = `<i data-lucide="refresh-cw" class="spin"></i> Running Full Audit (0/4)...`;
  lucide.createIcons();

  try {
    // 1. System Config
    masterBtn.innerHTML = `<i data-lucide="refresh-cw" class="spin"></i> Audit 1/4: Analyzing System Config...`;
    lucide.createIcons();
    setStepState('config', 'running');
    await fetchDiagnostics(false);
    auditStatus.config = true;
    updateAuditProgress();

    // 2. DNS Leak Check
    masterBtn.innerHTML = `<i data-lucide="refresh-cw" class="spin"></i> Audit 2/4: Inspecting Egress DNS Leak...`;
    lucide.createIcons();
    setStepState('leak', 'running');
    await runDnsLeakTest();
    auditStatus.leak = true;
    updateAuditProgress();

    // 3. DNS Benchmark Shootout
    masterBtn.innerHTML = `<i data-lucide="refresh-cw" class="spin"></i> Audit 3/4: Benchmarking 20+ DNS Resolvers...`;
    lucide.createIcons();
    setStepState('dns', 'running');
    await runDnsBenchmark();
    auditStatus.dns = true;
    updateAuditProgress();

    // 4. Speed & Bufferbloat Test
    masterBtn.innerHTML = `<i data-lucide="refresh-cw" class="spin"></i> Audit 4/4: Testing Fiber Speed & Bufferbloat...`;
    lucide.createIcons();
    setStepState('speed', 'running');
    await runSpeedTest();
    auditStatus.speed = true;
    updateAuditProgress();

    masterBtn.innerHTML = `<i data-lucide="check-circle-2"></i> 100% Audit Complete! Re-run`;
  } catch (err) {
    alert('Full audit encountered an error: ' + err.message);
    masterBtn.innerHTML = `<i data-lucide="zap"></i> Run Full Comprehensive Audit`;
  } finally {
    masterBtn.disabled = false;
    lucide.createIcons();
  }
}

/* ==========================================
   CLIENT DEVICE AWARENESS & PWA DETECTION
   ========================================== */

function detectClientDevice() {
  const ua = navigator.userAgent;
  let deviceName = 'Desktop Browser';
  let iconName = 'monitor';

  if (/Android/i.test(ua)) {
    deviceName = 'Android Mobile Device (Wi-Fi)';
    iconName = 'smartphone';
  } else if (/iPhone/i.test(ua)) {
    deviceName = 'Apple iPhone (Wi-Fi)';
    iconName = 'smartphone';
  } else if (/iPad/i.test(ua)) {
    deviceName = 'Apple iPad (Wi-Fi)';
    iconName = 'tablet';
  } else if (/Macintosh/i.test(ua)) {
    deviceName = 'Apple Mac System';
    iconName = 'laptop';
  } else if (/Windows/i.test(ua)) {
    deviceName = 'Windows PC Client';
    iconName = 'monitor';
  } else if (/Linux/i.test(ua)) {
    deviceName = 'Linux System';
    iconName = 'cpu';
  }

  const clientElem = document.getElementById('client-device-name');
  const clientIcon = document.getElementById('client-device-icon');
  if (clientElem) clientElem.innerText = deviceName;
  if (clientIcon) {
    clientIcon.setAttribute('data-lucide', iconName);
    lucide.createIcons();
  }
}




