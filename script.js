document.addEventListener('DOMContentLoaded', function () {
  var tabV4 = document.getElementById('tabV4');
  var tabV6 = document.getElementById('tabV6');
  var panelV4 = document.getElementById('panelV4');
  var panelV6 = document.getElementById('panelV6');
  var glossaryV4 = document.getElementById('glossaryV4');
  var glossaryV6 = document.getElementById('glossaryV6');

  function switchMode(mode) {
    tabV4.classList.toggle('active', mode === 'v4');
    tabV6.classList.toggle('active', mode === 'v6');
    panelV4.classList.toggle('hidden', mode !== 'v4');
    panelV6.classList.toggle('hidden', mode !== 'v6');
    glossaryV4.classList.toggle('hidden', mode !== 'v4');
    glossaryV6.classList.toggle('hidden', mode !== 'v6');
    filterGlossary();
  }

  tabV4.addEventListener('click', function () { switchMode('v4'); });
  tabV6.addEventListener('click', function () { switchMode('v6'); });

  // --- Live Glossary Search ---
  var glossarySearch = document.getElementById('glossarySearch');
  var glossaryNoResults = document.getElementById('glossaryNoResults');

  function filterGlossary() {
    if (!glossarySearch) return;
    var query = glossarySearch.value.trim().toLowerCase();

    if (!query) {
      var isV6 = tabV6.classList.contains('active');
      glossaryV4.classList.toggle('hidden', isV6);
      glossaryV6.classList.toggle('hidden', !isV6);
      [glossaryV4, glossaryV6].forEach(function (box) {
        box.querySelectorAll('.term-card, .glossary-cat').forEach(function (el) {
          el.classList.remove('hidden');
        });
      });
      if (glossaryNoResults) glossaryNoResults.classList.add('hidden');
      return;
    }

    var visibleCount = 0;
    [glossaryV4, glossaryV6].forEach(function (box) {
      var boxMatches = 0;
      box.querySelectorAll('.term-card').forEach(function (card) {
        var match = card.textContent.toLowerCase().indexOf(query) !== -1;
        card.classList.toggle('hidden', !match);
        if (match) { boxMatches++; visibleCount++; }
      });

      box.querySelectorAll('.glossary-cat').forEach(function (cat) {
        var next = cat.nextElementSibling;
        var hasVisibleCard = false;
        while (next && !next.classList.contains('glossary-cat')) {
          if (next.classList.contains('term-card') && !next.classList.contains('hidden')) {
            hasVisibleCard = true;
            break;
          }
          next = next.nextElementSibling;
        }
        cat.classList.toggle('hidden', !hasVisibleCard);
      });

      box.classList.toggle('hidden', boxMatches === 0);
    });

    if (glossaryNoResults) {
      glossaryNoResults.classList.toggle('hidden', visibleCount > 0);
    }
  }

  glossarySearch.addEventListener('input', filterGlossary);


  var v4Input = document.getElementById('v4Input');
  var v4Slider = document.getElementById('v4Slider');
  var v4Preset = document.getElementById('v4Preset');

  v4Preset.addEventListener('change', function (e) {
    if (!e.target.value) return;
    var parts = e.target.value.split('|');
    v4Input.value = parts.at(0);
    v4Slider.value = parts.at(1);
    updateV4();
  });

  function ipToInt(ip) {
    var parts = ip.trim().split('.').map(Number);
    if (parts.length !== 4 || parts.some(function (p) { return isNaN(p) || p < 0 || p > 255; })) return null;
    return ((parts.at(0) << 24) | (parts.at(1) << 16) | (parts.at(2) << 8) | parts.at(3)) >>> 0;
  }

  function intToIp(num) {
    return [(num >>> 24) & 255, (num >>> 16) & 255, (num >>> 8) & 255, num & 255].join('.');
  }

  function getV4MulticastMac(ipInt) {
    var low23 = ipInt & 0x7FFFFF;
    var b4 = ((low23 >>> 16) & 0x7F).toString(16).padStart(2, '0');
    var b5 = ((low23 >>> 8) & 0xFF).toString(16).padStart(2, '0');
    var b6 = (low23 & 0xFF).toString(16).padStart(2, '0');
    return '01:00:5e:' + b4 + ':' + b5 + ':' + b6;
  }

  function classifyV4(ipInt) {
    var first = (ipInt >>> 24) & 255;
    var second = (ipInt >>> 16) & 255;
    var third = (ipInt >>> 8) & 255;

    if (ipInt === 0xFFFFFFFF) {
      return { isMcast: false, badge: 'scope-special', label: 'BROADCAST — Limited Broadcast (255.255.255.255)' };
    }
    if (first === 0) {
      return { isMcast: false, badge: 'scope-special', label: 'RESERVED — "This Network" (0.0.0.0/8)' };
    }
    if (first >= 224 && first <= 239) {
      var sub = 'Global / Scoped Multicast';
      if (first === 224 && second === 0 && third === 0) sub = 'Local Network Control (224.0.0.0/24)';
      else if (first === 239) sub = 'Private / Admin Scoped (239.0.0.0/8)';
      return { isMcast: true, badge: 'scope-mcast', label: 'MULTICAST — Class D: ' + sub };
    }
    if (first >= 240) {
      return { isMcast: false, badge: 'scope-special', label: 'RESERVED — Class E Experimental (240.0.0.0/4)' };
    }
    if (first === 127) {
      return { isMcast: false, badge: 'scope-special', label: 'LOCAL — Loopback (127.0.0.0/8)' };
    }
    if (first === 10) {
      return { isMcast: false, badge: 'scope-private', label: 'PRIVATE — RFC 1918 Class A (10.0.0.0/8)' };
    }
    if (first === 172 && second >= 16 && second <= 31) {
      return { isMcast: false, badge: 'scope-private', label: 'PRIVATE — RFC 1918 Class B (172.16.0.0/12)' };
    }
    if (first === 192 && second === 168) {
      return { isMcast: false, badge: 'scope-private', label: 'PRIVATE — RFC 1918 Class C (192.168.0.0/16)' };
    }
    if (first === 100 && second >= 64 && second <= 127) {
      return { isMcast: false, badge: 'scope-cgnat', label: 'CGNAT — Shared ISP Space (100.64.0.0/10)' };
    }
    if (first === 169 && second === 254) {
      return { isMcast: false, badge: 'scope-special', label: 'LINK-LOCAL — APIPA (169.254.0.0/16)' };
    }
    if ((first === 192 && second === 0 && third === 2) ||
      (first === 198 && second === 51 && third === 100) ||
      (first === 203 && second === 0 && third === 113)) {
      return { isMcast: false, badge: 'scope-special', label: 'DOCS / RESERVED — RFC 5737 TEST-NET' };
    }
    if (first === 198 && (second === 18 || second === 19)) {
      return { isMcast: false, badge: 'scope-special', label: 'RESERVED — Benchmarking (198.18.0.0/15)' };
    }
    var cls = first < 128 ? 'Class A' : first < 192 ? 'Class B' : 'Class C';
    return { isMcast: false, badge: 'scope-public', label: 'PUBLIC — Internet Routable (' + cls + ')' };
  }

  function updateV4() {
    var prefix = parseInt(v4Slider.value, 10);
    var parsed = ipToInt(v4Input.value);
    var ipInt = parsed !== null ? parsed : ipToInt('192.168.1.50');
    var info = classifyV4(ipInt);

    document.getElementById('v4Badge').textContent = '/' + prefix;
    document.getElementById('v4NetCount').textContent = prefix;
    document.getElementById('v4HostCount').textContent = 32 - prefix;

    var mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
    var wildcard = (~mask) >>> 0;
    var network = (ipInt & mask) >>> 0;
    var broadcast = (network | wildcard) >>> 0;

    var usable = 0, rangeStr = 'N/A';
    if (info.isMcast) { usable = 'Multicast Group (No Host IDs)'; rangeStr = '224.0.0.0 – 239.255.255.255'; }
    else if (prefix === 32) { usable = '1 (Host Route)'; rangeStr = intToIp(network); }
    else if (prefix === 31) { usable = '2 (RFC 3021 Point-to-Point)'; rangeStr = intToIp(network) + ' – ' + intToIp(broadcast); }
    else { usable = (Math.pow(2, 32 - prefix) - 2).toLocaleString(); rangeStr = intToIp((network + 1) >>> 0) + ' – ' + intToIp((broadcast - 1) >>> 0); }

    document.getElementById('v4Scope').innerHTML = '<span class="scope-pill ' + info.badge + '">' + info.label + '</span>';
    document.getElementById('v4Mask').textContent = intToIp(mask);
    document.getElementById('v4Wildcard').textContent = intToIp(wildcard);
    document.getElementById('v4Network').textContent = intToIp(network);
    document.getElementById('v4Broadcast').textContent = info.isMcast ? 'N/A (Multicast)' : intToIp(broadcast);
    document.getElementById('v4Range').textContent = rangeStr;
    document.getElementById('v4Hosts').textContent = usable;
    document.getElementById('v4Mac').textContent = info.isMcast ? getV4MulticastMac(ipInt) : 'N/A (Uses ARP Unicast MAC)';

    var mcastBox = document.getElementById('v4McastBox');
    if (info.isMcast) {
      mcastBox.className = 'mcast-banner';
      mcastBox.innerHTML = '<strong>IPv4 Multicast Active (224.0.0.0/4 — Leading bits 1110)</strong>In IPv4 multicast, there is no network/host split—the remaining 28 bits identify the multicast group. Ethernet switches map the lower 23 bits directly to Layer 2 MAC <code>' + getV4MulticastMac(ipInt) + '</code> (32 IPs share each MAC).';
    } else {
      mcastBox.className = 'mcast-banner unicast-info';
      mcastBox.innerHTML = '<strong>Unicast Subnet Mode</strong>IPv4 uses a subnet broadcast address (<code>' + intToIp(broadcast) + '</code>) to reach all local hosts. For one-to-many group traffic, enter an IP in <code>224.0.0.0 – 239.255.255.255</code> or pick a Multicast preset above.';
    }

    var bin = ipInt.toString(2).padStart(32, '0');
    var grid = document.getElementById('v4BitGrid');
    grid.innerHTML = '';

    for (var o = 0; o < 4; o++) {
      var startBit = o * 8, endBit = startBit + 8;
      var isAllNet = prefix >= endBit, isAllHost = prefix <= startBit, isSplit = !isAllNet && !isAllHost;

      var octBox = document.createElement('div');
      octBox.className = 'octet' + (isSplit ? ' is-split' : '');
      var dec = document.createElement('div');
      dec.className = 'octet-dec';
      dec.textContent = (ipInt >>> (24 - o * 8)) & 255;
      octBox.appendChild(dec);

      var bitRow = document.createElement('div');
      bitRow.className = 'octet-bits';
      for (var b = 0; b < 8; b++) {
        var idx = startBit + b;
        var span = document.createElement('span');
        var cls = idx < prefix ? 'bit-net' : 'bit-host';
        if (info.isMcast && idx < 4) cls = 'bit-mcast';
        span.className = 'v4-bit ' + cls;
        span.textContent = bin.at(idx);
        bitRow.appendChild(span);
      }
      octBox.appendChild(bitRow);

      var roleTag = document.createElement('div');
      if (info.isMcast) { roleTag.className = 'block-role role-split'; roleTag.textContent = o === 0 ? '1110 + GROUP' : 'GROUP ID'; }
      else if (isAllNet) { roleTag.className = 'block-role role-net'; roleTag.textContent = 'NETWORK'; }
      else if (isAllHost) { roleTag.className = 'block-role role-host'; roleTag.textContent = 'HOST'; }
      else { roleTag.className = 'block-role role-split'; roleTag.textContent = 'SPLIT (' + (prefix - startBit) + 'N / ' + (endBit - prefix) + 'H)'; }
      octBox.appendChild(roleTag);

      grid.appendChild(octBox);
    }
  }
  var v6Input = document.getElementById('v6Input');
  var v6Slider = document.getElementById('v6Slider');
  var v6Preset = document.getElementById('v6Preset');

  v6Preset.addEventListener('change', function (e) {
    if (!e.target.value) return;
    var parts = e.target.value.split('|');
    v6Input.value = parts.at(0);
    v6Slider.value = parts.at(1);
    updateV6();
  });

  function expandIPv6(ip) {
    ip = ip.trim().toLowerCase();
    if (!ip) return null;
    var parts = ip.split('::');
    if (parts.length > 2) return null;

    var hextets = [];
    if (parts.length === 2) {
      var left = parts.at(0) ? parts.at(0).split(':') : [];
      var right = parts.at(1) ? parts.at(1).split(':') : [];
      var missing = 8 - (left.length + right.length);
      if (missing < 1) return null;
      hextets = left.concat(Array(missing).fill('0000'), right);
    } else {
      hextets = ip.split(':');
    }

    if (hextets.length !== 8 || hextets.some(function (h) { return !/^[0-9a-f]{1,4}$/.test(h); })) return null;
    return hextets.map(function (h) { return h.padStart(4, '0'); });
  }

  function compressIPv6(hextets) {
    var stripped = hextets.map(function (h) { return h.replace(/^0+/, '') || '0'; });
    var bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;

    for (var i = 0; i < 8; i++) {
      if (stripped.at(i) === '0') {
        if (curStart === -1) curStart = i;
        curLen++;
        if (curLen > bestLen && curLen > 1) { bestStart = curStart; bestLen = curLen; }
      } else {
        curStart = -1;
        curLen = 0;
      }
    }

    if (bestStart !== -1) {
      stripped.splice(bestStart, bestLen, '');
      if (bestStart === 0) stripped.unshift('');
      if (bestStart + bestLen === 8) stripped.push('');
    }
    return stripped.join(':');
  }

  function getV6MulticastScopeName(scopeHex) {
    var scopes = { '1': 'Interface-Local (Loopback)', '2': 'Link-Local (Same LAN)', '4': 'Admin-Local', '5': 'Site-Local', '8': 'Organization-Local', 'e': 'Global Scope (Internet)' };
    return scopes[scopeHex] || 'Reserved/Unassigned (0x' + scopeHex + ')';
  }

  function updateV6() {
    var prefix = parseInt(v6Slider.value, 10);
    var hextets = expandIPv6(v6Input.value) || expandIPv6('2001:db8:85a3::8a2e:370:7334');
    var ipBigInt = BigInt('0x' + hextets.join(''));

    document.getElementById('v6Badge').textContent = '/' + prefix;
    document.getElementById('v6NetCount').textContent = prefix;
    document.getElementById('v6HostCount').textContent = 128 - prefix;

    var allOnes = (1n << 128n) - 1n;
    var hostBits = BigInt(128 - prefix);
    var mask = (allOnes >> hostBits) << hostBits;
    var netBigInt = ipBigInt & mask;
    var netHex = netBigInt.toString(16).padStart(32, '0').match(/.{1,4}/g);

    var firstHextet = hextets.at(0);
    var isMcast = firstHextet.startsWith('ff');
    var low32 = ipBigInt & 0xFFFFFFFFn;
    var macBytes = low32.toString(16).padStart(8, '0').match(/.{1,2}/g);
    var mcastMac = '33:33:' + macBytes.join(':');

    var low24 = (ipBigInt & 0xFFFFFFn).toString(16).padStart(6, '0');
    var solNode = 'ff02::1:ff' + low24.slice(0, 2) + ':' + low24.slice(2);

    var scopeLabel = 'PUBLIC — Global Unicast (2000::/3)';
    var scopeBadge = 'scope-public';
    var h1 = hextets.at(1);

    if (isMcast) {
      scopeBadge = 'scope-mcast';
      scopeLabel = 'MULTICAST (ff00::/8) — Flags: 0x' + firstHextet.at(2) + ', Scope: ' + getV6MulticastScopeName(firstHextet.at(3));
    } else if (ipBigInt === 0n) {
      scopeBadge = 'scope-special';
      scopeLabel = 'UNSPECIFIED — Default Route / None (::/128)';
    } else if (ipBigInt === 1n) {
      scopeBadge = 'scope-special';
      scopeLabel = 'LOCAL — Loopback (::1/128)';
    } else if (hextets.slice(0, 5).join('') === '00000000000000000000' && hextets.at(5) === 'ffff') {
      scopeBadge = 'scope-special';
      scopeLabel = 'TRANSITION — IPv4-Mapped IPv6 (::ffff:0:0/96)';
    } else if (firstHextet === '0064' && h1 === 'ff9b') {
      scopeBadge = 'scope-special';
      scopeLabel = 'TRANSITION — NAT64 Well-Known Prefix (64:ff9b::/96)';
    } else if (firstHextet === '0100' && h1 === '0000' && hextets.at(2) === '0000' && hextets.at(3) === '0000') {
      scopeBadge = 'scope-special';
      scopeLabel = 'RESERVED — Discard-Only Block (100::/64)';
    } else if (firstHextet === '2001' && h1 === '0db8') {
      scopeBadge = 'scope-special';
      scopeLabel = 'DOCS / RESERVED — RFC 3849 Example (2001:db8::/32)';
    } else if (firstHextet === '2001' && h1 === '0000') {
      scopeBadge = 'scope-special';
      scopeLabel = 'TRANSITION — Teredo Tunneling (2001::/32)';
    } else if (firstHextet === '2002') {
      scopeBadge = 'scope-special';
      scopeLabel = 'TRANSITION — 6to4 Tunneling (2002::/16)';
    } else if (firstHextet.startsWith('fe8') || firstHextet.startsWith('fe9') || firstHextet.startsWith('fea') || firstHextet.startsWith('feb')) {
      scopeBadge = 'scope-special';
      scopeLabel = 'LINK-LOCAL — Unicast (fe80::/10)';
    } else if (firstHextet.startsWith('fc') || firstHextet.startsWith('fd')) {
      scopeBadge = 'scope-private';
      scopeLabel = 'PRIVATE — Unique Local / ULA (fc00::/7)';
    }

    document.getElementById('v6Scope').innerHTML = '<span class="scope-pill ' + scopeBadge + '">' + scopeLabel + '</span>';
    document.getElementById('v6Compressed').textContent = compressIPv6(hextets);
    document.getElementById('v6Expanded').textContent = hextets.join(':');
    document.getElementById('v6NetAddr').textContent = compressIPv6(netHex);
    document.getElementById('v6SolNode').textContent = isMcast ? 'N/A (Already Multicast)' : solNode;
    document.getElementById('v6Mac').textContent = isMcast ? mcastMac : '33:33:ff:' + low24.slice(0, 2) + ':' + low24.slice(2, 4) + ':' + low24.slice(4, 6) + ' (via Solicited-Node)';

    if (prefix <= 64) {
      var subs = 2n ** BigInt(64 - prefix);
      document.getElementById('v6Subnets').textContent = prefix === 64 ? '1 (Standard LAN)' : subs.toLocaleString() + ' /64 subnets';
    } else {
      document.getElementById('v6Subnets').textContent = 'Sub-netted past /64 boundary';
    }

    var hostSpace = 128 - prefix;
    document.getElementById('v6Hosts').textContent = hostSpace === 0 ? '1 (/128)' : hostSpace <= 53 ? (2 ** hostSpace).toLocaleString() : '2^' + hostSpace + ' (~' + (2 ** hostSpace).toExponential(2) + ')';

    var mcastBox = document.getElementById('v6McastBox');
    if (isMcast) {
      mcastBox.className = 'mcast-banner';
      mcastBox.innerHTML = '<strong>IPv6 Multicast Structure (ff00::/8)</strong>Bits 1–8 (<code>ff</code>) mark Multicast. Bits 9–12 (<code>0x' + firstHextet.at(2) + '</code>) hold Flags, and Bits 13–16 (<code>0x' + firstHextet.at(3) + '</code>) define Scope (<code>' + getV6MulticastScopeName(firstHextet.at(3)) + '</code>). The last 32 bits map directly to Ethernet MAC <code>' + mcastMac + '</code>.';
    } else {
      mcastBox.className = 'mcast-banner unicast-info';
      mcastBox.innerHTML = '<strong>IPv6 Has No Broadcast — It Uses Solicited-Node Multicast</strong>Instead of flooding the network with ARP broadcasts, every IPv6 unicast address automatically joins the Solicited-Node Multicast group <code>' + solNode + '</code> (taking its last 24 bits) for Neighbor Discovery.';
    }

    var bin = ipBigInt.toString(2).padStart(128, '0');
    var grid = document.getElementById('v6BitGrid');
    grid.innerHTML = '';

    for (var h = 0; h < 8; h++) {
      var startBit = h * 16, endBit = startBit + 16;
      var isAllNet = prefix >= endBit, isAllHost = prefix <= startBit, isSplit = !isAllNet && !isAllHost;

      var box = document.createElement('div');
      box.className = 'hextet' + (isSplit ? ' is-split' : '');
      var lbl = document.createElement('div');
      lbl.className = 'hextet-hex';
      lbl.textContent = hextets.at(h);
      box.appendChild(lbl);

      var row = document.createElement('div');
      row.className = 'hextet-bits';
      for (var b = 0; b < 16; b++) {
        var idx = startBit + b;
        var span = document.createElement('span');
        var cls = idx < prefix ? (idx < 48 ? 'bit-net' : 'bit-sub') : 'bit-host';
        if (isMcast && idx < 8) cls = 'bit-mcast';
        else if (isMcast && idx >= 8 && idx < 16) cls = 'bit-flag';
        span.className = 'v6-bit ' + cls;
        span.textContent = bin.at(idx);
        row.appendChild(span);
      }
      box.appendChild(row);

      var roleTag = document.createElement('div');
      if (isMcast && h === 0) { roleTag.className = 'block-role role-split'; roleTag.textContent = 'FF + FLAGS/SCOPE'; }
      else if (isAllNet) { roleTag.className = 'block-role role-net'; roleTag.textContent = h < 3 ? 'GLOBAL NET' : 'LOCAL SUBNET'; }
      else if (isAllHost) { roleTag.className = 'block-role role-host'; roleTag.textContent = 'INTERFACE (HOST)'; }
      else { roleTag.className = 'block-role role-split'; roleTag.textContent = 'SPLIT (' + (prefix - startBit) + 'N / ' + (endBit - prefix) + 'H)'; }
      box.appendChild(roleTag);

      grid.appendChild(box);
    }
  }

  v4Slider.addEventListener('input', updateV4);
  v4Input.addEventListener('input', updateV4);
  v6Slider.addEventListener('input', updateV6);
  v6Input.addEventListener('input', updateV6);

  updateV4();
  updateV6();
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && window.parent !== window) {
      window.parent.postMessage('closeIpv4v6Modal', '*');
    }
  });
});
