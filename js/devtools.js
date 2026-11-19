/* EncodeAll developer tools. Vanilla JS, everything runs locally in the browser. */
(function () {
  'use strict';

  function $(id) { return document.getElementById(id); }
  function on(el, ev, fn) { if (el) el.addEventListener(ev, fn); }
  function onAll(ids, fn) {
    ids.forEach(function (id) {
      var el = $(id);
      on(el, 'input', fn);
      on(el, 'change', fn);
    });
  }
  function toast(msg, isError) {
    if (window.showMessage) window.showMessage(msg, isError);
  }
  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { toast('Copied'); }, function () { toast('Copy failed', true); });
    }
  }
  document.addEventListener('click', function (e) {
    var btn = e.target.closest && e.target.closest('[data-copy-from]');
    if (btn) {
      var src = $(btn.getAttribute('data-copy-from'));
      if (src) copyText(src.value !== undefined ? src.value : src.textContent);
    }
  });

  // Unbiased random integer in [0, max) using crypto.getRandomValues.
  function randInt(max) {
    var buf = new Uint32Array(1);
    var limit = Math.floor(0x100000000 / max) * max;
    do { crypto.getRandomValues(buf); } while (buf[0] >= limit);
    return buf[0] % max;
  }
  function hex(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    return s;
  }
  function clampInt(v, min, max, def) {
    v = parseInt(v, 10);
    if (isNaN(v)) return def;
    return Math.min(max, Math.max(min, v));
  }

  /* ---------- UUID generator ---------- */
  function uuidV4() {
    var b = new Uint8Array(16);
    crypto.getRandomValues(b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    return fmtUuid(b);
  }
  function uuidV7() {
    var b = new Uint8Array(16);
    crypto.getRandomValues(b);
    var ts = Date.now();
    for (var i = 5; i >= 0; i--) { b[i] = ts % 256; ts = Math.floor(ts / 256); }
    b[6] = (b[6] & 0x0f) | 0x70;
    b[8] = (b[8] & 0x3f) | 0x80;
    return fmtUuid(b);
  }
  function fmtUuid(b) {
    var h = hex(b);
    return h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) + '-' + h.slice(16, 20) + '-' + h.slice(20);
  }
  function initUuid() {
    function gen() {
      var n = clampInt($('uuid-count').value, 1, 1000, 1);
      var v = $('uuid-version').value;
      var upper = $('uuid-upper').checked;
      var hyphens = $('uuid-hyphens').checked;
      var out = [];
      for (var i = 0; i < n; i++) {
        var u = v === '7' ? uuidV7() : (v === 'nil' ? '00000000-0000-0000-0000-000000000000' : uuidV4());
        if (!hyphens) u = u.replace(/-/g, '');
        if (upper) u = u.toUpperCase();
        out.push(u);
      }
      $('output').value = out.join('\n');
    }
    on($('generate'), 'click', gen);
    onAll(['uuid-count', 'uuid-version', 'uuid-upper', 'uuid-hyphens'], gen);
    gen();
  }

  /* ---------- Password generator ---------- */
  var SETS = {
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lower: 'abcdefghijklmnopqrstuvwxyz',
    digits: '0123456789',
    symbols: '!@#$%^&*()-_=+[]{};:,.<>/?~'
  };
  var AMBIGUOUS = /[O0oIl1|`'"]/g;
  function initPassword() {
    function gen() {
      var len = clampInt($('pw-length').value, 4, 128, 16);
      $('pw-length-value').textContent = len;
      var count = clampInt($('pw-count').value, 1, 100, 1);
      var pools = [];
      ['upper', 'lower', 'digits', 'symbols'].forEach(function (k) {
        if ($('pw-' + k).checked) {
          var s = SETS[k];
          if ($('pw-ambiguous').checked) s = s.replace(AMBIGUOUS, '');
          pools.push(s);
        }
      });
      if (!pools.length) {
        $('output').value = 'Select at least one character set.';
        $('pw-strength').textContent = '';
        return;
      }
      var all = pools.join('');
      var out = [];
      for (var c = 0; c < count; c++) {
        var chars = [];
        // Guarantee one character from each selected set, then fill and shuffle.
        pools.forEach(function (p) { chars.push(p[randInt(p.length)]); });
        while (chars.length < len) chars.push(all[randInt(all.length)]);
        chars = chars.slice(0, len);
        for (var i = chars.length - 1; i > 0; i--) {
          var j = randInt(i + 1);
          var t = chars[i]; chars[i] = chars[j]; chars[j] = t;
        }
        out.push(chars.join(''));
      }
      $('output').value = out.join('\n');
      var bits = Math.round(len * Math.log2(all.length));
      var label = bits < 40 ? 'Weak' : bits < 60 ? 'Fair' : bits < 80 ? 'Strong' : 'Very strong';
      $('pw-strength').textContent = label + ' - about ' + bits + ' bits of entropy';
      $('pw-strength').className = 'meter meter-' + label.toLowerCase().replace(' ', '-');
    }
    on($('generate'), 'click', gen);
    onAll(['pw-length', 'pw-count', 'pw-upper', 'pw-lower', 'pw-digits', 'pw-symbols', 'pw-ambiguous'], gen);
    gen();
  }

  /* ---------- JWT decoder ---------- */
  function b64urlDecode(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var bin = atob(s);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  }
  function fmtClaimTime(v) {
    if (typeof v !== 'number') return null;
    var d = new Date(v * 1000);
    return isNaN(d) ? null : d.toISOString() + ' (' + relative(d) + ')';
  }
  function initJwt() {
    function run() {
      var raw = $('input').value.trim().replace(/^Bearer\s+/i, '');
      var hOut = $('jwt-header'), pOut = $('jwt-payload'), info = $('jwt-info');
      hOut.value = ''; pOut.value = ''; info.textContent = '';
      if (!raw) return;
      var parts = raw.split('.');
      if (parts.length < 2) { info.textContent = 'Not a JWT: expected header.payload.signature'; info.className = 'note error'; return; }
      try {
        var header = JSON.parse(b64urlDecode(parts[0]));
        var payload = JSON.parse(b64urlDecode(parts[1]));
        hOut.value = JSON.stringify(header, null, 2);
        pOut.value = JSON.stringify(payload, null, 2);
        var notes = ['Algorithm: ' + (header.alg || 'none')];
        ['iat', 'nbf', 'exp'].forEach(function (k) {
          var t = fmtClaimTime(payload[k]);
          if (t) notes.push(k + ': ' + t);
        });
        if (typeof payload.exp === 'number') {
          notes.push(payload.exp * 1000 < Date.now() ? 'Status: EXPIRED' : 'Status: not expired');
        }
        notes.push('Signature is not verified.');
        info.textContent = notes.join('\n');
        info.className = 'note';
      } catch (e) {
        info.textContent = 'Could not decode: ' + e.message;
        info.className = 'note error';
      }
    }
    on($('input'), 'input', run);
    run();
  }

  /* ---------- Unix timestamp converter ---------- */
  function relative(d) {
    var diff = (d.getTime() - Date.now()) / 1000;
    var abs = Math.abs(diff);
    var units = [['year', 31536000], ['month', 2592000], ['day', 86400], ['hour', 3600], ['minute', 60], ['second', 1]];
    for (var i = 0; i < units.length; i++) {
      if (abs >= units[i][1] || units[i][0] === 'second') {
        var n = Math.round(abs / units[i][1]);
        var s = n + ' ' + units[i][0] + (n === 1 ? '' : 's');
        return diff < 0 ? s + ' ago' : 'in ' + s;
      }
    }
  }
  function initTimestamp() {
    var now = $('ts-now');
    setInterval(function () { now.textContent = Math.floor(Date.now() / 1000); }, 1000);
    now.textContent = Math.floor(Date.now() / 1000);

    function fromEpoch() {
      var v = $('ts-input').value.trim();
      var out = $('ts-result');
      if (!v) { out.value = ''; return; }
      if (!/^-?\d+(\.\d+)?$/.test(v)) { out.value = 'Enter a number of seconds, milliseconds, microseconds or nanoseconds.'; return; }
      var n = parseFloat(v), unit = 'seconds', ms = n * 1000;
      var digits = v.replace(/^-/, '').split('.')[0].length;
      if (digits >= 18) { unit = 'nanoseconds'; ms = n / 1e6; }
      else if (digits >= 15) { unit = 'microseconds'; ms = n / 1000; }
      else if (digits >= 12) { unit = 'milliseconds'; ms = n; }
      var d = new Date(ms);
      if (isNaN(d)) { out.value = 'Invalid timestamp'; return; }
      out.value = [
        'Detected unit:  ' + unit,
        'UTC:            ' + d.toUTCString(),
        'ISO 8601:       ' + d.toISOString(),
        'Local time:     ' + d.toString(),
        'Relative:       ' + relative(d),
        'Seconds:        ' + Math.floor(ms / 1000),
        'Milliseconds:   ' + Math.round(ms)
      ].join('\n');
    }
    function fromDate() {
      var v = $('ts-date').value;
      var out = $('ts-date-result');
      if (!v) { out.value = ''; return; }
      var d = new Date(v);
      if (isNaN(d)) { out.value = 'Invalid date'; return; }
      out.value = 'Seconds:       ' + Math.floor(d.getTime() / 1000) + '\nMilliseconds:  ' + d.getTime() + '\nISO 8601:      ' + d.toISOString();
    }
    on($('ts-input'), 'input', fromEpoch);
    on($('ts-date'), 'input', fromDate);
    on($('ts-use-now'), 'click', function () { $('ts-input').value = Math.floor(Date.now() / 1000); fromEpoch(); });
    var pad = function (x) { return (x < 10 ? '0' : '') + x; };
    var n = new Date();
    $('ts-date').value = n.getFullYear() + '-' + pad(n.getMonth() + 1) + '-' + pad(n.getDate()) + 'T' + pad(n.getHours()) + ':' + pad(n.getMinutes());
    $('ts-input').value = Math.floor(Date.now() / 1000);
    fromEpoch();
    fromDate();
  }

  /* ---------- Word counter ---------- */
  var STOP = ('a an and are as at be but by for from has have he her his i if in into is it its of on or our she so that the their them they this to was we were what when which who will with you your').split(' ');
  function initWords() {
    function run() {
      var t = $('input').value;
      var words = t.match(/[\p{L}\p{N}'’-]+/gu) || [];
      var sentences = t.split(/[.!?]+(?:\s|$)/).filter(function (s) { return s.trim(); }).length;
      var paragraphs = t.split(/\n\s*\n/).filter(function (s) { return s.trim(); }).length;
      var stats = {
        'wc-words': words.length,
        'wc-chars': Array.from(t).length,
        'wc-chars-ns': Array.from(t.replace(/\s/g, '')).length,
        'wc-sentences': sentences,
        'wc-paragraphs': paragraphs,
        'wc-reading': Math.max(words.length ? 1 : 0, Math.ceil(words.length / 238)) + ' min',
        'wc-speaking': Math.max(words.length ? 1 : 0, Math.ceil(words.length / 140)) + ' min'
      };
      Object.keys(stats).forEach(function (k) { $(k).textContent = stats[k]; });
      var freq = {};
      words.forEach(function (w) {
        w = w.toLowerCase();
        if (w.length > 2 && STOP.indexOf(w) < 0) freq[w] = (freq[w] || 0) + 1;
      });
      var top = Object.keys(freq).sort(function (a, b) { return freq[b] - freq[a]; }).slice(0, 10);
      $('wc-keywords').innerHTML = '';
      top.forEach(function (w) {
        var li = document.createElement('li');
        li.textContent = w + ' - ' + freq[w] + ' (' + (freq[w] / words.length * 100).toFixed(1) + '%)';
        $('wc-keywords').appendChild(li);
      });
    }
    on($('input'), 'input', run);
    run();
  }

  /* ---------- Lorem ipsum generator ---------- */
  var LOREM = ('lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua ut enim ad minim veniam quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur excepteur sint occaecat cupidatat non proident sunt in culpa qui officia deserunt mollit anim id est laborum curabitur pretium tincidunt lacus nulla gravida orci a odio nullam varius turpis et commodo pharetra est eros bibendum elit nec luctus magna felis sollicitudin mauris integer in mauris eu nibh euismod gravida duis ac tellus et risus vulputate vehicula donec lobortis risus a elit etiam tempor ut ullamcorper ligula eu tempor congue eros est euismod turpis id tincidunt sapien risus a quam maecenas fermentum consequat mi donec fermentum pellentesque malesuada nulla a mi duis sapien sem aliquet nec commodo eget consequat quis neque aliquam faucibus').split(' ');
  function initLorem() {
    function word() { return LOREM[randInt(LOREM.length)]; }
    function sentence() {
      var n = 6 + randInt(10), w = [];
      for (var i = 0; i < n; i++) w.push(word());
      var s = w.join(' ');
      return s.charAt(0).toUpperCase() + s.slice(1) + '.';
    }
    function paragraph() {
      var n = 4 + randInt(4), s = [];
      for (var i = 0; i < n; i++) s.push(sentence());
      return s.join(' ');
    }
    function gen() {
      var n = clampInt($('li-count').value, 1, 500, 5);
      var unit = $('li-unit').value;
      var out;
      if (unit === 'words') {
        var w = [];
        for (var i = 0; i < n; i++) w.push(word());
        out = w.join(' ');
      } else if (unit === 'sentences') {
        var s = [];
        for (var j = 0; j < n; j++) s.push(sentence());
        out = s.join(' ');
      } else {
        var p = [];
        for (var k = 0; k < n; k++) p.push(paragraph());
        out = p.join($('li-html').checked ? '</p>\n<p>' : '\n\n');
        if ($('li-html').checked) out = '<p>' + out + '</p>';
      }
      if ($('li-classic').checked) {
        out = out.replace(/^(<p>)?[A-Za-z]+( [a-z]+){0,4}/, function (m, p) {
          return (p || '') + 'Lorem ipsum dolor sit amet';
        });
      }
      $('output').value = out;
    }
    on($('generate'), 'click', gen);
    onAll(['li-count', 'li-unit', 'li-classic', 'li-html'], gen);
    gen();
  }

  var tools = {
    uuid: initUuid,
    password: initPassword,
    jwt: initJwt,
    timestamp: initTimestamp,
    words: initWords,
    lorem: initLorem
  };
  function boot() {
    var t = document.body.getAttribute('data-tool');
    if (tools[t]) tools[t]();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
