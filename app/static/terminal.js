// Terminal interactif (xterm.js) relié au conteneur par WebSocket ; repli : une commande à la fois.
(function () {
  var box = document.getElementById('xterm');
  if (!box || typeof Terminal === 'undefined') return;
  var slug = box.dataset.slug, which = document.getElementById('which'), root = document.getElementById('asroot');
  var status = document.getElementById('xstatus'), btn = document.getElementById('xconnect');
  var term = new Terminal({cursorBlink: true, fontSize: 14, fontFamily: 'ui-monospace, Menlo, Consolas, monospace',
                           scrollback: 5000, theme: {background: '#111418', foreground: '#e6e6e6'}});
  var fit = new FitAddon.FitAddon(); term.loadAddon(fit); term.open(box); fit.fit();
  var ws = null;
  function size() { if (ws && ws.readyState === 1) ws.send(JSON.stringify({t: 'r', c: term.cols, r: term.rows})); }
  function connect() {
    if (ws) { try { ws.close(); } catch (e) {} }
    term.reset();
    var url = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/apps/' + slug + '/terminal/ws?which='
              + encodeURIComponent(which.value) + '&root=' + (root.checked ? '1' : '');
    ws = new WebSocket(url); ws.binaryType = 'arraybuffer';
    status.textContent = box.dataset.connecting;
    ws.onopen = function () { status.textContent = box.dataset.connected; fit.fit(); size(); term.focus(); };
    ws.onmessage = function (e) { term.write(new Uint8Array(e.data)); };
    ws.onclose = function (e) { status.textContent = e.code === 4403 ? box.dataset.refused : box.dataset.closed; };
  }
  term.onData(function (d) { if (ws && ws.readyState === 1) ws.send(JSON.stringify({t: 'i', d: d})); });
  window.addEventListener('resize', function () { fit.fit(); size(); });
  term.onResize(size);
  btn.addEventListener('click', connect);
  which.addEventListener('change', connect);
  root.addEventListener('change', connect);
  connect();
})();
