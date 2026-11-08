/* Statistiques d'une appli : petits graphiques à une série, survol avec infobulle, vue tableau. */
(function () {
  var el = document.getElementById('stdata'); if (!el) return;
  var D = JSON.parse(el.textContent), box = document.getElementById('charts');
  var NS = 'http://www.w3.org/2000/svg';
  var day = D.range === '7j';
  function hhmm(t) { var d = new Date(t * 1000); return String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0'); }
  function dm(t) { var d = new Date(t * 1000); return String(d.getDate()).padStart(2, '0') + '/' + String(d.getMonth() + 1).padStart(2, '0'); }
  function when(t) { return day ? dm(t) + ' ' + hhmm(t) : hhmm(t); }
  function fmt(v, unit) { if (v == null) return '—'; var n = v >= 100 ? Math.round(v) : Math.round(v * 10) / 10; return n.toLocaleString('fr-FR') + (unit ? ' ' + unit : ''); }
  function nice(max) { if (max <= 0) return 1; var p = Math.pow(10, Math.floor(Math.log10(max))), m = max / p; return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10) * p; }
  function node(tag, attrs, parent) { var n = document.createElementNS(NS, tag); for (var k in attrs) n.setAttribute(k, attrs[k]); if (parent) parent.appendChild(n); return n; }

  var CHARTS = [
    { key: 'req', title: 'Requêtes', sub: 'par ' + (D.step >= 3600 ? (D.step / 3600) + ' h' : (D.step / 60) + ' min'), unit: '', kind: 'bar', extra: 'e5' },
    { key: 'p95', title: 'Temps de réponse', sub: '95 % des requêtes en moins de (ms)', unit: 'ms', kind: 'line' },
    { key: 'mem', title: 'Mémoire', sub: 'max sur la période (Mo)', unit: 'Mo', kind: 'line', limit: D.mem_limit },
    { key: 'cpu', title: 'Processeur', sub: 'moyenne (% d’un cœur)', unit: '%', kind: 'line' }
  ];

  function draw(c, card) {
    var cap = document.createElement('figcaption');
    var vals = D[c.key], last = null;
    for (var i = vals.length - 1; i >= 0; i--) if (vals[i] != null) { last = vals[i]; break; }
    cap.innerHTML = '<span class="ct"></span><span class="cs"></span>';
    cap.firstChild.textContent = c.title; cap.lastChild.textContent = c.sub;
    card.appendChild(cap);
    var W = Math.max(240, card.clientWidth || 300), H = 150, L = 40, R = 8, T = 10, B = 22;
    var svg = node('svg', { viewBox: '0 0 ' + W + ' ' + H, width: '100%', height: H, role: 'img',
      'aria-label': c.title + ', dernière valeur ' + fmt(last, c.unit) });
    card.appendChild(svg);
    var n = vals.length, pw = W - L - R, ph = H - T - B;
    var max = 0; vals.forEach(function (v) { if (v != null && v > max) max = v; });
    if (c.limit && c.limit > max) max = c.limit;
    var top = nice(max * 1.05);
    function x(i) { return L + (n <= 1 ? pw / 2 : (i + 0.5) * pw / n); }
    function y(v) { return T + ph - v / top * ph; }
    [0, top / 2, top].forEach(function (g) {   // grille : traits fins, discrets
      node('line', { x1: L, x2: W - R, y1: y(g), y2: y(g), class: 'grid' }, svg);
      var tx = node('text', { x: L - 6, y: y(g) + 4, class: 'tick', 'text-anchor': 'end' }, svg);
      tx.textContent = g >= 1000 ? (g / 1000).toLocaleString('fr-FR') + 'k' : g.toLocaleString('fr-FR');
    });
    var ticks = 4;
    for (var k = 0; k <= ticks; k++) {
      var i = Math.round(k * (n - 1) / ticks);
      var tx = node('text', { x: x(i), y: H - 6, class: 'tick', 'text-anchor': k === 0 ? 'start' : k === ticks ? 'end' : 'middle' }, svg);
      tx.textContent = day ? dm(D.t[i]) : hhmm(D.t[i]);
    }
    if (c.limit) {
      node('line', { x1: L, x2: W - R, y1: y(c.limit), y2: y(c.limit), class: 'limit' }, svg);
      var lt = node('text', { x: W - R, y: y(c.limit) - 4, class: 'tick', 'text-anchor': 'end' }, svg);
      lt.textContent = 'limite ' + c.limit + ' Mo';
    }
    if (c.kind === 'bar') {
      var bw = Math.max(1, Math.min(24, pw / n - 2));
      vals.forEach(function (v, i) {
        if (!v) return;
        var h = Math.max(1, v / top * ph), x0 = x(i) - bw / 2, y0 = T + ph - h, r = Math.min(4, bw / 2, h);
        // bout arrondi côté valeur, carré côté ligne de base
        node('path', { class: 'mark', d: 'M' + x0 + ',' + (T + ph) + 'V' + (y0 + r) + 'Q' + x0 + ',' + y0 + ' ' + (x0 + r) + ',' + y0 +
          'H' + (x0 + bw - r) + 'Q' + (x0 + bw) + ',' + y0 + ' ' + (x0 + bw) + ',' + (y0 + r) + 'V' + (T + ph) + 'Z' }, svg);
        if (D.e5[i]) node('rect', { class: 'errmark', x: x0, y: y0 - 4, width: bw, height: 2 }, svg);
      });
    } else {
      var d = '', pen = false, lastI = -1;
      vals.forEach(function (v, i) {
        if (v == null) { pen = false; return; }
        d += (pen ? 'L' : 'M') + x(i).toFixed(1) + ',' + y(v).toFixed(1); pen = true; lastI = i;
      });
      if (d) node('path', { class: 'line', d: d }, svg);
      if (lastI >= 0) node('circle', { class: 'dot', cx: x(lastI), cy: y(vals[lastI]), r: 4 }, svg);
    }
    if (max === 0) {
      var e = node('text', { x: L + pw / 2, y: T + ph / 2, class: 'tick', 'text-anchor': 'middle' }, svg);
      e.textContent = 'aucune donnée sur la période';
    }
    // survol : réticule + infobulle, zone de capture sur toute la hauteur
    var cross = node('line', { class: 'cross', y1: T, y2: T + ph, x1: L, x2: L, visibility: 'hidden' }, svg);
    var tip = document.createElement('div'); tip.className = 'tip'; tip.hidden = true; card.appendChild(tip);
    var hit = node('rect', { x: L, y: 0, width: pw, height: H, fill: 'transparent' }, svg);
    function show(ev) {
      var r = svg.getBoundingClientRect(), px = (ev.clientX - r.left) * W / r.width;
      var i = Math.max(0, Math.min(n - 1, Math.floor((px - L) / pw * n)));
      cross.setAttribute('x1', x(i)); cross.setAttribute('x2', x(i)); cross.setAttribute('visibility', 'visible');
      var txt = when(D.t[i]) + ' · ' + fmt(vals[i] == null && c.kind === 'bar' ? 0 : vals[i], c.unit);
      if (c.key === 'req' && D.e5[i]) txt += ' · ' + D.e5[i] + ' erreur' + (D.e5[i] > 1 ? 's' : '') + ' 5xx';
      if (c.key === 'p95' && D.avg[i] != null) txt += ' (moyenne ' + fmt(D.avg[i], 'ms') + ')';
      tip.textContent = txt; tip.hidden = false;
      var left = x(i) / W * r.width; tip.style.left = Math.min(Math.max(0, left - 70), r.width - 150) + 'px';
    }
    hit.addEventListener('mousemove', show);
    hit.addEventListener('mouseleave', function () { tip.hidden = true; cross.setAttribute('visibility', 'hidden'); });
  }

  function render() {
    // toutes les cartes d'abord, pour que la grille fixe leur largeur avant la mesure
    box.textContent = '';
    var cards = CHARTS.map(function () { var f = document.createElement('figure'); f.className = 'chart'; box.appendChild(f); return f; });
    CHARTS.forEach(function (c, i) { draw(c, cards[i]); });
  }
  render();
  var rt; window.addEventListener('resize', function () { clearTimeout(rt); rt = setTimeout(render, 150); });

  // vue tableau (lignes avec données seulement)
  var tb = document.getElementById('stattable'), rows = [];
  D.t.forEach(function (t, i) {
    if (!D.req[i] && D.mem[i] == null) return;
    rows.push('<tr><td class="mono">' + when(t) + '</td><td>' + (D.req[i] || 0) + '</td><td>' + (D.e5[i] || 0) + '</td><td>' + fmt(D.p95[i]) +
      '</td><td>' + fmt(D.mem[i]) + '</td><td>' + fmt(D.cpu[i]) + '</td></tr>');
  });
  tb.innerHTML = rows.length ? '<table><thead><tr><th>Début</th><th>Requêtes</th><th>5xx</th><th>p95 (ms)</th><th>RAM (Mo)</th><th>CPU (%)</th></tr></thead><tbody>' +
    rows.reverse().join('') + '</tbody></table>' : '<p class="hint">Aucune donnée.</p>';
})();
