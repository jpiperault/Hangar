/* Petits graphiques à une série (barres ou ligne), survol avec infobulle, vue tableau.
   Données : élément #stdata (JSON) = {t, step, range, charts:[…]}
   Chaque graphique : {title, sub, unit, kind: 'bar'|'line', values, limit?, limitLabel?,
                       marks?: {values, label} (repères d'erreur au-dessus des barres),
                       extra?: [{label, values, unit}] (lignes supplémentaires de l'infobulle)} */
(function () {
  var el = document.getElementById('stdata'); if (!el) return;
  var D = JSON.parse(el.textContent), box = document.getElementById('charts');
  var NS = 'http://www.w3.org/2000/svg';
  var day = D.range === '7j';
  function pad(n) { return String(n).padStart(2, '0'); }
  function hhmm(t) { var d = new Date(t * 1000); return pad(d.getHours()) + ':' + pad(d.getMinutes()); }
  function dm(t) { var d = new Date(t * 1000); return pad(d.getDate()) + '/' + pad(d.getMonth() + 1); }
  function when(t) { return day ? dm(t) + ' ' + hhmm(t) : hhmm(t); }
  function fmt(v, unit) {
    if (v == null) return '—';
    var n = Math.abs(v) >= 100 ? Math.round(v) : Math.round(v * 10) / 10;
    return n.toLocaleString('fr-FR') + (unit ? ' ' + unit : '');
  }
  function nice(max) { if (max <= 0) return 1; var p = Math.pow(10, Math.floor(Math.log10(max))), m = max / p; return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10) * p; }
  function tick(g) { return g >= 1e6 ? (g / 1e6).toLocaleString('fr-FR') + 'M' : g >= 10000 ? (g / 1000).toLocaleString('fr-FR') + 'k' : g.toLocaleString('fr-FR'); }
  function node(tag, attrs, parent) { var n = document.createElementNS(NS, tag); for (var k in attrs) n.setAttribute(k, attrs[k]); if (parent) parent.appendChild(n); return n; }

  function draw(c, card) {
    var vals = c.values, last = null;
    for (var i = vals.length - 1; i >= 0; i--) if (vals[i] != null) { last = vals[i]; break; }
    var cap = document.createElement('figcaption');
    var ct = document.createElement('span'); ct.className = 'ct'; ct.textContent = c.title;
    var cs = document.createElement('span'); cs.className = 'cs'; cs.textContent = c.sub || '';
    cap.appendChild(ct); cap.appendChild(cs); card.appendChild(cap);
    var W = Math.max(240, card.clientWidth || 300), H = 150, L = 40, R = 8, T = 10, B = 22;
    var svg = node('svg', { viewBox: '0 0 ' + W + ' ' + H, width: '100%', height: H, role: 'img',
      'aria-label': c.title + ', dernière valeur ' + fmt(last, c.unit) });
    card.appendChild(svg);
    var n = vals.length, pw = W - L - R, ph = H - T - B;
    var max = 0; vals.forEach(function (v) { if (v != null && v > max) max = v; });
    var empty = max === 0;
    // avec une limite (100 %, RAM totale, RAM max de l'appli), l'axe s'arrête dessus tant que les données la respectent
    var top = c.limit && c.limit >= max ? c.limit : nice(max * 1.05);
    function x(i) { return L + (n <= 1 ? pw / 2 : (i + 0.5) * pw / n); }
    function y(v) { return T + ph - v / top * ph; }
    [0, top / 2, top].forEach(function (g) {
      node('line', { x1: L, x2: W - R, y1: y(g), y2: y(g), class: 'grid' }, svg);
      node('text', { x: L - 6, y: y(g) + 4, class: 'tick', 'text-anchor': 'end' }, svg).textContent = tick(Math.round(g * 10) / 10);
    });
    var ticks = 4;
    for (var k = 0; k <= ticks; k++) {
      var j = Math.round(k * (n - 1) / ticks);
      node('text', { x: x(j), y: H - 6, class: 'tick', 'text-anchor': k === 0 ? 'start' : k === ticks ? 'end' : 'middle' }, svg)
        .textContent = day ? dm(D.t[j]) : hhmm(D.t[j]);
    }
    if (c.limit) {
      node('line', { x1: L, x2: W - R, y1: y(c.limit), y2: y(c.limit), class: 'limit' }, svg);
      node('text', { x: W - R, y: y(c.limit) + (y(c.limit) - T < 12 ? 12 : -4), class: 'tick', 'text-anchor': 'end' }, svg).textContent = c.limitLabel || ('limite ' + fmt(c.limit, c.unit));
    }
    if (c.kind === 'bar') {
      var bw = Math.max(1, Math.min(24, pw / n - 2));
      vals.forEach(function (v, i) {
        if (!v) return;
        var h = Math.max(1, v / top * ph), x0 = x(i) - bw / 2, y0 = T + ph - h, r = Math.min(4, bw / 2, h);
        node('path', { class: 'mark', d: 'M' + x0 + ',' + (T + ph) + 'V' + (y0 + r) + 'Q' + x0 + ',' + y0 + ' ' + (x0 + r) + ',' + y0 +
          'H' + (x0 + bw - r) + 'Q' + (x0 + bw) + ',' + y0 + ' ' + (x0 + bw) + ',' + (y0 + r) + 'V' + (T + ph) + 'Z' }, svg);
        if (c.marks && c.marks.values[i]) node('rect', { class: 'errmark', x: x0, y: y0 - 4, width: bw, height: 2 }, svg);
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
    if (empty) node('text', { x: L + pw / 2, y: T + ph / 2, class: 'tick', 'text-anchor': 'middle' }, svg).textContent = 'aucune donnée sur la période';
    var cross = node('line', { class: 'cross', y1: T, y2: T + ph, x1: L, x2: L, visibility: 'hidden' }, svg);
    var tip = document.createElement('div'); tip.className = 'tip'; tip.hidden = true; card.appendChild(tip);
    var hit = node('rect', { x: L, y: 0, width: pw, height: H, fill: 'transparent' }, svg);
    hit.addEventListener('mousemove', function (ev) {
      var r = svg.getBoundingClientRect(), px = (ev.clientX - r.left) * W / r.width;
      var i = Math.max(0, Math.min(n - 1, Math.floor((px - L) / pw * n)));
      cross.setAttribute('x1', x(i)); cross.setAttribute('x2', x(i)); cross.setAttribute('visibility', 'visible');
      var txt = when(D.t[i]) + ' · ' + fmt(vals[i] == null && c.kind === 'bar' ? 0 : vals[i], c.unit);
      if (c.marks && c.marks.values[i]) txt += ' · ' + c.marks.values[i] + ' ' + c.marks.label;
      (c.extra || []).forEach(function (e) { if (e.values[i] != null) txt += ' · ' + e.label + ' ' + fmt(e.values[i], e.unit); });
      tip.textContent = txt; tip.hidden = false;
      var left = x(i) / W * r.width; tip.style.left = Math.min(Math.max(0, left - 70), Math.max(0, r.width - 170)) + 'px';
    });
    hit.addEventListener('mouseleave', function () { tip.hidden = true; cross.setAttribute('visibility', 'hidden'); });
  }

  function render() {
    // toutes les cartes d'abord, pour que la grille fixe leur largeur avant la mesure
    box.textContent = '';
    var cards = D.charts.map(function () { var f = document.createElement('figure'); f.className = 'chart'; box.appendChild(f); return f; });
    D.charts.forEach(function (c, i) { draw(c, cards[i]); });
  }
  render();
  var rt; window.addEventListener('resize', function () { clearTimeout(rt); rt = setTimeout(render, 150); });

  var tb = document.getElementById('stattable'); if (!tb) return;
  var head = '<th>Début</th>' + D.charts.map(function (c) { return '<th>' + c.title + (c.unit ? ' (' + c.unit + ')' : '') + '</th>'; }).join('');
  var rows = [];
  D.t.forEach(function (t, i) {
    if (!D.charts.some(function (c) { return c.values[i]; })) return;
    rows.push('<tr><td class="mono">' + when(t) + '</td>' + D.charts.map(function (c) { return '<td>' + fmt(c.values[i]) + '</td>'; }).join('') + '</tr>');
  });
  tb.innerHTML = rows.length ? '<table><thead><tr>' + head + '</tr></thead><tbody>' + rows.reverse().join('') + '</tbody></table>'
    : '<p class="hint">Aucune donnée.</p>';
})();
