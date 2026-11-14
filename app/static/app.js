// Comportements communs de la console, sans JavaScript dans les attributs HTML (politique CSP stricte).
(function () {
  // confirmation : sur un formulaire (à l'envoi) ou sur un bouton (au clic) ; le texte est lu, jamais exécuté
  document.addEventListener('submit', function (e) {
    var f = e.target, b = e.submitter;
    var msg = (b && b.dataset && b.dataset.confirm) || (f.dataset && f.dataset.confirm);
    if (msg && !window.confirm(msg)) e.preventDefault();
  }, true);
  document.addEventListener('click', function (e) {
    var b = e.target.closest && e.target.closest('[data-copy]');
    if (!b) return;
    var el = document.getElementById(b.dataset.copy);
    if (el && navigator.clipboard) navigator.clipboard.writeText(el.textContent).then(function () { b.textContent = 'Copié'; });
  });
  document.addEventListener('change', function (e) {
    if (e.target.hasAttribute && e.target.hasAttribute('data-autosubmit') && e.target.form) e.target.form.submit();
  });

  // compte en lecture seule : les champs des formulaires d'action sont figés (les boutons sont cachés par le CSS)
  function readOnly(root) {
    if (!document.body.classList.contains('ro')) return;
    root.querySelectorAll('form[method=post]:not(.ro-ok)').forEach(function (f) {
      f.querySelectorAll('input:not([type=hidden]), select, textarea').forEach(function (el) { el.disabled = true; });
    });
  }
  readOnly(document);

  // blocs chargés après la page (lectures lentes sur un nœud) : data-lazy="/chemin/du/fragment"
  document.querySelectorAll('[data-lazy]').forEach(function (el) {
    fetch(el.getAttribute('data-lazy'), {credentials: 'same-origin'}).then(function (r) {
      return r.ok ? r.text() : Promise.reject(r.status);
    }).then(function (h) { el.innerHTML = h; el.removeAttribute('data-lazy'); readOnly(el); })
      .catch(function () { el.innerHTML = '<p class="hint">Lecture impossible pour l\'instant.</p>'; });
  });

  // barre de chargement : un lien interne ou un formulaire part, la page suivante arrive
  function busy() { document.documentElement.classList.add('navigating'); }
  window.addEventListener('pageshow', function () { document.documentElement.classList.remove('navigating'); });
  document.addEventListener('click', function (e) {
    var a = e.target.closest && e.target.closest('a[href]');
    if (!a || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || a.target || a.hasAttribute('download')) return;
    var u = new URL(a.href, location.href);
    if (u.origin !== location.origin || (u.pathname === location.pathname && u.search === location.search)) return;
    busy();
  });
  document.addEventListener('submit', function (e) { if (!e.defaultPrevented) setTimeout(function () { if (!e.defaultPrevented) busy(); }, 0); });
})();
