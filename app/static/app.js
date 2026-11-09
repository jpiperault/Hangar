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
})();
