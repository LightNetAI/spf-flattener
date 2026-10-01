/* ============================================================
   ATS Solutions — SPF Flattener UI behaviour
   Includes the isometric cube grid used behind the dark
   hero / slider surfaces on dev.ats.solutions.
   ============================================================ */
(function () {
  'use strict';

  /* ---- Header shadow + reading progress bar --------------- */
  (function headerAndProgress() {
    var header = document.getElementById('appHeader');
    var bar    = document.getElementById('progressBar');

    function onScroll() {
      var y = window.scrollY || document.documentElement.scrollTop;
      if (header) header.classList.toggle('header--scrolled', y > 8);
      if (bar) {
        var max = document.documentElement.scrollHeight - window.innerHeight;
        bar.style.width = (max > 0 ? (y / max) * 100 : 0) + '%';
      }
    }

    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
  })();

  /* ---- Isometric cube grid (canvas) ----------------------- */
  var ISO_SIZE = 28; // cube edge length in px

  function drawIsoCubes(canvas) {
    var parent = canvas.parentElement;
    var w = parent.offsetWidth  || window.innerWidth;
    var h = parent.offsetHeight || 500;
    canvas.width  = w;
    canvas.height = h;

    var ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.clearRect(0, 0, w, h);

    var e  = ISO_SIZE;
    var hw = e * Math.sqrt(3) / 2; // half-width  ≈ e * 0.866
    var hh = e / 2;                // half-height = e * 0.5

    var cols = Math.ceil(w / hw) + 6;
    var rows = Math.ceil(h / hh) + 6;

    for (var r = -3; r < rows; r++) {
      for (var c = -3; c < cols; c++) {
        var cx = w * 0.28 + (c - r) * hw;
        var cy =            (c + r) * hh;

        /* top face */
        ctx.beginPath();
        ctx.moveTo(cx,      cy);
        ctx.lineTo(cx + hw, cy + hh);
        ctx.lineTo(cx,      cy + e);
        ctx.lineTo(cx - hw, cy + hh);
        ctx.closePath();
        ctx.strokeStyle = 'rgba(0,212,255,0.14)';
        ctx.lineWidth   = 0.75;
        ctx.stroke();

        /* left face */
        ctx.beginPath();
        ctx.moveTo(cx - hw, cy + hh);
        ctx.lineTo(cx,      cy + e);
        ctx.lineTo(cx,      cy + e * 2);
        ctx.lineTo(cx - hw, cy + hh + e);
        ctx.closePath();
        ctx.strokeStyle = 'rgba(0,180,220,0.08)';
        ctx.lineWidth   = 0.75;
        ctx.stroke();

        /* right face */
        ctx.beginPath();
        ctx.moveTo(cx,      cy + e);
        ctx.lineTo(cx + hw, cy + hh);
        ctx.lineTo(cx + hw, cy + hh + e);
        ctx.lineTo(cx,      cy + e * 2);
        ctx.closePath();
        ctx.strokeStyle = 'rgba(0,200,240,0.10)';
        ctx.lineWidth   = 0.75;
        ctx.stroke();
      }
    }
  }

  (function initCubeGrids() {
    var gridDivs = document.querySelectorAll('.page-hero__grid, .hero__grid, .login-page__grid');
    if (!gridDivs.length) return;

    gridDivs.forEach(function (div) {
      var canvas = document.createElement('canvas');
      canvas.className = 'hero-canvas';
      canvas.setAttribute('aria-hidden', 'true');
      div.insertBefore(canvas, div.firstChild);
      drawIsoCubes(canvas);
    });

    window.addEventListener('resize', function () {
      document.querySelectorAll('.hero-canvas').forEach(drawIsoCubes);
    }, { passive: true });
  })();

  /* ---- Tabs ------------------------------------------------ */
  // Maps a URL fragment to the tab content it should reveal. The nav links
  // and the post-action redirects use these short hashes, which did not match
  // any element id, so clicking them appeared to do nothing.
  var TAB_HASH_MAP = {
    'domains': 'tab-domains',
    'add':     'tab-add',
    'senders': 'tab-senders',
    'config':  'tab-config'
  };

  window.showTab = function (tabId, el) {
    var target = document.getElementById(tabId);
    if (!target) return;

    document.querySelectorAll('.tab').forEach(function (t) { t.classList.remove('active'); });
    document.querySelectorAll('.tab-content').forEach(function (c) { c.classList.remove('active'); });

    if (el) {
      el.classList.add('active');
    } else {
      // Match the tab button to the panel by its onclick target.
      var match = null;
      document.querySelectorAll('.tab').forEach(function (t) {
        var attr = t.getAttribute('onclick') || '';
        if (attr.indexOf("'" + tabId + "'") !== -1) match = t;
      });
      if (match) match.classList.add('active');
    }

    target.classList.add('active');
  };

  /**
   * Reveal the tab named by the current URL fragment.
   */
  function activateTabFromHash() {
    var hash = (window.location.hash || '').replace(/^#/, '').toLowerCase();
    if (!hash) return;

    var tabId = TAB_HASH_MAP[hash] || (hash.indexOf('tab-') === 0 ? hash : null);
    if (!tabId) return;

    window.showTab(tabId, null);

    // Bring the panel into view, since a hidden element cannot be scrolled to.
    var panel = document.getElementById(tabId);
    if (panel) {
      try { panel.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
      catch (e) { panel.scrollIntoView(); }
    }
  }

  window.activateTabFromHash = activateTabFromHash;

  document.addEventListener('DOMContentLoaded', activateTabFromHash);
  window.addEventListener('hashchange', activateTabFromHash);

  /* ---- Collapsibles ---------------------------------------- */
  window.toggleCollapse = function (el) {
    el.classList.toggle('open');
    var body = el.nextElementSibling;
    if (body) body.classList.toggle('show');
  };

  /* ---- Copy to clipboard ----------------------------------- */
  window.copyText = function (text, btn) {
    var done = function () {
      if (!btn) return;
      var original = btn.textContent;
      btn.textContent = '\u2713 Copied';
      setTimeout(function () { btn.textContent = original; }, 1500);
    };

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, done);
    } else {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); } catch (e) { /* ignore */ }
      document.body.removeChild(ta);
      done();
    }
  };

  /* ---- Escape helper (shared with inline page scripts) ----- */
  window.escapeHtml = function (s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c];
    });
  };
})();
