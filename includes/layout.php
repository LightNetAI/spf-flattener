<?php
/**
 * Shared layout partials — ATS Solutions branded chrome.
 */

/**
 * Render the top navigation bar.
 *
 * @param Auth   $auth
 * @param string $active  Key of the active nav item
 */
function renderHeader(Auth $auth, $active = '') {
    $user = $auth->user();
    $items = [
        'domains' => ['index.php',        'Domains'],
        'add'     => ['index.php#add',    'Add Domain'],
        'senders' => ['index.php#senders','Senders'],
        'log'     => ['audit.php',        'Audit Log'],
        'users'   => ['users.php',        'Users'],
        'config'  => ['index.php#config', 'Settings'],
    ];
    ?>
    <div class="progress-bar" id="progressBar"></div>
    <header class="header" id="appHeader">
      <div class="container container--wide">
        <div class="header__inner">
          <div class="header__logo">
            <a href="index.php" aria-label="ATS Solutions">
              <img src="assets/img/ats-logo.png" alt="ATS Solutions">
            </a>
            <span class="header__brand-sub">SPF Flattener</span>
          </div>

          <?php if ($user): ?>
          <nav class="nav">
            <?php foreach ($items as $key => [$href, $text]):
                if ($key === 'users' && $user['role'] !== 'admin') { continue; }
            ?>
              <a class="nav__link <?= $active === $key ? 'active' : '' ?>" href="<?= htmlspecialchars($href) ?>"><?= htmlspecialchars($text) ?></a>
            <?php endforeach; ?>
            <div class="header__user">
              <span class="header__user-name"><?= htmlspecialchars($user['display_name']) ?></span>
              <span class="header__user-role"><?= htmlspecialchars($user['role']) ?></span>
              <a class="btn btn-outline btn-sm" href="logout.php">Sign out</a>
            </div>
          </nav>
          <?php endif; ?>
        </div>
      </div>
    </header>
    <?php
}

/**
 * Render the page hero banner, with the ATS isometric cube grid behind it.
 */
function renderHero($title, $subtitle = null, $eyebrow = null, $gridClass = 'page-hero__grid') {
    ?>
    <section class="page-hero">
      <div class="<?= htmlspecialchars($gridClass) ?>" aria-hidden="true"></div>
      <div class="container">
        <div class="page-hero__inner">
          <?php if ($eyebrow): ?><span class="label"><?= htmlspecialchars($eyebrow) ?></span><?php endif; ?>
          <h1 class="h1"><?= htmlspecialchars($title) ?></h1>
          <?php if ($subtitle): ?><p class="lead mt-8"><?= htmlspecialchars($subtitle) ?></p><?php endif; ?>
        </div>
      </div>
    </section>
    <?php
}

/**
 * Flash a message from the session (if any) then clear it.
 */
function renderFlash() {
    if (empty($_SESSION['flash'])) {
        return;
    }
    $flash = $_SESSION['flash'];
    unset($_SESSION['flash']);

    $type = in_array($flash['type'], ['success', 'error', 'warning', 'info'], true) ? $flash['type'] : 'info';
    $icons = ['success' => '✓', 'error' => '✕', 'warning' => '!', 'info' => 'i'];
    ?>
    <div class="alert alert-<?= $type ?>">
      <span class="alert__icon"><?= $icons[$type] ?></span>
      <div><?= htmlspecialchars($flash['message']) ?></div>
    </div>
    <?php
}

/**
 * Queue a flash message.
 */
function setFlash($message, $type = 'success') {
    if (session_status() !== PHP_SESSION_ACTIVE) {
        Auth::startSession();
    }
    $_SESSION['flash'] = ['message' => $message, 'type' => $type];
}

/**
 * Render the page footer.
 */
function renderFooter($extra = null) {
    ?>
    <footer class="footer">
      <div class="container container--wide">
        <div class="footer__inner">
          <div>
            <div class="footer__logo">
              <img src="assets/img/ats-logo-white.svg" alt="ATS Solutions">
            </div>
            <p class="footer__desc mt-8">
              SPF Flattener — resolve <span class="inline-code">include:</span> chains into direct
              <span class="inline-code">ip4:</span> / <span class="inline-code">ip6:</span> entries
              and stay inside the RFC 7208 ten-lookup limit.
            </p>
            <div class="footer__badges">
              <span class="footer__badge">RFC 7208</span>
              <span class="footer__badge">SPF Flattening</span>
              <span class="footer__badge">Cloudflare Sync</span>
            </div>
          </div>
          <div class="footer__meta">
            <?= $extra ? htmlspecialchars($extra) . '<br>' : '' ?>
            SPF Flattener v1.0.0 · ATS Solutions<br>
            <?= date('Y') ?> · All rights reserved
          </div>
        </div>
      </div>
    </footer>
    <?php
}

/**
 * Shared page <head>.
 */
function renderHead($title) {
    ?>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title><?= htmlspecialchars($title) ?> · ATS Solutions SPF Flattener</title>
    <link rel="icon" href="assets/img/ats-logo.png">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="assets/css/app.css">
    <?php
}

/**
 * Shared page scripts. All behaviour lives in assets/js/app.js; page
 * specific logic is added inline by the individual views.
 */
function renderScripts() {
    ?>
    <script src="assets/js/app.js"></script>
    <?php
}
