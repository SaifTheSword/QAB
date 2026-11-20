<?php
/* Grocery POS API. Upload next to grocery-pos.html (same folder). Needs PHP 7.4+ and write access to this folder. */

/* ---------- CONFIG: change these before going live ---------- */
$USERS = [
  'admin'      => ['pass' => 'QABUSMAN',    'pin' => '1234'],
  'superadmin' => ['pass' => 'ChangeMe123', 'pin' => '4321'],
];
$REPORT_USER = 'admin';
$REPORT_PASS = 'QABUSMAN';
$ALLOW_ORIGIN = '';      // '' = same site only. Or e.g. 'https://yourshop.com' if the page is on another domain
$TOKEN_HOURS  = 12;      // how long a sign-in lasts
/* ------------------------------------------------------------ */

$DIR = __DIR__ . '/pos_data';
if (!is_dir($DIR)) {
  @mkdir($DIR, 0750, true); @mkdir("$DIR/reports", 0750, true);
  @file_put_contents("$DIR/.htaccess", "Require all denied\nDeny from all\n");
}
header('Content-Type: application/json');
header('Cache-Control: no-store');
if ($ALLOW_ORIGIN) {
  header("Access-Control-Allow-Origin: $ALLOW_ORIGIN");
  header('Access-Control-Allow-Headers: Content-Type, X-Token');
  header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
}
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') exit;

function out($d, $c = 200) { http_response_code($c); echo json_encode($d); exit; }
function jread($f) { return is_file($f) ? (json_decode(file_get_contents($f), true) ?: []) : []; }
function jwrite($f, $d) { file_put_contents($f, json_encode($d), LOCK_EX); }
function r2($n) { return round($n, 2); }

/* failed-attempt lockout: 5 tries per 10 minutes */
function fl($k, $act) {
  global $DIR; $f = "$DIR/fails.json"; $d = jread($f); $k = md5($k);
  $e = $d[$k] ?? [0, time()]; if (time() - $e[1] > 600) $e = [0, time()];
  if ($act === 'check') return $e[0] >= 5;
  if ($act === 'add') { $e[0]++; $d[$k] = $e; } else unset($d[$k]);
  jwrite($f, $d); return false;
}

$a  = $_GET['a'] ?? '';
$in = json_decode(file_get_contents('php://input'), true) ?: [];

if ($a === 'ping') out(['ok' => true]);

/* ---------- sign in ---------- */
if ($a === 'login') {
  $k = 'l' . ($_SERVER['REMOTE_ADDR'] ?? 'x');
  if (fl($k, 'check')) out(['error' => 'Too many attempts. Try again in 10 minutes.'], 429);
  $u = strtolower((string)($in['user'] ?? '')); $sec = (string)($in['secret'] ?? '');
  $mode = (($in['mode'] ?? '') === 'pin') ? 'pin' : 'pass';
  if (!isset($USERS[$u]) || !hash_equals((string)$USERS[$u][$mode], $sec)) {
    fl($k, 'add'); usleep(600000);
    out(['error' => 'Wrong username or ' . ($mode === 'pin' ? 'PIN' : 'password')], 401);
  }
  fl($k, 'clear');
  $T = jread("$DIR/tokens.json");
  foreach ($T as $t => $v) if ($v['exp'] < time()) unset($T[$t]);
  $tok = bin2hex(random_bytes(24));
  $T[$tok] = ['user' => $u, 'exp' => time() + $TOKEN_HOURS * 3600, 'rep' => 0];
  jwrite("$DIR/tokens.json", $T);
  out(['ok' => true, 'token' => $tok, 'user' => $u]);
}

/* ---------- everything below needs a valid token ---------- */
$tok = $_SERVER['HTTP_X_TOKEN'] ?? ($_GET['t'] ?? '');
$T = jread("$DIR/tokens.json");
if (!isset($T[$tok]) || $T[$tok]['exp'] < time()) out(['error' => 'auth'], 401);

if ($a === 'reportauth') {
  $k = 'r' . $tok;
  if (fl($k, 'check')) out(['error' => 'Too many attempts. Try again in 10 minutes.'], 429);
  $ok = strtolower((string)($in['user'] ?? '')) === $REPORT_USER && hash_equals($REPORT_PASS, (string)($in['password'] ?? ''));
  if (!$ok) { fl($k, 'add'); usleep(600000); out(['error' => 'Wrong username or password'], 403); }
  fl($k, 'clear');
  $T[$tok]['rep'] = time() + 900; jwrite("$DIR/tokens.json", $T);
  out(['ok' => true]);
}

function with_state($fn) {
  global $DIR;
  $h = fopen("$DIR/state.json", 'c+'); flock($h, LOCK_EX);
  $raw = stream_get_contents($h); $S = $raw ? json_decode($raw, true) : null;
  $fn($S);
  if ($S !== null) { ftruncate($h, 0); rewind($h); fwrite($h, json_encode($S)); fflush($h); }
  flock($h, LOCK_UN); fclose($h);
  return $S;
}

function till_exp($S) {
  $t = $S['till']; if (empty($t['open'])) return 0;
  $e = $t['float'];
  foreach ($S['sales'] as $s)   if ($s['method'] === 'cash' && $s['t'] >= $t['openedAt']) $e += $s['total'];
  foreach ($S['settles'] as $s) if ($s['method'] === 'cash' && $s['t'] >= $t['openedAt']) $e += $s['amt'];
  foreach ($t['moves'] as $m) $e += ($m['type'] === 'in') ? $m['amt'] : -$m['amt'];
  return r2($e);
}

function apply(&$S, $o) {
  $uid = $o['uid'] ?? null;
  if ($uid) {
    $S['seen'] = $S['seen'] ?? [];
    if (in_array($uid, $S['seen'], true)) return;
    $S['seen'][] = $uid; if (count($S['seen']) > 500) array_shift($S['seen']);
  }
  switch ($o['k'] ?? '') {
    case 'sale':
      $s = $o['sale']; $s['id'] = $S['n']++; $s['uid'] = $uid;
      foreach ($s['lines'] as $l) foreach ($S['items'] as &$i) if ($i['id'] == $l['id']) { $i['stock'] -= $l['qty']; $i['sold'] = ($i['sold'] ?? 0) + $l['qty']; }
      unset($i);
      if (!empty($s['cust'])) foreach ($S['customers'] as &$c) if ($c['id'] == $s['cust']) $c['bal'] = r2($c['bal'] + $s['total']);
      unset($c);
      $S['sales'][] = $s; break;
    case 'settle':
      foreach ($S['customers'] as &$c) if ($c['id'] == $o['cust']) {
        $c['bal'] = r2($c['bal'] - $o['amt']);
        $S['settles'][] = ['id' => $S['n']++, 't' => $o['t'], 'cust' => $o['cust'], 'custName' => $c['name'], 'amt' => $o['amt'], 'method' => $o['method'], 'by' => $o['by'] ?? ''];
      }
      unset($c); break;
    case 'item':
      $f = false;
      foreach ($S['items'] as &$i) if ($i['id'] == $o['item']['id']) { $i = array_merge($i, $o['item']); $f = true; }
      unset($i); if (!$f) $S['items'][] = $o['item']; break;
    case 'itemdel':
      $S['items'] = array_values(array_filter($S['items'], function ($i) use ($o) { return $i['id'] != $o['id']; })); break;
    case 'stockadd':
      foreach ($S['items'] as &$i) if ($i['id'] == $o['id']) $i['stock'] += $o['n'];
      unset($i); break;
    case 'cust': $S['customers'][] = $o['cust']; break;
    case 'settings':
      foreach (['store', 'tax', 'cur', 'low', 'till'] as $k) if (isset($o['settings'][$k])) $S['settings'][$k] = $o['settings'][$k];
      break;
    case 'tillopen':
      $S['till'] = ['open' => true, 'float' => $o['float'], 'openedAt' => $o['t'], 'by' => $o['by'] ?? '', 'moves' => []]; break;
    case 'tillmove':
      if (!empty($S['till']['open'])) $S['till']['moves'][] = ['t' => $o['t'], 'type' => $o['type'], 'amt' => $o['amt'], 'note' => $o['note'] ?? '', 'by' => $o['by'] ?? '']; break;
    case 'tillclose':
      if (!empty($S['till']['open'])) {
        $e = till_exp($S);
        $S['tillLog'][] = ['openedAt' => $S['till']['openedAt'], 'closedAt' => $o['t'], 'float' => $S['till']['float'], 'expected' => $e, 'counted' => $o['counted'], 'variance' => r2($o['counted'] - $e), 'by' => $o['by'] ?? '', 'openedBy' => $S['till']['by'] ?? ''];
        $S['till']['open'] = false;
      } break;
  }
}

if ($a === 'state') { $S = null; with_state(function (&$s) use (&$S) { $S = $s; }); out(['state' => $S]); }

if ($a === 'init') {   // first device only: creates the shared database
  $S = with_state(function (&$s) use ($in) { if ($s === null && isset($in['state']['items'])) $s = $in['state']; });
  out(['state' => $S]);
}

if ($a === 'op' && isset($in['op'])) {
  $o = $in['op']; $ready = true;
  $S = with_state(function (&$s) use ($o, &$ready) { if ($s === null) { $ready = false; return; } apply($s, $o); });
  if (!$ready) out(['error' => 'not initialised'], 409);
  out(['state' => $S]);
}

if ($a === 'report') {   // save a daily PDF on the server
  $d = $_GET['date'] ?? '';
  if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $d)) out(['error' => 'bad date'], 400);
  $bin = base64_decode(preg_replace('#^data:application/pdf[^,]*,#', '', (string)($in['pdf'] ?? '')), true);
  if (!$bin || substr($bin, 0, 4) !== '%PDF') out(['error' => 'bad pdf'], 400);
  file_put_contents("$DIR/reports/$d.pdf", $bin);
  $S = with_state(function (&$s) use ($d) {
    if ($s === null) return;
    $s['archive'] = array_values(array_filter($s['archive'] ?? [], function ($x) use ($d) { return $x['date'] !== $d; }));
    $s['archive'][] = ['date' => $d];
    if (($s['reported'] ?? '') < $d) $s['reported'] = $d;
  });
  out(['state' => $S]);
}

if ($a === 'reportfile') {   // download a saved PDF (reports must be unlocked)
  if (($T[$tok]['rep'] ?? 0) < time()) out(['error' => 'Reports are locked'], 403);
  $d = $_GET['date'] ?? '';
  if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $d) || !is_file("$DIR/reports/$d.pdf")) out(['error' => 'not found'], 404);
  header('Content-Type: application/pdf'); readfile("$DIR/reports/$d.pdf"); exit;
}

out(['error' => 'unknown action'], 404);
