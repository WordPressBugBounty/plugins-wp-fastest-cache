<?php

    if ( ! defined( 'ABSPATH' ) ) {
        die( 'Invalid request.' );
    }

    function wpfc_security_is_premium() {
        $premium_plugin = 'wp-fastest-cache-premium/wpFastestCachePremium.php';
        $active_plugins = (array) get_option('active_plugins', array());

        if (in_array($premium_plugin, $active_plugins, true)) {
            return true;
        }

        if (is_multisite()) {
            $network_plugins = (array) get_site_option('active_sitewide_plugins', array());
            return isset($network_plugins[$premium_plugin]);
        }

        return false;
    }

    function wpfc_security_trial_expired() {
        if (wpfc_security_is_premium()) {
            return false;
        }

        $trial_started = (int) get_option('wpfc_security_trial_started', 0);
        return $trial_started > 0 && time() >= ($trial_started + (14 * DAY_IN_SECONDS));
    }

    function wpfc_is_enabled() {
        return (bool) get_option('wpfc_fastest_security_enabled', false)
            && (wpfc_security_is_premium() || !wpfc_security_trial_expired());
    }

    function wpfc_get_logs_table_name() {
        global $wpdb;

        return $wpdb->prefix . 'wpfc_security_logs';
    }

    add_action('template_redirect', 'wpfc_log_404_requests');
    add_action('wp_login_failed', 'wpfc_login_failed_handler');
    add_action('register_post', 'wpfc_log_signup_attempt', 10, 3);
    add_action('plugins_loaded', 'wpfc_check_ip_blocklist', 0);
    add_action('plugins_loaded', 'wpfc_expire_security_trial', 1);
    add_action('wpfc_after_ip_block_change', 'wpfc_update_htaccess_blocked_ips');
    add_action('wp_ajax_wpfc_security_manage_logs', 'wpfc_ajax_manage_logs');

    function wpfc_expire_security_trial() {
        if (!wpfc_security_trial_expired() || !get_option('wpfc_fastest_security_enabled', false)) {
            return;
        }

        wpfc_remove_htaccess_blocked_ips();
        update_option('wpfc_fastest_security_enabled', '0', false);
    }

    add_action('register_form', function () {
        if (!wpfc_is_enabled()) {
            return;
        }

        wp_nonce_field('fs_registration_action', 'fs_registration_nonce');
    });

    add_filter('registration_errors', function ($errors, $sanitized_user_login, $user_email) {
        if (!wpfc_is_enabled()) {
            return $errors;
        }

        if (!isset($_POST['fs_registration_nonce']) ||
            !wp_verify_nonce($_POST['fs_registration_nonce'], 'fs_registration_action')) {
            $errors->add('nonce_error', __('<strong>ERROR</strong>: Security check failed. Please try again.'));
        }
        return $errors;
    }, 10, 3);





    function wpfc_create_table() {
        global $wpdb;

        $table_name      = wpfc_get_logs_table_name();
        $charset_collate = $wpdb->get_charset_collate();

        /*
         * dbDelta() only supports a deliberately small subset of CREATE TABLE.
         * Keep every column and key on one line; in particular, it cannot parse
         * SQL comments, standalone character-set clauses, or foreign keys.
         */
        $sql = "CREATE TABLE $table_name (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            ip varchar(45) NOT NULL,
            parent_id bigint(20) unsigned DEFAULT NULL,
            date datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            status tinyint(1) NOT NULL DEFAULT 0,
            type tinyint(1) NOT NULL DEFAULT 0,
            method varchar(10) NOT NULL DEFAULT '',
            url text NOT NULL,
            post_data longtext DEFAULT NULL,
            PRIMARY KEY  (id),
            KEY ip_parent (ip,parent_id),
            KEY parent_id (parent_id)
        ) $charset_collate;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);
    }

    /**
     * Get blocked IPs by type
     *
     * @param int $type The attack type (1 = Malicious Scanning, 2 = Brute Force, etc.)
     * @return array List of blocked IPs for the given type
     */
    function wpfc_get_blocked_ips_by_type($type = -1) {
        global $wpdb;
        $table_name = wpfc_get_logs_table_name();

        $results = $wpdb->get_col(
            $wpdb->prepare(
                "SELECT ip
                 FROM $table_name
                 WHERE status = 1 AND parent_id IS NULL AND type = %d",
                $type
            )
        );

        /**
         * Hook: wpfc_blocked_ips_by_type
         *
         * Allow filtering blocked IPs for a given type.
         *
         * @param array $results List of IPs
         * @param int   $type    The type requested
         */
        return apply_filters('wpfc_blocked_ips_by_type', $results, $type);
    }



    function wpfc_check_ip_blocklist() {
        if (!wpfc_is_enabled() || should_skip_request()) {
            return;
        }

        global $wpdb;
        $table_name = wpfc_get_logs_table_name();

        $visitor_ip = sanitize_text_field($_SERVER['REMOTE_ADDR']);

        $blocked = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM $table_name WHERE ip = %s AND status = 1",
                $visitor_ip
            )
        );

        if ($blocked > 0) {
            // Send 403 Forbidden
            wp_die('Forbidden', '403 Forbidden', array('response' => 403));
            exit;
        }

        wpfc_auto_block_ip();
    }





    function wpfc_prune_old_inactive_logs() {
        global $wpdb;
        $table_name = wpfc_get_logs_table_name();

        // Get blocked parent IDs whose latest parent or child activity is older than 15 days.
        $parent_ids_to_delete = $wpdb->get_col("
            SELECT parent.id
            FROM $table_name AS parent
            LEFT JOIN $table_name AS child ON child.parent_id = parent.id
            WHERE parent.parent_id IS NULL AND parent.status = 0
            GROUP BY parent.id, parent.ip, parent.date
            HAVING GREATEST(parent.date, IFNULL(MAX(child.date), parent.date)) < (NOW() - INTERVAL 15 DAY)
        ");

        if (!empty($parent_ids_to_delete)) {
            // Parent logları sil
            $ids_placeholder = implode(',', array_map('intval', $parent_ids_to_delete));
            $wpdb->query("DELETE FROM $table_name WHERE id IN ($ids_placeholder)");

            // Bu parent'lara bağlı child logları sil
            $wpdb->query("DELETE FROM $table_name WHERE parent_id IN ($ids_placeholder)");
        }
    }


    function wpfc_cleanup_old_blocked_ips() {
        global $wpdb;

        $table_name = wpfc_get_logs_table_name();

        $wpdb->query("
            DELETE p, c
            FROM {$table_name} AS p
            LEFT JOIN {$table_name} AS c
                ON c.parent_id = p.id
            WHERE p.parent_id IS NULL
              AND p.status = 1
              AND p.date < NOW() - INTERVAL 90 DAY
        ");
    }

    function wpfc_update_htaccess_blocked_ips() {

        wpfc_cleanup_old_blocked_ips();

        global $wpdb;

        $htaccess_file = ABSPATH . '.htaccess';

        $table_name = wpfc_get_logs_table_name();

        /* Aktif IP'leri al */
        $blocked_ips = $wpdb->get_col(
            "SELECT DISTINCT ip FROM $table_name WHERE status = 1"
        );

        if (empty($blocked_ips)) {
            
            $new_block  = "# BEGIN WPFC BLOCKED IPS\n";
            $new_block .= "# END WPFC BLOCKED IPS\n\n";

        }else{
            /* IP'leri sırala */
            usort($blocked_ips, function ($a, $b) {
                return ip2long($a) <=> ip2long($b);
            });

            /* Yeni WPFC IP Bloğu */
            $new_block  = "# BEGIN WPFC BLOCKED IPS\n";
            $new_block .= "<FilesMatch \"\\.php$\">\n";
            $new_block .= "    <RequireAll>\n";
            $new_block .= "        Require all granted\n";

            foreach ($blocked_ips as $ip) {
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    $new_block .= "        Require not ip {$ip}\n";
                }
            }

            $new_block .= "    </RequireAll>\n";
            $new_block .= "</FilesMatch>\n";
            $new_block .= "# END WPFC BLOCKED IPS\n\n";
        }




        /* İçeriği oku */
        $content = file_get_contents($htaccess_file);

        if ($content === false) {
            return;
        }


        /* Eski WPFC IP bloğunu sil */
        $pattern = '/# BEGIN WPFC BLOCKED IPS.*?# END WPFC BLOCKED IPS\s*/s';

        $clean = preg_replace($pattern, '', $content);

        if ($clean === null) {
            return;
        }


        /* Baştaki garbage temizle */
        $clean = ltrim($clean);


        /* Final içerik: her zaman EN BAŞTA */
        $final = $new_block . $clean;


        /* Değişiklik yoksa yazma */
        if ($final === $content) {
            return;
        }


        /* ATOMIC WRITE */
        $tmp = $htaccess_file . '.tmp';

        if (file_put_contents($tmp, $final, LOCK_EX) === false) {
            return;
        }

        rename($tmp, $htaccess_file);
    }

    function wpfc_remove_htaccess_blocked_ips() {
        $htaccess_file = ABSPATH . '.htaccess';

        if (!is_file($htaccess_file) || !is_writable($htaccess_file)) {
            return;
        }

        $content = file_get_contents($htaccess_file);
        if ($content === false) {
            return;
        }

        $clean = preg_replace('/# BEGIN WPFC BLOCKED IPS.*?# END WPFC BLOCKED IPS\s*/s', '', $content);
        if ($clean === null || $clean === $content) {
            return;
        }

        file_put_contents($htaccess_file, $clean, LOCK_EX);
    }



    function wpfc_auto_block_ip() {
        global $wpdb;
        $table_name = wpfc_get_logs_table_name();
        $ip_address = sanitize_text_field($_SERVER['REMOTE_ADDR']);

        $results = [];

        $results = $wpdb->get_row($wpdb->prepare(
            "SELECT 
                -- Type 1: Malicious Scanning Attempt
                CASE WHEN SUM(type = 1 AND date > (NOW() - INTERVAL 3 MINUTE)) >= 10 THEN 1 ELSE 0 END AS type1_3min_flag,
                CASE WHEN SUM(type = 1 AND date > (NOW() - INTERVAL 180 MINUTE)) >= 20 THEN 1 ELSE 0 END AS type1_180min_flag,
                CASE WHEN SUM(type = 1 AND date > (NOW() - INTERVAL 1 DAY)) >= 30 THEN 1 ELSE 0 END AS type1_24hours_flag,
                CASE WHEN SUM(type = 1 AND date > (NOW() - INTERVAL 15 DAY)) >= 50 THEN 1 ELSE 0 END AS type1_15days_flag,
                CASE WHEN SUM(type = 1 AND date > (NOW() - INTERVAL 30 DAY)) >= 75 THEN 1 ELSE 0 END AS type1_30days_flag,

                -- Type 2: Brute Force
                CASE WHEN SUM(type = 2 AND date > (NOW() - INTERVAL 1 DAY)) >= 10 THEN 1 ELSE 0 END AS type2_24hours_flag,
                CASE WHEN SUM(type = 2 AND date > (NOW() - INTERVAL 7 DAY)) >= 15 THEN 1 ELSE 0 END AS type2_7days_flag,
                CASE WHEN SUM(type = 2 AND date > (NOW() - INTERVAL 30 DAY)) >= 30 THEN 1 ELSE 0 END AS type2_30days_flag,

                -- Type 3: Multiple Signup Attempts
                CASE WHEN SUM(type = 3 AND date > (NOW() - INTERVAL 1 DAY)) >= 10 THEN 1 ELSE 0 END AS type3_24hours_flag,
                CASE WHEN SUM(type = 3 AND date > (NOW() - INTERVAL 15 DAY)) >= 20 THEN 1 ELSE 0 END AS type3_15days_flag,
                CASE WHEN SUM(type = 3 AND date > (NOW() - INTERVAL 90 DAY)) >= 30 THEN 1 ELSE 0 END AS type3_90days_flag,

                -- Type 4: Remote Code Execution
                CASE WHEN SUM(type = 4 AND date > (NOW() - INTERVAL 7 DAY)) >= 3 THEN 1 ELSE 0 END AS type4_7days_flag,
                CASE WHEN SUM(type = 4 AND date > (NOW() - INTERVAL 30 DAY)) >= 5 THEN 1 ELSE 0 END AS type4_30days_flag,

                -- Type 5: Unsuccessful Signup Attempts
                CASE WHEN SUM(type = 5 AND date > (NOW() - INTERVAL 1 DAY)) >= 10 THEN 1 ELSE 0 END AS type5_24hours_flag,
                CASE WHEN SUM(type = 5 AND date > (NOW() - INTERVAL 90 DAY)) >= 20 THEN 1 ELSE 0 END AS type5_90days_flag,

                -- Type 6: Reconnaissance / Sensitive File Scanning
                CASE WHEN SUM(type = 6 AND date > (NOW() - INTERVAL 2 MINUTE)) >= 10 THEN 1 ELSE 0 END AS type6_2min_flag,
                CASE WHEN SUM(type = 6 AND date > (NOW() - INTERVAL 60 MINUTE)) >= 20 THEN 1 ELSE 0 END AS type6_60min_flag,

                -- Type 7: SQL Injection Attempt
                CASE WHEN SUM(type = 7 AND date > (NOW() - INTERVAL 7 DAY)) >= 3 THEN 1 ELSE 0 END AS type7_7days_flag,
                CASE WHEN SUM(type = 7 AND date > (NOW() - INTERVAL 30 DAY)) >= 5 THEN 1 ELSE 0 END AS type7_30days_flag,

                -- Type 8: Path Traversal / Local File Inclusion
                CASE WHEN SUM(type = 8 AND date > (NOW() - INTERVAL 7 DAY)) >= 3 THEN 1 ELSE 0 END AS type8_7days_flag,
                CASE WHEN SUM(type = 8 AND date > (NOW() - INTERVAL 30 DAY)) >= 5 THEN 1 ELSE 0 END AS type8_30days_flag,

                -- Type 9: Cross-Site Scripting (XSS)
                CASE WHEN SUM(type = 9 AND date > (NOW() - INTERVAL 7 DAY)) >= 3 THEN 1 ELSE 0 END AS type9_7days_flag,
                CASE WHEN SUM(type = 9 AND date > (NOW() - INTERVAL 30 DAY)) >= 5 THEN 1 ELSE 0 END AS type9_30days_flag


            FROM $table_name
            WHERE ip = %s",
            $ip_address
        ), ARRAY_N);




        if (in_array(1, $results)) {
            $wpdb->query(
                $wpdb->prepare(
                    "UPDATE $table_name SET status = %d WHERE ip = %s AND parent_id IS NULL",
                    1,
                    $ip_address
                )
            );

            // Yeni eklenen satır: .htaccess güncelle
            wpfc_update_htaccess_blocked_ips();
        }


    }

    function should_skip_request() {
        // Check if both REMOTE_ADDR (client IP) and SERVER_ADDR (server IP) are set
        if (!isset($_SERVER['REMOTE_ADDR'], $_SERVER['SERVER_ADDR'])) {
            return true;
        }

        // Skip if client IP matches the server IP
        if ($_SERVER['REMOTE_ADDR'] === $_SERVER['SERVER_ADDR']) {
            return true;
        }

        // Skip if user is logged in
        if (function_exists('is_user_logged_in') && is_user_logged_in()) {
            return true;
        }

        // Skip if request is for static assets
        if (isset($_SERVER['REQUEST_URI'])) {
            if (preg_match('/\.(js|css|png|jpe?g|gif|svg|webp|ico|bmp)$/i', $_SERVER['REQUEST_URI'])) {
                return true;
            }
        }

        // Skip WordPress Heartbeat API requests
        // if (isset($_SERVER['REQUEST_URI'], $_POST['action'])) {
        //     if (strpos($_SERVER['REQUEST_URI'], 'admin-ajax.php') !== false && $_POST['action'] === 'heartbeat') {
        //         return true;
        //     }
        // }



        // Otherwise, do not skip
        return false;
    }

    function wpfc_is_sql_injection(){

        foreach ($_POST as $key => $value) {

            if(preg_match('/(?:\\\\\'|\'|%27|";|\'\s*;)\s*(and|or|union|select|sleep|benchmark)/i',$value)){
                return true;
            }

        }

        return false;
    }

    /**
     * Detect path traversal and common local file inclusion attempts in request input.
     *
     * @param mixed $value Request value to inspect.
     * @return bool
     */
    function wpfc_contains_path_traversal($value) {
        if (is_array($value)) {
            foreach ($value as $key => $nested_value) {
                if (wpfc_contains_path_traversal((string) $key) || wpfc_contains_path_traversal($nested_value)) {
                    return true;
                }
            }
            return false;
        }

        if (!is_scalar($value)) {
            return false;
        }

        $candidate = (string) $value;

        // Decode nested URL encoding a bounded number of times to avoid unbounded work.
        for ($i = 0; $i < 3; $i++) {
            $decoded = rawurldecode($candidate);
            if ($decoded === $candidate) {
                break;
            }
            $candidate = $decoded;
        }

        $candidate = str_replace('\\', '/', $candidate);

        // Match parent-directory segments, including encoded/mixed separators after decoding.
        if (preg_match('~(?:^|/)\\.\\.(?:/|$)~', $candidate)) {
            return true;
        }

        // Match common sensitive-file inclusion probes, requiring a path-like context.
        return (bool) preg_match('~(?:^|/)(?:wp-config\\.php|\\.env|passwd|shadow)(?:$|[/?#])~i', $candidate);
    }

    function wpfc_is_path_traversal_attempt() {
        $request_uri = isset($_SERVER['REQUEST_URI']) ? (string) wp_unslash($_SERVER['REQUEST_URI']) : '';

        return wpfc_contains_path_traversal($request_uri)
            || wpfc_contains_path_traversal(wp_unslash($_GET))
            || wpfc_contains_path_traversal(wp_unslash($_POST));
    }

    /**
     * Detect common reflected XSS payloads in request input.
     * This identifies suspicious requests; output escaping is still required
     * wherever a site displays user supplied data.
     *
     * @param mixed $value Request value to inspect.
     * @return bool
     */
    function wpfc_contains_xss_payload($value) {
        if (is_array($value)) {
            foreach ($value as $key => $nested_value) {
                if (wpfc_contains_xss_payload((string) $key) || wpfc_contains_xss_payload($nested_value)) {
                    return true;
                }
            }
            return false;
        }

        if (!is_scalar($value)) {
            return false;
        }

        $candidate = (string) $value;

        // Decode common URL and HTML entity encodings, with a fixed bound.
        for ($i = 0; $i < 3; $i++) {
            $decoded = rawurldecode($candidate);
            $decoded = html_entity_decode($decoded, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            if ($decoded === $candidate) {
                break;
            }
            $candidate = $decoded;
        }

        $patterns = array(
            '~<\\s*script\\b~i',
            '~<\\s*(?:iframe|object|embed)\\b~i',
            '~<\\s*(?:svg|img|body|video|audio|input|details)\\b[^>]*\\bon(?:abort|blur|change|click|error|focus|input|load|mouseover|mouseenter|mouseleave|keydown|keypress|keyup|submit|animationstart|transitionend)\\s*=~is',
            '~\\bon(?:abort|blur|change|click|error|focus|input|load|mouseover|mouseenter|mouseleave|keydown|keypress|keyup|submit|animationstart|transitionend)\\s*=\\s*(?:"[^"]*"|\'[^\']*\'|[^\\s>]+)~i',
            '~javascript\\s*:~i',
            '~data\\s*:\\s*text/html~i'
        );

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $candidate)) {
                return true;
            }
        }

        return false;
    }

    function wpfc_is_xss_attempt() {
        $request_uri = isset($_SERVER['REQUEST_URI']) ? (string) wp_unslash($_SERVER['REQUEST_URI']) : '';

        return wpfc_contains_xss_payload($request_uri)
            || wpfc_contains_xss_payload(wp_unslash($_GET))
            || wpfc_contains_xss_payload(wp_unslash($_POST));
    }

    function wpfc_is_url_using_dangerous_function($url = ""){
        $dangerousFunctions = [
            'new\s*java\s*\.\s*io\s*\.InputStreamReader', // OGNL (Object-Graph Navigation Language) injection
            'php\-cgi\.exe', // php-cgi.exe
            '\/alfacgiapi\/', // /alfacgiapi/perl.alfa , /alfacgiapi/py.alfa
            'eval\-stdin\.php', // eval-stdin.php
            'wp\-plain\.php',
            'f(?:.*?)i(?:.*?)l(?:.*?)e(?:.*?)_(?:.*?)p(?:.*?)u(?:.*?)t(?:.*?)_(?:.*?)c(?:.*?)o(?:.*?)n(?:.*?)t(?:.*?)e(?:.*?)n(?:.*?)t(?:.*?)s' // file_put_contents
        ];


        if (preg_match('/' . implode('|', $dangerousFunctions) . '/i', $url, $matches)) {
            return true;
        }

        return false;
    }


function wpfc_redact_sensitive_post_data($data) {
    if (!is_array($data)) {
        return sanitize_text_field(is_scalar($data) ? (string) $data : '');
    }

    $sensitive_key_pattern = '/(?:pass(?:word)?|passwd|pwd|token|secret|authorization|api[_-]?key|access[_-]?key|client[_-]?secret|nonce|credential|card(?:number)?|cvv|cvc)/i';
    $redacted = array();

    foreach ($data as $key => $value) {
        if (preg_match($sensitive_key_pattern, (string) $key)) {
            $redacted[$key] = '[REDACTED]';
        } elseif (is_array($value)) {
            $redacted[$key] = wpfc_redact_sensitive_post_data($value);
        } else {
            $redacted[$key] = sanitize_text_field(is_scalar($value) ? (string) $value : '');
        }
    }

    return $redacted;
}

function wpfc_insert_log($type = 0){
    if (!wpfc_is_enabled() || should_skip_request()) {
        return;
    }

    global $wpdb;
    $table_name = wpfc_get_logs_table_name();

    $ip_address = sanitize_text_field($_SERVER['REMOTE_ADDR']);
    $url        = sanitize_text_field($_SERVER['REQUEST_URI']);
    $method     = sanitize_text_field($_SERVER['REQUEST_METHOD']);
    $post_data  = (!empty($_POST)) ? sanitize_text_field(print_r(wpfc_redact_sensitive_post_data(wp_unslash($_POST)), true)) : "";

    // Whitelist kontrolü
    if ($wpdb->get_var(
        $wpdb->prepare("SELECT 1 FROM $table_name WHERE ip = %s AND status = 2 LIMIT 1", $ip_address)
    )) {
        return;
    }

    // --- TRANSACTION BAŞLAT ---
    $wpdb->query('START TRANSACTION');

    try {

        /**
         * Parent satırı kilitleyerek alıyoruz.
         * Aynı anda gelen istekler burada sıraya girer.
         */
        $parent_id = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT id 
                 FROM $table_name 
                 WHERE ip = %s AND parent_id IS NULL
                 LIMIT 1
                 FOR UPDATE",
                $ip_address
            )
        );

        if (!$parent_id) {
            // Parent yok → oluştur
            $inserted = $wpdb->insert(
                $table_name,
                [
                    'ip'        => $ip_address,
                    'parent_id'=> null,
                    'method'   => $method,
                    'url'      => $url,
                    'post_data'=> $post_data,
                    'status'   => 0,
                    'type'     => $type,
                ],
                ['%s','%d','%s','%s','%s','%d','%d']
            );

            if (!$inserted) {
                throw new Exception('Parent insert failed');
            }

            $parent_id = $wpdb->insert_id;

        } else {
            // Child ekle
            $inserted = $wpdb->insert(
                $table_name,
                [
                    'ip'        => $ip_address,
                    'parent_id'=> $parent_id,
                    'method'   => $method,
                    'url'      => $url,
                    'post_data'=> $post_data,
                    'status'   => 0,
                    'type'     => $type,
                ],
                ['%s','%d','%s','%s','%s','%d','%d']
            );

            if (!$inserted) {
                throw new Exception('Child insert failed');
            }

            // Parent tarihini güncelle
            $wpdb->query(
                $wpdb->prepare(
                    "UPDATE $table_name SET date = NOW() WHERE id = %d",
                    $parent_id
                )
            );
        }

        // Her şey başarılı → commit
        $wpdb->query('COMMIT');

    } catch (Throwable $e) {
        // Hata varsa rollback
        $wpdb->query('ROLLBACK');

        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('WPFC IP INSERT ERROR: ' . $e->getMessage());
        }
    }
}



    function wpfc_log_signup_attempt($sanitized_user_login, $user_email, $errors) {

        if($errors && $errors->has_errors()){
            wpfc_insert_log(5); // Unsuccessful Signup Attempt
        }else{
            wpfc_insert_log(3); // Multiple Signup Attempts

        }

    }

    function wpfc_login_failed_handler(){
        wpfc_insert_log(2); // Brute Force
    }

    function wpfc_log_404_requests() {

        if (!wpfc_is_enabled()) {
            return;
        }

        $url        = sanitize_text_field($_SERVER['REQUEST_URI']);
        $method     = sanitize_text_field($_SERVER['REQUEST_METHOD']);

        // Dangerous URL check
        if (wpfc_is_url_using_dangerous_function($url)) {
            wpfc_insert_log(4);

        }else if(wpfc_is_path_traversal_attempt()){

            wpfc_insert_log(8);

        }else if(wpfc_is_xss_attempt()){

            wpfc_insert_log(9);

        }else if(wpfc_is_sql_injection()){

            wpfc_insert_log(7);

        }else{

            if (is_404()) {
                
                if ($method === 'GET') {
                    wpfc_insert_log(1);

                }else if ($method === 'HEAD') {
                    wpfc_insert_log(6);

                }else if ($method === 'POST' && preg_match("/(?:\/-){2,}/", $_SERVER['REQUEST_URI'])) {
                    // When a POST request is sent to the rewritten login page, the URL appears as "/-/-/-/-/-/-/-/-/-/-/-/"
                    wpfc_insert_log(2); // Brute Force

                } else {
                    wpfc_insert_log();

                }

            }


        }


        wpfc_prune_old_inactive_logs();
        
    }

    function wpfc_get_type_label($type) {
        $map = array(
            1 => 'Malicious Scanning Attempt',
            2 => 'Brute Force',
            3 => 'Multiple Signup Attempts',
            4 => 'Remote Code Execution',
            5 => 'Unsuccessful Signup Attempt',
            6 => 'Reconnaissance / Sensitive File Scanning',
            7 => 'SQL Injection Attempt',
            8 => 'Path Traversal / Local File Inclusion',
            9 => 'Cross-Site Scripting (XSS) Attempt'
            // Add more types here as needed
        );

        return isset($map[$type]) ? $map[$type] : 'Unknown';
    }

    function wpfc_ajax_manage_logs() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => __('You do not have permission to manage security logs.', 'wp-fastest-cache')), 403);
        }

        check_ajax_referer('wpfc_bulk_action', 'security');

        global $wpdb;
        $table_name = wpfc_get_logs_table_name();
        $operation = sanitize_key($_POST['operation'] ?? '');
        $message = '';
        $remove_ids = array();
        $clear_table = false;

        if ($operation === 'manage_ip') {
            $target_ip = sanitize_text_field(wp_unslash($_POST['target_ip'] ?? ''));
            $ip_status = isset($_POST['ip_status']) ? absint($_POST['ip_status']) : -1;
            if (!filter_var($target_ip, FILTER_VALIDATE_IP) || !in_array($ip_status, array(0, 1, 2), true)) {
                wp_send_json_error(array('message' => __('Invalid IP address or status.', 'wp-fastest-cache')), 400);
            }
            if ($wpdb->update($table_name, array('status' => $ip_status), array('ip' => $target_ip), array('%d'), array('%s')) === false) {
                wp_send_json_error(array('message' => __('Could not update this IP address.', 'wp-fastest-cache')), 500);
            }
            do_action('wpfc_after_ip_block_change');
            $message = $ip_status === 1 ? __('IP address blocked.', 'wp-fastest-cache') : ($ip_status === 2 ? __('IP address whitelisted.', 'wp-fastest-cache') : __('IP address unblocked.', 'wp-fastest-cache'));
        } elseif ($operation === 'bulk') {
            $action = sanitize_key($_POST['bulk_action'] ?? '');
            $ids = isset($_POST['log_ids']) ? array_filter(array_map('absint', (array) $_POST['log_ids'])) : array();
            $allowed_actions = array('delete', 'block', 'unblock', 'whitelist');

            if (empty($ids) || !in_array($action, $allowed_actions, true)) {
                wp_send_json_error(array('message' => __('Select at least one log and an action.', 'wp-fastest-cache')), 400);
            }

            $placeholders = implode(',', array_fill(0, count($ids), '%d'));
            if ($action === 'delete') {
                $wpdb->query($wpdb->prepare("DELETE FROM $table_name WHERE id IN ($placeholders)", ...$ids));
                $message = __('Selected logs deleted.', 'wp-fastest-cache');
            } else {
                $statuses = array('block' => 1, 'unblock' => 0, 'whitelist' => 2);
                $wpdb->query($wpdb->prepare("UPDATE $table_name SET status = %d WHERE id IN ($placeholders)", $statuses[$action], ...$ids));
                $message = __('Selected logs updated.', 'wp-fastest-cache');
            }

            do_action('wpfc_after_ip_block_change');
            $remove_ids = $ids;
        } else {
            wp_send_json_error(array('message' => __('Invalid security action.', 'wp-fastest-cache')), 400);
        }

        wp_send_json_success(array(
            'message' => $message,
            'ip_status' => $operation === 'manage_ip' ? $ip_status : null,
            'remove_ids' => $remove_ids,
            'clear_table' => $clear_table,
            'counts' => array(
                'all' => (int) $wpdb->get_var("SELECT COUNT(*) FROM $table_name WHERE status = 0 AND parent_id IS NULL"),
                'blocked' => (int) $wpdb->get_var("SELECT COUNT(*) FROM $table_name WHERE status = 1 AND parent_id IS NULL"),
                'whitelisted' => (int) $wpdb->get_var("SELECT COUNT(*) FROM $table_name WHERE status = 2 AND parent_id IS NULL"),
            ),
        ));
    }

    function wpfc_render_admin_styles() {
        static $rendered = false;

        if ($rendered) {
            return;
        }

        $rendered = true;
        echo '<style>
            .wpfc-security { position: relative; max-width: 1180px; margin: 20px 20px 0 0; color: #1d2327; }
            .wpfc-security *, .wpfc-security *:before, .wpfc-security *:after { box-sizing: border-box; }
            .wpfc-security[aria-busy="true"]:before { position: absolute; z-index: 10; inset: 0; border-radius: 12px; background: rgba(255, 255, 255, .72); content: ""; cursor: wait; }
            .wpfc-security[aria-busy="true"]:after { position: absolute; z-index: 11; top: 50%; left: 50%; width: 38px; height: 38px; margin: -19px 0 0 -19px; border: 4px solid #d9eaf7; border-top-color: #2271b1; border-radius: 50%; content: ""; animation: wpfc-security-spin .7s linear infinite; }
            @keyframes wpfc-security-spin { to { transform: rotate(360deg); } }
            .wpfc-security__hero { display: flex; justify-content: space-between; gap: 24px; align-items: center; padding: 28px 32px; border-radius: 12px; background: linear-gradient(135deg, #172b4d, #2271b1); color: #fff; box-shadow: 0 8px 24px rgba(23, 43, 77, .16); }
            .wpfc-security__eyebrow { margin: 0 0 6px; color: #b9dcf8; font-size: 12px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
            .wpfc-security__hero h1 { margin: 0; color: #fff; font-size: 28px; line-height: 1.2; }
            .wpfc-security__hero p { max-width: 650px; margin: 8px 0 0; color: #e8f3fb; font-size: 14px; }
            .wpfc-security__hero .button { flex: 0 0 auto; margin: 0; border-color: #f0f6fc; color: #fff; background: transparent; }
            .wpfc-security__hero .button:hover { border-color: #fff; color: #fff; background: rgba(255, 255, 255, .12); }
            .wpfc-security__summary { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; margin: 20px 0; }
            .wpfc-security__summary a { display: block; padding: 18px 20px; border: 1px solid #dcdcde; border-radius: 10px; background: #fff; color: #1d2327; text-decoration: none; box-shadow: 0 1px 2px rgba(0, 0, 0, .04); }
            .wpfc-security__summary a:hover, .wpfc-security__summary a:focus { border-color: #2271b1; box-shadow: 0 0 0 1px #2271b1; }
            .wpfc-security__summary a.is-active { border-color: #2271b1; background: #f0f6fc; box-shadow: inset 0 3px 0 #2271b1; }
            .wpfc-security__summary-label { display: block; color: #50575e; font-size: 13px; font-weight: 600; }
            .wpfc-security__summary-count { display: block; margin-top: 4px; color: #1d2327; font-size: 28px; font-weight: 700; line-height: 1; }
            .wpfc-security__notice { display: none; margin: 0 0 16px; padding: 12px 14px; border-left: 4px solid #00a32a; border-radius: 4px; background: #edfaef; color: #1d6b2a; font-weight: 600; }
            .wpfc-security__notice.is-error { border-color: #d63638; background: #fcf0f1; color: #8a2424; }
            .wpfc-security__notice.is-visible { display: block; }
            .wpfc-security__ip-summary { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 16px; margin: 0 0 16px; padding: 18px 20px; border: 1px solid #dcdcde; border-radius: 8px; background: #fff; }
            .wpfc-security__ip-summary h2 { margin: 0 0 6px; font-size: 18px; }
            .wpfc-security__ip-summary p { margin: 4px 0; color: #646970; }
            .wpfc-security__ip-state { display: inline-block; padding: 3px 9px; border-radius: 999px; background: #f0f0f1; color: #50575e; font-size: 12px; font-weight: 700; }
            .wpfc-security__ip-state.is-active { background: #edfaef; color: #1d6b2a; }
            .wpfc-security__ip-state.is-blocked { background: #fcf0f1; color: #b32d2e; }
            .wpfc-security__ip-state.is-whitelisted { background: #edfaef; color: #1d6b2a; }
            .wpfc-security__ip-controls { display: flex; flex-wrap: wrap; gap: 8px; }
            .wpfc-security__panel { overflow: hidden; border: 1px solid #dcdcde; border-radius: 10px; background: #fff; box-shadow: 0 1px 2px rgba(0, 0, 0, .04); }
            .wpfc-security__toolbar { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 14px 20px; border-bottom: 1px solid #dcdcde; background: #f6f7f7; }
            .wpfc-security__actions { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
            .wpfc-security__actions select { min-width: 145px; min-height: 34px; margin: 0; border-color: #c3c4c7; border-radius: 5px; }
            .wpfc-security__actions .button { min-height: 34px; margin: 0; padding: 0 12px; border-radius: 5px; font-weight: 600; line-height: 32px; }
            .wpfc-security__actions .action { border-color: #2271b1; background: #2271b1; color: #fff; }
            .wpfc-security__actions .action:hover, .wpfc-security__actions .action:focus { border-color: #135e96; background: #135e96; color: #fff; }
            .wpfc-security__actions .button-link-delete { border-color: #d63638; color: #b32d2e; background: #fff; }
            .wpfc-security__actions .button-link-delete:hover, .wpfc-security__actions .button-link-delete:focus { border-color: #b32d2e; color: #fff; background: #b32d2e; }
            .wpfc-security__log-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; padding: 14px 20px; border-bottom: 1px solid #dcdcde; background: #fff; }
            .wpfc-security__log-actions .button { min-height: 34px; margin: 0; padding: 0 12px; border-radius: 5px; font-weight: 600; line-height: 32px; }
            .wpfc-security__log-actions .button-link-delete { border-color: #d63638; color: #b32d2e; background: #fff; }
            .wpfc-security__log-actions .button-link-delete:hover, .wpfc-security__log-actions .button-link-delete:focus { border-color: #b32d2e; color: #fff; background: #b32d2e; }
            .wpfc-security .tablenav-pages { display: flex; align-items: center; gap: 10px; float: none; min-height: 34px; margin: 0; color: #50575e; }
            .wpfc-security .displaying-num { margin: 0; white-space: nowrap; font-size: 12px; }
            .wpfc-security .pagination-links { display: inline-flex; align-items: center; gap: 4px; }
            .wpfc-security .pagination-links .button, .wpfc-security .pagination-links .button.disabled { display: inline-flex; align-items: center; justify-content: center; width: 32px; min-width: 32px; height: 32px; min-height: 32px; margin: 0; padding: 0; border-radius: 5px; line-height: 1; }
            .wpfc-security .pagination-links .button.disabled { border-color: #dcdcde; color: #a7aaad; background: #f0f0f1; }
            .wpfc-security .paging-input { display: inline-flex; align-items: center; gap: 4px; margin: 0 2px; color: #50575e; }
            .wpfc-security .paging-input .current-page { width: 38px; min-width: 38px; height: 32px; min-height: 32px; margin: 0; padding: 0 4px; border-radius: 5px; text-align: center; }
            .wpfc-security .widefat { margin: 0; border: 0; box-shadow: none; }
            .wpfc-security .widefat th, .wpfc-security .widefat td { padding: 13px 16px; vertical-align: middle; }
            .wpfc-security .widefat thead th { color: #50575e; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
            .wpfc-security .widefat a { font-weight: 600; }
            .wpfc-security .widefat .wpfc-security__sort-link { display: inline-flex; align-items: center; gap: 5px; }
            .wpfc-security__sort-icon { color: #787c82; font-size: 14px; line-height: 1; }
            .wpfc-security__sort-link:hover .wpfc-security__sort-icon, .wpfc-security__sort-link:focus .wpfc-security__sort-icon { color: #2271b1; }
            .wpfc-security .widefat.fixed.striped tbody th { padding: 0 3px;}
            .wpfc-security__empty { padding: 42px 20px; color: #646970; text-align: center; }
            .wpfc-security--disabled { max-width: 760px; }
            .wpfc-security--disabled .wpfc-security__hero { display: block; }
            .wpfc-security--disabled .button-primary { margin-top: 18px; }
            @media (max-width: 782px) { .wpfc-security { margin-right: 10px; } .wpfc-security__hero { display: block; padding: 24px; } .wpfc-security__hero .button { margin-top: 18px; } .wpfc-security__summary { grid-template-columns: 1fr; } .wpfc-security__toolbar { display: block; } .wpfc-security__actions { margin-bottom: 14px; } .wpfc-security .tablenav-pages { flex-wrap: wrap; justify-content: flex-start; } }
        </style>';
    }

    function wpfc_display_logs() {
        if (!current_user_can('manage_options')) {
            return;
        }

        wpfc_render_admin_styles();

        if (wpfc_is_enabled() && isset($_POST['wpfc_disable_security'])) {
            check_admin_referer('wpfc_disable_security');
            wpfc_remove_htaccess_blocked_ips();
            update_option('wpfc_fastest_security_enabled', '0', false);
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Security has been disabled.', 'wp-fastest-cache') . '</p></div>';
        }

        if (!wpfc_is_enabled()) {
            if (wpfc_security_trial_expired()) {
                echo '<div class="wpfc-security wpfc-security--disabled">';
                echo '<div class="wpfc-security__hero"><div><p class="wpfc-security__eyebrow">' . esc_html__('WP Fastest Cache', 'wp-fastest-cache') . '</p><h1>' . esc_html__('Security trial ended', 'wp-fastest-cache') . '</h1>';
                echo '<p>' . esc_html__('Your 14-day Security trial has ended. Upgrade to WP Fastest Cache Premium to continue using Security.', 'wp-fastest-cache') . '</p></div>';
                echo '<a class="button button-primary" href="https://www.wpfastestcache.com/#buy" target="_blank" rel="noopener noreferrer">' . esc_html__('Get Premium', 'wp-fastest-cache') . '</a></div></div>';
                return;
            }

            if (isset($_POST['wpfc_enable_security'])) {
                check_admin_referer('wpfc_enable_security');
                if (!get_option('wpfc_security_trial_started', false)) {
                    add_option('wpfc_security_trial_started', time(), '', false);
                }
                wpfc_create_table();
                update_option('wpfc_fastest_security_enabled', '1', false);
                wpfc_update_htaccess_blocked_ips();
                echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Security has been enabled.', 'wp-fastest-cache') . '</p></div>';
            } else {
                echo '<div class="wpfc-security wpfc-security--disabled">';
                echo '<div class="wpfc-security__hero"><div><p class="wpfc-security__eyebrow">' . esc_html__('WP Fastest Cache', 'wp-fastest-cache') . '</p><h1>' . esc_html__('Security Center', 'wp-fastest-cache') . '</h1>';
                echo '<p>' . esc_html__('Security is currently disabled. Enable it to start your 14-day trial and log suspicious requests, block abusive IP addresses, and reduce the server load caused by repeated attacks.', 'wp-fastest-cache') . '</p></div>';
                echo '<form method="post">';
                wp_nonce_field('wpfc_enable_security');
                echo '<input type="hidden" name="wpfc_enable_security" value="1">';
                submit_button(__('Enable Security', 'wp-fastest-cache'), 'primary', 'submit', false);
                echo '</form></div></div>';
                return;
            }
        }

        global $wpdb;
        $table_name = wpfc_get_logs_table_name();

        // Handle bulk actions
        if (isset($_POST['action']) && !empty($_POST['log_ids']) && check_admin_referer('wpfc_bulk_action', 'security')) {
            $ids = array_map('intval', $_POST['log_ids']);
            $placeholders = implode(',', array_fill(0, count($ids), '%d'));



            if (!empty($ids)) {


                switch ($_POST['action']) {
                    case 'delete':
                        $wpdb->query($wpdb->prepare("DELETE FROM $table_name WHERE id IN ($placeholders)", ...$ids));
                        do_action('wpfc_after_ip_block_change'); // <-- htaccess güncelle
                        echo '<div class="notice notice-success is-dismissible"><p>Logs with matching IPs deleted.</p></div>';
                        break;
                    case 'whitelist':
                        $wpdb->query($wpdb->prepare("UPDATE $table_name SET status = 2 WHERE id IN ($placeholders)", ...$ids));
                        do_action('wpfc_after_ip_block_change'); // <-- htaccess güncelle
                        echo '<div class="notice notice-success is-dismissible"><p>Logs with matching IPs blocked.</p></div>';
                        break;
                    case 'block':
                        $wpdb->query($wpdb->prepare("UPDATE $table_name SET status = 1 WHERE id IN ($placeholders)", ...$ids));
                        do_action('wpfc_after_ip_block_change'); // <-- htaccess güncelle
                        echo '<div class="notice notice-success is-dismissible"><p>Logs with matching IPs blocked.</p></div>';
                        break;

                    case 'unblock':
                        $wpdb->query($wpdb->prepare("UPDATE $table_name SET status = 0 WHERE id IN ($placeholders)", ...$ids));
                        do_action('wpfc_after_ip_block_change'); // <-- htaccess güncelle
                        echo '<div class="notice notice-success is-dismissible"><p>Logs with matching IPs unblocked.</p></div>';
                        break;
                }
            }
        }



        // Pagination setup
        $items_per_page = 100;
        $paged = max(1, intval($_GET['paged'] ?? 1));
        $offset = ($paged - 1) * $items_per_page;

        // Filters
        $status_param = $_GET['status'] ?? '';
        $status_filter = in_array($status_param, ['all', 'blocked', 'whitelisted']) ? $status_param : 'all';

        $ip_filter = sanitize_text_field($_GET['ip'] ?? '');



        // Sorting
        $orderby = $_GET['orderby'] ?? 'count';
        $order   = strtoupper($_GET['order'] ?? 'DESC');

        $allowed_orderby = ['count', 'date', 'type'];

        if (!in_array($orderby, $allowed_orderby)) {
            $orderby = 'count';
        }

        if (!in_array($order, ['ASC', 'DESC'])) {
            $order = 'DESC';
        }




        // Build filter links
        $base_url = remove_query_arg(['paged']);
        $all_url = esc_url(add_query_arg('status', 'all', remove_query_arg('ip', $base_url)));
        $blocked_url = esc_url(add_query_arg('status', 'blocked', remove_query_arg('ip', $base_url)));
        $whitelisted_url = esc_url(add_query_arg('status', 'whitelisted', remove_query_arg('ip', $base_url)));


        $where_clause = '';
        $params = [];

        if ($status_filter === 'blocked') {
            $where_clause = 'WHERE parent_id IS NULL AND status = %d';
            $params[] = 1;
        } elseif ($status_filter === 'whitelisted') {
            $where_clause = 'WHERE parent_id IS NULL AND status = %d';
            $params[] = 2;
        } else {
            // By default (Activity Logs page), show only status = 0
            $where_clause = 'WHERE parent_id IS NULL AND status = %d';
            $params[] = 0;
        }

        if (!empty($ip_filter)) {
            $where_clause = 'WHERE ip = %s';
            $params = [$ip_filter];
        }

        // Count query
        $count_query = !empty($ip_filter)
            ? "SELECT COUNT(ip) FROM $table_name $where_clause"
            : "SELECT COUNT(DISTINCT ip) FROM $table_name $where_clause";

        $total_items = !empty($params)
            ? (int) $wpdb->get_var($wpdb->prepare($count_query, ...$params))
            : (int) $wpdb->get_var($count_query);


        $total_pages = ceil($total_items / $items_per_page);

        // Prepare query params for log fetching
        $params[] = $items_per_page;
        $params[] = $offset;


if (!empty($ip_filter)) {

    $order_by_sql = ($orderby === 'date')
        ? "date $order"
        : "date DESC";

    $logs_query = "
        SELECT * FROM $table_name
        $where_clause
        ORDER BY $order_by_sql
        LIMIT %d OFFSET %d
    ";

} else {

    if ($orderby === 'date') {

        $order_by_sql = "p.date $order";

    } elseif ($orderby === 'type') {

        $order_by_sql = "p.type $order";

    } else {

        $order_by_sql = "child_count $order";

    }

    $logs_query = "
        SELECT p.*, 
               (SELECT COUNT(*) FROM $table_name c WHERE c.parent_id = p.id) as child_count
        FROM $table_name p
        $where_clause
        ORDER BY $order_by_sql
        LIMIT %d OFFSET %d
    ";
}


        $logs = $wpdb->get_results($wpdb->prepare($logs_query, ...$params));


        $all_count = (int) $wpdb->get_var("SELECT COUNT(*) FROM $table_name WHERE status = 0 AND parent_id IS NULL");
        $blocked_count = (int) $wpdb->get_var("SELECT COUNT(*) FROM $table_name WHERE status = 1 AND parent_id IS NULL");
        $whitelisted_count = (int) $wpdb->get_var("SELECT COUNT(*) FROM $table_name WHERE status = 2 AND parent_id IS NULL");

        $has_ip_filter = !empty($ip_filter);
        $ip_summary = null;
        $ip_status = 0;
        if ($has_ip_filter) {
            $ip_summary = $wpdb->get_row($wpdb->prepare(
                "SELECT COUNT(*) AS event_count, MAX(date) AS last_activity, MAX(status = 1) AS is_blocked, MAX(status = 2) AS is_whitelisted FROM $table_name WHERE ip = %s",
                $ip_filter
            ));
            if ($ip_summary && (int) $ip_summary->is_blocked) {
                $ip_status = 1;
            } elseif ($ip_summary && (int) $ip_summary->is_whitelisted) {
                $ip_status = 2;
            }
        }

        // Header and log status summary
        echo '<div class="wpfc-security">';
        echo '<div class="wpfc-security__hero"><div><p class="wpfc-security__eyebrow">' . esc_html__('WP Fastest Cache', 'wp-fastest-cache') . '</p><h1>' . esc_html__('Security Center', 'wp-fastest-cache') . '</h1><p>' . esc_html__('Review suspicious requests, manage blocked IP addresses, and keep your activity log under control.', 'wp-fastest-cache') . '</p></div>';
        echo '<form method="post">';
        wp_nonce_field('wpfc_disable_security');
        echo '<input type="hidden" name="wpfc_disable_security" value="1">';
        submit_button(__('Disable Security', 'wp-fastest-cache'), 'secondary', 'submit', false);
        echo '</form></div>';
        if (!wpfc_security_is_premium()) {
            $trial_started = (int) get_option('wpfc_security_trial_started', time());
            $days_remaining = max(1, (int) ceil((($trial_started + (14 * DAY_IN_SECONDS)) - time()) / DAY_IN_SECONDS));
            echo '<p class="notice notice-info">' . sprintf(esc_html(_n('Security trial: %d day remaining.', 'Security trial: %d days remaining.', $days_remaining, 'wp-fastest-cache')), $days_remaining) . '</p>';
        }
        echo '<div class="wpfc-security__summary">';
        echo '<a href="' . $all_url . '" data-security-status="all" class="' . ($status_filter === 'all' && !$has_ip_filter ? 'is-active' : '') . '"><span class="wpfc-security__summary-label">' . esc_html__('Activity logs', 'wp-fastest-cache') . '</span><span class="wpfc-security__summary-count">' . $all_count . '</span></a>';
        echo '<a href="' . $blocked_url . '" data-security-status="blocked" class="' . ($status_filter === 'blocked' && !$has_ip_filter ? 'is-active' : '') . '"><span class="wpfc-security__summary-label">' . esc_html__('Blocked IPs', 'wp-fastest-cache') . '</span><span class="wpfc-security__summary-count">' . $blocked_count . '</span></a>';
        echo '<a href="' . $whitelisted_url . '" data-security-status="whitelisted" class="' . ($status_filter === 'whitelisted' && !$has_ip_filter ? 'is-active' : '') . '"><span class="wpfc-security__summary-label">' . esc_html__('Whitelisted IPs', 'wp-fastest-cache') . '</span><span class="wpfc-security__summary-count">' . $whitelisted_count . '</span></a>';
        echo '</div>';
        echo '<div class="wpfc-security__notice" role="status" aria-live="polite"></div>';
        if ($has_ip_filter && $ip_summary) {
            $ip_status_label = $ip_status === 1 ? __('Blocked', 'wp-fastest-cache') : ($ip_status === 2 ? __('Whitelisted', 'wp-fastest-cache') : __('Active', 'wp-fastest-cache'));
            $ip_status_class = $ip_status === 1 ? ' is-blocked' : ($ip_status === 2 ? ' is-whitelisted' : ' is-active');
            echo '<section class="wpfc-security__ip-summary" data-ip-address="' . esc_attr($ip_filter) . '"><div><h2>' . esc_html__('IP history', 'wp-fastest-cache') . ': <code>' . esc_html($ip_filter) . '</code></h2>';
            echo '<p><span class="wpfc-security__ip-state' . esc_attr($ip_status_class) . '" data-ip-state data-active-label="' . esc_attr__('Active', 'wp-fastest-cache') . '" data-blocked-label="' . esc_attr__('Blocked', 'wp-fastest-cache') . '" data-whitelisted-label="' . esc_attr__('Whitelisted', 'wp-fastest-cache') . '">' . esc_html($ip_status_label) . '</span></p>';
            echo '<p>' . sprintf(esc_html__('%1$s events · Last activity: %2$s', 'wp-fastest-cache'), number_format_i18n((int) $ip_summary->event_count), esc_html($ip_summary->last_activity ?: '—')) . '</p></div>';
            echo '<div class="wpfc-security__ip-controls" data-block-label="' . esc_attr__('Block IP', 'wp-fastest-cache') . '" data-whitelist-label="' . esc_attr__('Whitelist IP', 'wp-fastest-cache') . '" data-unblock-label="' . esc_attr__('Unblock', 'wp-fastest-cache') . '" data-remove-whitelist-label="' . esc_attr__('Remove from whitelist', 'wp-fastest-cache') . '">';
            if ($ip_status !== 1) {
                echo '<button type="button" class="button" data-ip-status="1">' . esc_html__('Block IP', 'wp-fastest-cache') . '</button>';
            }
            if ($ip_status !== 2) {
                echo '<button type="button" class="button" data-ip-status="2">' . esc_html__('Whitelist IP', 'wp-fastest-cache') . '</button>';
            }
            if ($ip_status !== 0) {
                echo '<button type="button" class="button" data-ip-status="0">' . ($ip_status === 2 ? esc_html__('Remove from whitelist', 'wp-fastest-cache') : esc_html__('Unblock', 'wp-fastest-cache')) . '</button>';
            }
            echo '</div></section>';
        }
        echo '<div class="wpfc-security__panel">';

        // Begin form
        echo '<form method="post">';
        wp_nonce_field('wpfc_bulk_action', 'security');

        // Bulk actions UI
        echo '<div class="wpfc-security__toolbar">';
        echo '<div class="wpfc-security__actions">';
        echo '<select name="action">
                <option value="">Bulk actions</option>
                <option value="delete">Delete</option>
                <option value="whitelist">Whitelist</option>';
        if ($status_filter !== 'blocked') {
            echo '<option value="block">Block</option>';
        }
        if ($status_filter !== 'all') {
            echo '<option value="unblock">Unblock</option>';
        }
        if ($status_filter === 'all') {
        }
        if ($status_filter === 'blocked') {
        }
        echo '
             </select>';
        echo '<input type="submit" class="button action" value="Apply">';

        echo '</div>'; // .wpfc-security__actions


        // Pagination UI
        echo '<div class="tablenav-pages"><span class="displaying-num">' . $total_items . ' items</span>';
        echo '<span class="pagination-links">';

        if ($paged > 1) {
            echo '<a class="first-page button" href="' . esc_url(add_query_arg('paged', 1, $base_url)) . '">«</a>';
            echo '<a class="prev-page button" href="' . esc_url(add_query_arg('paged', $paged - 1, $base_url)) . '">‹</a>';
        } else {
            echo '<span class="tablenav-pages-navspan button disabled">«</span>';
            echo '<span class="tablenav-pages-navspan button disabled">‹</span>';
        }

        echo '<span class="paging-input">
                <label for="current-page-selector" class="screen-reader-text">Current Page</label>
                <input class="current-page" id="current-page-selector" type="text" name="paged" value="' . $paged . '" size="2">
                <span class="tablenav-paging-text"> of <span class="total-pages">' . $total_pages . '</span></span>
              </span>';

        if ($paged < $total_pages) {
            echo '<a class="next-page button" href="' . esc_url(add_query_arg('paged', $paged + 1, $base_url)) . '">›</a>';
            echo '<a class="last-page button" href="' . esc_url(add_query_arg('paged', $total_pages, $base_url)) . '">»</a>';
        } else {
            echo '<span class="tablenav-pages-navspan button disabled">›</span>';
            echo '<span class="tablenav-pages-navspan button disabled">»</span>';
        }

        echo '</span></div></div>'; // End toolbar

        // Logs table
        echo '<table class="widefat fixed striped">';
        echo '<thead><tr>';
        echo '<td class="manage-column column-cb check-column"><input type="checkbox" id="cb-select-all"></td>';
        echo '<th>IP</th>';


        $count_order = ($orderby === 'count' && $order === 'DESC') ? 'ASC' : 'DESC';
        $count_sort_url = esc_url(add_query_arg([
            'orderby' => 'count',
            'order'   => $count_order
        ], $base_url));

        echo empty($ip_filter)
            ? '<th><a class="wpfc-security__sort-link" href="' . $count_sort_url . '" data-security-sort>Count <span class="wpfc-security__sort-icon" aria-hidden="true">↕</span></a></th>'
            : '';

            

        $date_order = ($orderby === 'date' && $order === 'DESC') ? 'ASC' : 'DESC';
        $date_sort_url = esc_url(add_query_arg([
            'orderby' => 'date',
            'order'   => $date_order
        ], $base_url));
        echo '<th><a class="wpfc-security__sort-link" href="' . $date_sort_url . '" data-security-sort>Date <span class="wpfc-security__sort-icon" aria-hidden="true">↕</span></a></th>';



        $type_order = ($orderby === 'type' && $order === 'DESC') ? 'ASC' : 'DESC';
        $type_sort_url = esc_url(add_query_arg([
            'orderby' => 'type',
            'order'   => $type_order
        ], $base_url));
        echo '<th><a class="wpfc-security__sort-link" href="' . $type_sort_url . '" data-security-sort>Type <span class="wpfc-security__sort-icon" aria-hidden="true">↕</span></a></th>';




        echo !empty($ip_filter) ? '<th>Method</th>' : '';
        echo !empty($ip_filter) ? '<th>URL</th>' : '';
        echo '</tr></thead><tbody>';



        if (!empty($logs)) {
            $seen_ips = [];

            foreach ($logs as $log) {
                $show_checkbox = !in_array($log->ip, $seen_ips);

                echo '<tr>';
                echo '<th scope="row" class="check-column">';
                echo $show_checkbox
                    ? '<input type="checkbox" name="log_ids[]" value="' . esc_attr($log->id) . '">'
                    : '';
                echo '</th>';

                if ($show_checkbox) $seen_ips[] = $log->ip;

                echo '<td>' . (!empty($ip_filter) ? esc_html($log->ip) : '<a href="' . esc_url(add_query_arg('ip', $log->ip, $base_url)) . '" data-security-ip>' . esc_html($log->ip) . '</a>') . '</td>';
                
                if (empty($ip_filter)) {
                    echo '<td>' . absint(1 + absint($log->child_count)) . '</td>';
                }

                echo '<td>' . esc_html($log->date) . '</td>';
                echo '<td>' . esc_html(wpfc_get_type_label((int) $log->type)) . '</td>';

                if (!empty($ip_filter)) {
                    echo '<td>' . esc_html($log->method) . '</td>';
                    echo '<td>' . "<span style='font-weight: bold;'>URL:</span> ".esc_html($log->url);
                    echo !empty($log->post_data) ? "<br><span style='font-weight: bold;'>Data:</span> ".esc_html($log->post_data) : "";
                    echo '</td>';
                }

                echo '</tr>';
            }
        } else {
            $empty_colspan = empty($ip_filter) ? 5 : 6;
            echo '<tr><td colspan="' . $empty_colspan . '" class="wpfc-security__empty">' . esc_html__('No logs found for this view.', 'wp-fastest-cache') . '</td></tr>';
        }

        echo '</tbody></table>';
        echo '</form>';
        echo '</div></div>'; // .wpfc-security__panel, .wpfc-security

        // JS for changing log views and submitting management actions without a page refresh.
        echo '<script>
            window.wpfcSecurityInit = function(root) {
                root = root || document.querySelector(".wpfc-security");
                const panel = root ? root.querySelector(".wpfc-security__panel") : null;
                const notice = root ? root.querySelector(".wpfc-security__notice") : null;
                const form = panel ? panel.querySelector("form") : null;

                if (!form || typeof ajaxurl === "undefined" || !window.fetch) {
                    return;
                }

                const selectAll = root.querySelector("#cb-select-all");
                if (selectAll) {
                    selectAll.addEventListener("click", function() {
                        form.querySelectorAll(\'input[name="log_ids[]"]\').forEach(function(checkbox) {
                            checkbox.checked = this.checked;
                        }, this);
                    });
                }

                const showNotice = function(message, isError) {
                    notice.textContent = message;
                    notice.className = "wpfc-security__notice is-visible" + (isError ? " is-error" : "");
                };

                const runAction = function(button) {
                    const isBulkAction = button && button.classList.contains("action");
                    const isIpAction = button && button.dataset.ipStatus !== undefined;
                    const operation = isIpAction ? "manage_ip" : (isBulkAction ? "bulk" : (button ? button.name : ""));
                    const validOperations = ["bulk", "manage_ip"];

                    if (validOperations.indexOf(operation) === -1) {
                        return;
                    }

                    const data = new FormData(form);
                    const bulkAction = form.querySelector("select[name=action]").value;
                    data.set("action", "wpfc_security_manage_logs");
                    data.set("operation", operation);
                    data.set("bulk_action", bulkAction);
                    if (isIpAction) {
                        data.set("target_ip", root.querySelector("[data-ip-address]").dataset.ipAddress);
                        data.set("ip_status", button.dataset.ipStatus);
                    }

                    button.disabled = true;
                    form.setAttribute("aria-busy", "true");

                    fetch(ajaxurl, { method: "POST", credentials: "same-origin", body: data })
                        .then(function(response) { return response.json(); })
                        .then(function(response) {
                            if (!response.success) {
                                throw new Error(response.data && response.data.message ? response.data.message : "Security action could not be completed.");
                            }

                            const result = response.data;
                            showNotice(result.message, false);

                            Object.keys(result.counts).forEach(function(status) {
                                const card = root.querySelector("[data-security-status=" + status + "] .wpfc-security__summary-count");
                                if (card) {
                                    card.textContent = result.counts[status];
                                }
                            });

                            if (isIpAction) {
                                const state = root.querySelector("[data-ip-state]");
                                if (state) {
                                    const labels = {0: state.dataset.activeLabel, 1: state.dataset.blockedLabel, 2: state.dataset.whitelistedLabel};
                                    state.textContent = labels[result.ip_status] || labels[0];
                                    state.classList.toggle("is-active", result.ip_status === 0);
                                    state.classList.toggle("is-blocked", result.ip_status === 1);
                                    state.classList.toggle("is-whitelisted", result.ip_status === 2);
                                }
                                const controls = root.querySelector(".wpfc-security__ip-controls");
                                if (controls) {
                                    controls.querySelectorAll("[data-ip-status]").forEach(function(control) {
                                        control.remove();
                                    });
                                    const actions = result.ip_status === 1 ? [2, 0] : (result.ip_status === 2 ? [1, 0] : [1, 2]);
                                    const labels = {
                                        0: result.ip_status === 2 ? controls.dataset.removeWhitelistLabel : controls.dataset.unblockLabel,
                                        1: controls.dataset.blockLabel,
                                        2: controls.dataset.whitelistLabel
                                    };
                                    actions.forEach(function(status) {
                                        const control = document.createElement("button");
                                        control.type = "button";
                                        control.className = "button";
                                        control.dataset.ipStatus = status;
                                        control.textContent = labels[status];
                                        control.addEventListener("click", function() { runAction(control); });
                                        controls.appendChild(control);
                                    });
                                }
                            }

                            if (result.clear_table) {
                                form.querySelector("tbody").innerHTML = "";
                            } else if (result.remove_ids && result.remove_ids.length) {
                                form.querySelectorAll(\'input[name="log_ids[]"]\').forEach(function(checkbox) {
                                    if (result.remove_ids.indexOf(parseInt(checkbox.value, 10)) !== -1) {
                                        checkbox.closest("tr").remove();
                                    }
                                });
                            }

                            const selectAll = root.querySelector("#cb-select-all");
                            if (selectAll) {
                                selectAll.checked = false;
                            }
                        })
                        .catch(function(error) {
                            showNotice(error.message || "Security action could not be completed.", true);
                        })
                        .finally(function() {
                            button.disabled = false;
                            form.removeAttribute("aria-busy");
                        });
                };

                form.querySelectorAll(".action").forEach(function(button) {
                    button.addEventListener("click", function(event) {
                        if (event.defaultPrevented) {
                            return;
                        }
                        event.preventDefault();
                        runAction(button);
                    });
                });

                root.querySelectorAll("[data-ip-status]").forEach(function(button) {
                    button.addEventListener("click", function() {
                        runAction(button);
                    });
                });

                form.addEventListener("submit", function(event) {
                    event.preventDefault();
                });

                const loadSecurityView = function(url) {
                    root.setAttribute("aria-busy", "true");
                    fetch(url, { credentials: "same-origin" })
                        .then(function(response) {
                            if (!response.ok) {
                                throw new Error("Security logs could not be loaded.");
                            }
                            return response.text();
                        })
                        .then(function(html) {
                            const page = new DOMParser().parseFromString(html, "text/html");
                            const nextRoot = page.querySelector(".wpfc-security");

                            if (!nextRoot) {
                                throw new Error("Security logs could not be loaded.");
                            }

                            root.replaceWith(nextRoot);
                            window.history.pushState({}, "", url);
                            window.wpfcSecurityInit(nextRoot);
                        })
                        .catch(function(error) {
                            showNotice(error.message || "Security logs could not be loaded.", true);
                        })
                        .finally(function() {
                            root.removeAttribute("aria-busy");
                        });
                };

                root.querySelectorAll("[data-security-status]").forEach(function(tab) {
                    tab.addEventListener("click", function(event) {
                        event.preventDefault();

                        if (tab.classList.contains("is-active")) {
                            return;
                        }

                        loadSecurityView(tab.href);
                    });
                });

                root.querySelectorAll(".pagination-links a.button").forEach(function(link) {
                    link.addEventListener("click", function(event) {
                        event.preventDefault();
                        loadSecurityView(link.href);
                    });
                });

                root.querySelectorAll("[data-security-sort]").forEach(function(link) {
                    link.addEventListener("click", function(event) {
                        event.preventDefault();
                        loadSecurityView(link.href);
                    });
                });

                root.querySelectorAll("[data-security-ip]").forEach(function(link) {
                    link.addEventListener("click", function(event) {
                        event.preventDefault();
                        loadSecurityView(link.href);
                    });
                });

                const currentPage = root.querySelector("#current-page-selector");
                if (currentPage) {
                    currentPage.addEventListener("change", function() {
                        const url = new URL(window.location.href);
                        url.searchParams.set("paged", currentPage.value || "1");
                        loadSecurityView(url.toString());
                    });
                }
            };

            window.wpfcSecurityInit(document.querySelector(".wpfc-security"));
        </script>';
    }
