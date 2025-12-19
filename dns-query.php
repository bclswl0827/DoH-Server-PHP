<?php

$upstreams = [
    "https://1.0.0.1/dns-query",
    "https://8.8.4.4/dns-query",
    "https://208.67.220.220/dns-query",
    "https://dns.nextdns.io/dns-query",
    "https://doh.opendns.com/dns-query",
    "https://unfiltered.adguard-dns.com/dns-query",
    "https://freedns.controld.com/p0",
    "https://public.dns.iij.jp/dns-query",
    "https://doh.dns.sb/dns-query",
    "https://jp.tiar.app/dns-query",
    "https://dns.dnsguard.pub/dns-query",
    "https://doh.cleanbrowsing.org/doh/security-filter/",
    "https://wikimedia-dns.org/dns-query",
    "https://doh.ffmuc.net/dns-query",
    "https://sky.rethinkdns.com/dns-query"
];

$cache_ttl = 600;
$batch_size = 3;

function now_ms()
{
    return (int) round(microtime(true) * 1000);
}

function error_json($code, $message)
{
    http_response_code($code);
    header("Content-Type: application/json");
    echo json_encode(
        [
            "error" => [
                "timestamp" => now_ms(),
                "code" => $code,
                "message" => $message,
            ],
        ],
        JSON_UNESCAPED_UNICODE
    );
    exit();
}

$method = $_SERVER["REQUEST_METHOD"] ?? "GET";
if (!in_array($method, ["GET", "POST"])) {
    error_json(405, "Method Not Allowed: only GET/POST supported");
}

$extra_query = "";
if ($method === "GET") {
    if (!empty($_SERVER["QUERY_STRING"])) {
        parse_str($_SERVER["QUERY_STRING"], $params);
        if ($params) {
            $extra_query = "?" . http_build_query($params);
        }
    } else {
        error_json(400, "Bad Request: GET must include query parameters");
    }
}

$body = file_get_contents("php://input");
$cache_key = "doh_" . md5($method . ":" . $extra_query . ":" . $body);

if (function_exists("apcu_fetch")) {
    $cached = apcu_fetch($cache_key);
    if ($cached !== false) {
        header("Content-Type: application/dns-message");
        echo $cached;
        exit();
    }
}

shuffle($upstreams);

function query_batch(
    array $batch,
    string $method,
    string $extra_query,
    string $body,
    int $cache_ttl,
    string $cache_key
) {
    $mh = curl_multi_init();
    $chs = [];

    foreach ($batch as $up) {
        $ch = curl_init($up . $extra_query);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                "Content-Type: application/dns-message",
                "Accept: application/dns-message",
            ],
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_TIMEOUT => 4,
            CURLOPT_FORBID_REUSE => false,
            CURLOPT_FRESH_CONNECT => false,
        ]);
        curl_multi_add_handle($mh, $ch);
        $chs[(int) $ch] = $ch;
    }

    $running = null;
    $first_failure = null;

    do {
        curl_multi_exec($mh, $running);

        while ($info = curl_multi_info_read($mh)) {
            $ch = $info["handle"];
            if (
                $info["result"] === CURLE_OK &&
                curl_getinfo($ch, CURLINFO_HTTP_CODE) === 200
            ) {
                $resp = curl_multi_getcontent($ch);
                if (strlen($resp) >= 4) {
                    $rcode = ord($resp[3]) & 0x0f;
                } else {
                    $rcode = 2;
                }

                if ($rcode === 0) {
                    if (function_exists("apcu_store")) {
                        apcu_store($cache_key, $resp, $cache_ttl);
                    }
                    header("Content-Type: application/dns-message");
                    echo $resp;

                    foreach ($chs as $c) {
                        curl_multi_remove_handle($mh, $c);
                        curl_close($c);
                    }
                    curl_multi_close($mh);
                    exit();
                } else {
                    if ($first_failure === null) {
                        $first_failure = $resp;
                    }
                }
            }
            curl_multi_remove_handle($mh, $ch);
            curl_close($ch);
            unset($chs[(int) $ch]);
        }

        if ($running) {
            curl_multi_select($mh, 0.1);
        }
    } while ($running);

    curl_multi_close($mh);
    return $first_failure;
}

$first_failure = null;
for ($i = 0; $i < count($upstreams); $i += $batch_size) {
    $batch = array_slice($upstreams, $i, $batch_size);
    $res = query_batch(
        $batch,
        $method,
        $extra_query,
        $body,
        $cache_ttl,
        $cache_key
    );
    if ($res !== null) {
        if (function_exists("apcu_store")) {
            apcu_store($cache_key, $res, $cache_ttl);
        }
        header("Content-Type: application/dns-message");
        echo $res;
        exit();
    }
}

error_json(502, "All upstream DoH failed");
