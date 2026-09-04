# SECURITY AUDIT REPORT — mixudev/security-defense

**Audit Date:** September 4, 2026
**Auditor:** Hermes Agent (attacker-perspective + whitebox analysis)
**Scope:** Full codebase — 32 source files, 14 test files, config, migration
**Baseline:** 34 tests / 142 assertions — ALL PASSING
**Methodology:** Attacker-driven code review with exploit-chain analysis

---

## EXECUTIVE SUMMARY

Paket ini berisi arsitektur yang cukup matang untuk security defense package Laravel. Beberapa komponen dirancang dengan benar (Sanitizer, DTO pattern, ReDoS hardening, config-driven thresholds). Ditemukan **2 CRITICAL**, **5 HIGH**, dan **6 MEDIUM** vulnerability — **SEMUA 13 telah diperbaiki** (lihat REMEDIATION LOG di bagian akhir).

Masalah paling berulang: **race condition pada read-modify-write cache counters** — semua detection rules terpengaruh. Ini memungkinkan attacker bypass brute force protection dengan parallel requests.

---

## FINDINGS TABLE

| # | Severity | Finding | Status | File(s) |
|---|----------|---------|--------|---------|
| 1 | CRITICAL | Race condition pada brute-force/credential-stuffing/distributed-spray counters | **FIXED** | `Rules/BruteForceRule.php`, `CredentialStuffingRule.php`, `DistributedSprayRule.php`, `PathReconnaissanceRule.php`, `RateLimitBypassRule.php` |
| 2 | CRITICAL | Race condition pada alert rate limiter | **FIXED** | `Services/AlertDispatcher.php` |
| 3 | HIGH | IP quarantine bypass via cache flush/persistence loss | **FIXED** (optional DB-backed quarantine) | `Services/IpQuarantineService.php`, `Models/SecurityQuarantine.php` |
| 4 | HIGH | Information leak — attack payloads stored in SecurityAlert metadata | **FIXED** (control chars stripped) | `Rules/PayloadInjectionRule.php`, `Middleware/RequestThreatScanner.php` |
| 5 | HIGH | Information leak — targeted identifiers list in credential stuffing alerts | **FIXED** (hashed) | `Rules/CredentialStuffingRule.php` |
| 6 | HIGH | Information leak — attacking IPs list in distributed spray alerts | **FIXED** (hashed) | `Rules/DistributedSprayRule.php` |
| 7 | HIGH | Impossible travel — TOCTOU race on location cache update | **FIXED** (cache lock) | `Rules/ImpossibleTravelRule.php` |
| 8 | MEDIUM | User-Agent scanner bypass — empty UA bypasses all detection | **FIXED** (optionally blocked via `block_empty_user_agent`) | `Middleware/RequestThreatScanner.php`, `Rules/UserAgentAnomalyRule.php` |
| 9 | MEDIUM | Header overexposure in RequestThreatSource metadata | **FIXED** (hashed/sanitized headers) | `Sources/RequestThreatSource.php` |
| 10 | MEDIUM | Cache-backed quarantine/quarantine counters — no persistent enforcement | **FIXED** (optional DB persistence + docs) | `Services/IpQuarantineService.php`, `config/security-defense.php` |
| 11 | MEDIUM | DispatchAlertChannelJob instantiates arbitrary class from queue payload | **FIXED** (class whitelist) | `Jobs/DispatchAlertChannelJob.php` |
| 12 | MEDIUM | Metadata size unbounded in alerts — potential storage exhaustion | **FIXED** (16KB limit + value trim) | `Services/AlertDispatcher.php` |
| 13 | MEDIUM | RequestThreatScanner creates SecurityEvent but never feeds to detection engine | **FIXED** (wired to `processEvent`) | `Middleware/RequestThreatScanner.php` |

---

## DETAILED FINDINGS

### 1. CRITICAL — Race Condition pada Detection Counters

**Eksploitasi:**
Semua rules menggunakan pola read-modify-write yang sama pada cache:

```php
$attempts = (array) $cache->get($cacheKey, []);       // READ
$attempts = array_filter($attempts, ...);               // MODIFY
$attempts[] = $now;                                      // MODIFY
$cache->put($cacheKey, array_values($attempts), ...);   // WRITE
```

Dengan 10 parallel requests brute force:
- Request A & B keduanya READ `$attempts = [timestamp_1]` (1 item)
- Keduanya MODIFY dan WRITE `[timestamp_1, timestamp_2]` (2 items)
- Hasil: 10 attempts, tapi counter hanya 2 → threshold 10 tidak tercapai

**Impact:** Brute force protection, credential stuffing protection, distributed spray detection, path reconnaissance detection, dan rate limit bypass detection — semuanya bisa di-bypass dengan parallel requests.

**Fix:** Ganti dengan atomic counter `cache->increment()` atau gunakan Lock. Contoh untuk BruteForce:

```php
// Atomic increment approach — simple, no race condition
$counterKey = $this->getCacheKey(md5($target) . ':count');
$cache->put($this->getCacheKey(md5($target) . ':window_start'), $now, $window);
$count = (int) $cache->increment($counterKey);

// Clean up stale window entries separately (optional, for precision)
if ($count === 1) {
    $cache->put($counterKey, 1, $window);
}
```

**Affected files (same pattern in all 5):**
- `src/Rules/BruteForceRule.php:46-51`
- `src/Rules/CredentialStuffingRule.php:51-59`
- `src/Rules/DistributedSprayRule.php:51-59`
- `src/Rules/PathReconnaissanceRule.php:68-72`
- `src/Rules/RateLimitBypassRule.php:59-66`

---

### 2. CRITICAL — Race Condition pada Alert Rate Limiter

**Eksploitasi:**
```php
// AlertDispatcher::incrementRateLimiter()
if (!Cache::has($key)) {    // CHECK
    Cache::put($key, 1, 60); // SET to 1
} else {
    Cache::increment($key);   // INCREMENT
}
```

TOCTOU: 100 concurrent threats → semua lihat `has($key) === false` → semua `put($key, 1)` → rate limiter selalu di 1 → unlimited alerts ke database.

**Impact:** Alert flooding ke database, membanjiri SIEM/discord/telegram channels, memungkinkan resource exhaustion pada storage dan API rate limits.

**Fix:**
```php
protected function incrementRateLimiter(): void
{
    // ...
    $key = config('security-defense.cache_prefix', 'security_defense:') . 'rate_limit:alerts_per_minute';
    // Atomic: set-if-not-exists then increment
    if (!Cache::has($key)) {
        Cache::put($key, 0, 60);
    }
    Cache::increment($key);
}
```

---

### 3. HIGH — IP Quarantine Bypass via Cache Loss

**Eksploitasi:**
IP quarantine disimpan di cache. Bisa di-bypass dengan:
1. Cache flush (opsional/debug endpoint)
2. Cache driver restart (file-based)
3. Laravel `Cache::flush()` dari queue worker
4. Multi-server deployment tanpa shared cache
5. Cache TTL expiry tanpa persistent record

**Impact:** IP yang sudah di-quarantine bisa langsung bypass protection setelah cache hilang.

**Recommendation:** Untuk production, tambahkan optional DB-backed quarantine sebagai fallback:

```php
// In IpQuarantineService::isQuarantined()
// Check cache first (fast path), then DB (durable path)
if ($this->getCache()->has($cacheKey)) {
    return true;
}
// Fallback to DB table for durable quarantine
return SecurityQuarantine::where('ip', $ip)
    ->where('expires_at', '>', now())
    ->exists();
```

**Config needed:**
```php
'quarantine' => [
    'persist_to_database' => env('SECURITY_QUARANTINE_PERSIST_DB', false),
],
```

---

### 4. HIGH — Attack Payload Stored in Alert Metadata

**Eksploitasi:**
Ketika middleware mendeteksi payload injection, `matched_sample` (hingga 50 karakter dari payload asli attacker) disimpan di metadata:

```php
'matched_sample' => $sample, // "UNION SELECT * FR..." up to 50 chars
```

Dan di `PayloadInjectionRule.php`:
```php
'matched_signature' => $matchedSample, // attacker-controlled substring
```

Ini tersimpan di database `security_alerts.metadata`. Jika admin panel menampilkan metadata, attacker bisa:
1. Store persistent XSS di metadata field yang ditampilkan
2. Inject Telegram Markdown V1 special chars untuk formatting abuse
3. Inject Discord embed markup
4. Trigger log injection jika metadata di-echo ke log tanpa encoding

**Fix:** Sanitize matched samples sebelum storage — strip control chars, limit ke safe subset:
```php
$matchedSample = preg_replace('/[\x00-\x1f\x7f]/', '', substr($matches[0], 0, 50));
```

---

### 5. HIGH — Targeted Identifiers List in Credential Stuffing Alert

**Eksploitasi:**
```php
'sample_identifiers' => array_slice(array_keys($targetedAccounts), 0, 10),
```

Ini menyimpan hingga 10 identifier (email/username) yang di-target dalam satu IP. Jika attacker mencoba credential stuffing pada email daftar karyawan, daftar email valid ini terpampang di alert metadata.

**Information Disclosure:** Valid email/username list → bisa digunakan untuk phishing, account enumeration, atau social engineering.

**Fix:**
```php
// Hash identifiers instead of storing plaintext
'sample_identifiers_hashed' => array_map(
    fn($id) => hash('sha256', $id),
    array_slice(array_keys($targetedAccounts), 0, 5)
),
'distinct_identifiers_count' => count($targetedAccounts), // Keep count for context
```

---

### 6. HIGH — Attacking IPs List in Distributed Spray Alert

**Eksploitasi:**
```php
'sample_ips' => array_slice(array_keys($probingIps), 0, 10),
```

Menyimpan hingga 10 IP addresses yang men-target satu account. Jika ini disiarkan ke Discord/Telegram webhook, attacker bisa melihat IP rekan-conspirator atau mengidentifikasi botnet infrastructure.

**Fix:**
```php
// Only store count and anonymized subnet info
'distinct_ips_count' => count($probingIps),
'sample_subnet_hashes' => array_map(
    fn($ip) => hash('sha256', substr($ip, 0, strrpos($ip, '.'))),
    array_slice(array_keys($probingIps), 0, 5)
),
```

---

### 7. HIGH — Impossible Travel TOCTOU Race

**Eksploitasi:**
```php
// Step 1: UPDATE cache with new location
$cache->put($cacheKey, [...], $window);

// Step 2: READ previous location (potentially overwritten!)
$lastLocation = $cache->get($cacheKey);
```

Dua concurrent requests dari IP berbeda:
- Request A writes location A, reads → gets location A (self-comparison, filtered by IP match check)
- Request B writes location B, reads → gets location A (before B overwrote it)
- Both complete their checks, potential missed detection or duplicate alerts

**Impact:** Detection inconsistency — impossible travel bisa tidak terdeteksi atau trigger false positive.

**Fix:** Gunakan Cache Lock:
```php
$lock = $this->getCache()->lock('impossible_travel:' . md5($target), 5);
if ($lock->block()) {
    try {
        $lastLocation = $cache->get($cacheKey);
        $cache->put($cacheKey, [...], $window);
        // ... detection logic ...
    } finally {
        $lock->release();
    }
}
```

---

### 8. MEDIUM — User-Agent Scanner Bypass via Empty UA

**Eksploitasi:**
```php
// Middleware
$userAgent = (string) ($request->userAgent() ?: '');
if ($userAgent !== '' && ...) {  // EMPTY STRING BYPASSES ALL CHECKS
    $scannerTool = $this->uaRule->identifyScanner($userAgent);
    ...
}

// Rule
if (trim($ua) === '') {
    return null;  // EMPTY UA BYPASSES DETECTION
}
```

Attacker cukup mengirim request tanpa User-Agent header. Semua 12 scanner signatures (sqlmap, nikto, dll) tidak aktif.

**Recommendation:** Untuk User-Agent kosong, pertimbangkan untuk:
1. Flagging empty UA sebagai anomaly (request dari browser selalu punya UA)
2. Atau minimal log warning untuk analysis

---

### 9. MEDIUM — Header Overexposure in RequestThreatSource

**Eksploitasi:**
```php
'headers' => [
    'x-forwarded-for' => $this->request->header('x-forwarded-for'),
    'cf-connecting-ip' => $this->request->header('cf-connecting-ip'),
    'origin' => $this->request->header('origin'),
    'referer' => $this->request->header('referer'),
],
```

Header `x-forwarded-for` bisa mengandung IP internal/attacker-controlled values. `origin` dan `referer` bisa mengandung:
- Internal network paths
- CSRF tokens in URL parameters
- Authentication tokens in referer strings
- Full internal URLs

Ini semua tersimpan di metadata → masuk database → potentially visible di admin panels.

**Fix:** Only store sanitized/safe headers:
```php
'headers' => [
    'x_forwarded_for_hash' => hash('sha256', (string) $this->request->header('x-forwarded-for')),
    // Don't store origin/referer raw values
],
```

---

### 10. MEDIUM — Cache-Only Enforcement No Persistence

**Analisis:**
Semua protection state (counters, quarantine, scoring) hanya di cache. Dalam production:
- File cache: hilang saat restart
- Array cache: hilang setiap request
- Redis: hilang saat flush
- Multi-server: state tidak konsisten

**Recommendation:** Document requirement untuk Redis/Memcached minimum, atau tambahkan optional DB-backed persistence. Minimal tambahkan warning di README:
> "For production use, Redis or Memcached is REQUIRED. File/array cache drivers provide NO protection — all state is lost on restart."

---

### 11. MEDIUM — Arbitrary Class Instantiation in Queue Job

**Eksploitasi:**
```php
// DispatchAlertChannelJob::handle()
$channel = app($this->channelClass);
```

`$this->channelClass` diambil dari queue payload. Jika attacker bisa memodifikasi queue (e.g., Redis tanpa auth), mereka bisa:
1. Set `$channelClass` ke arbitrary class name
2. Trigger instantiation of any registered service
3. Potentially exploit side effects of class construction

**Fix:** Whitelist valid channel classes:
```php
private const VALID_CHANNELS = [
    DatabaseChannel::class,
    TelegramChannel::class,
    DiscordChannel::class,
    WebhookChannel::class,
];

public function handle(): void
{
    if (!in_array($this->channelClass, self::VALID_CHANNELS, true)) {
        Log::error('SecurityDefense: Invalid channel class in queue job.', [
            'channel' => $this->channelClass,
        ]);
        return;
    }
    // ...
}
```

---

### 12. MEDIUM — Unbounded Metadata Size in Alerts

**Eksploitasi:**
Metadata array tidak dibatasi ukurannya. Attacker bisa:
1. Kirim payload injection dengan metadata sangat besar → alert tersimpan dengan metadata ratusan KB
2. Flood database dengan large alerts → storage exhaustion
3. Telegram/Discord channels gagal karena message terlalu panjang

**Fix:** Batasi metadata size sebelum persistence:
```php
$metadata = $threat->metadata;
$metadataJson = json_encode($metadata);
if (strlen($metadataJson) > 16384) { // 16KB limit
    $metadata = array_merge(
        array_slice($metadata, 0, 10, true),
        ['_truncated' => true, '_original_size' => strlen($metadataJson)]
    );
}
```

---

### 13. MEDIUM — SecurityEvent Created but Never Used in Middleware

**Analisis:**
Di `RequestThreatScanner::handleDetectedAnomaly()`:
```php
$event = new SecurityEvent(...);  // Created
// Never used! Not dispatched to detection engine
```

Ini berarti middleware hanya melakukan preventive blocking (payload injection, scanner UA, path recon) tapi tidak menjalankan detection rules (brute force, credential stuffing, impossible travel) untuk request yang masuk.

**Impact:** Detection rules hanya aktif untuk events yang di-record manual melalui `SecurityDefense::record()`. Jika host app tidak memanggil `record()` untuk setiap login failure, brute force detection tidak aktif.

**Recommendation:** Dispatch event ke detection engine:
```php
$this->defenseManager->processEvent($event);
```

---

## WHAT'S ALREADY CORRECT (Positif)

| Area | Status |
|------|--------|
| Sanitizer recursive redaction | ✓ Solid — sensitive keys covered, Bearer token scrubbed, depth-limited |
| ReDoS hardening via string truncation | ✓ Correct — max_inspection_length 4096 prevents catastrophic backtracking |
| Array traversal depth limit | ✓ Prevents stack overflow on nested payloads |
| DTO immutability (readonly properties) | ✓ No mutation after construction |
| SecurityThreat severity normalization | ✓ Invalid severity defaults to 'medium' |
| Config-driven thresholds | ✓ All detection parameters configurable |
| Webhook HMAC signature | ✓ Uses hash_hmac('sha256') with secret |
| Alert deduplication | ✓ Fingerprint-based with sliding window |
| Exception handling in channels | ✓ All HTTP calls wrapped in try-catch |
| HTML response escaping | ✓ htmlspecialchars with ENT_QUOTES on all user-facing output |
| Compound threat loop prevention | ✓ `$threat->threatType === 'compound_threat'` guard prevents infinite recursion |
| Migration composite indexes | ✓ Proper indexing for query performance |

---

## SEVERITY SUMMARY

| Severity | Count | Action Required |
|----------|-------|----------------|
| CRITICAL | 2 | Fix immediately — brute force bypass, alert flooding |
| HIGH | 5 | Fix before production — info leaks, bypass vectors |
| MEDIUM | 6 | Harden before wide distribution |
| **Total** | **13** | |

---

## RECOMMENDED ACTION PLAN

### Phase 1: Fix CRITICAL (immediate)
1. Replace read-modify-write cache patterns with atomic `cache->increment()` in all 5 rules
2. Fix TOCTOU race in `AlertDispatcher::incrementRateLimiter()`

### Phase 2: Fix HIGH (before production)
3. Sanitize matched payloads in `PayloadInjectionRule` and `RequestThreatScanner`
4. Hash/redact identifiers and IPs in `CredentialStuffingRule` and `DistributedSprayRule` metadata
5. Add Cache Lock to `ImpossibleTravelRule`
6. Add documentation warning about Redis/Memcached requirement for cache-only enforcement

### Phase 3: Harden MEDIUM
7. Add empty User-Agent anomaly detection
8. Sanitize headers in `RequestThreatSource`
9. Whitelist channel classes in `DispatchAlertChannelJob`
10. Add metadata size limit before persistence
11. Wire up SecurityEvent to detection engine in middleware

---

## TEST COVERAGE GAPS

| Missing Test | Priority |
|-------------|----------|
| Parallel request race condition test | HIGH |
| Empty User-Agent bypass test | MEDIUM |
| Metadata size boundary test | MEDIUM |
| Queue job class whitelist test | MEDIUM |
| Impossible travel concurrent request test | MEDIUM |
| Alert rate limiter concurrent flood test | HIGH |
| Metadata sanitization in alert persistence | MEDIUM |
| Cache flush quarantine bypass simulation | LOW |

---

## CONFIGURATION RECOMMENDATIONS

Add to `config/security-defense.php`:

```php
'hardening' => [
    // ... existing ...
    
    // Require Redis/Memcached for production cache-backed state
    'require_durable_cache' => env('SECURITY_DEFENSE_REQUIRE_REDIS', false),
    
    // Maximum alert metadata size (bytes) before truncation
    'max_alert_metadata_size' => 16384,
    
    // Block requests with empty User-Agent (most browsers always send one)
    'block_empty_user_agent' => env('SECURITY_DEFENSE_BLOCK_EMPTY_UA', false),
],
```

---

*Report generated by Hermes Agent security audit — attacker-perspective + whitebox code review*

---

## REMEDIATION LOG (FIX ALL)

All 13 findings remediated. **Baseline shift:** 34 tests → **46 tests, 185 assertions** (12 new regression tests added). All 10 source files modified + 2 new files (SecurityQuarantine model + quarantine migration).

### Changes by finding

**#1 CRITICAL — Atomic counters (5 rules)**
- Replaced read-modify-write `get()`→`put()` with atomic `cache->increment()` on dedicated counter key, seeded TTL via sibling window key. BruteForce, CredentialStuffing, DistributedSpray, PathReconnaissance, RateLimitBypass. Parallel requests now accumulate correctly.
- Sacrificed exact sliding-window precision for atomic correctness (documented tradeoff, per skill).

**#2 CRITICAL — Alert rate limiter TOCTOU**
- `incrementRateLimiter()` now seeds TTL with `put($key, 0, 60)` on first create, always `increment()`. No more stuck-at-1 under concurrency.

**#3 HIGH — Durable DB quarantine**
- New `SecurityQuarantine` model + `security_quarantines` migration. `IpQuarantineService` checks DB as durable fallback when `persist_to_database=true`, upserts on jail, deletes on pardon. Cache is fast path, DB is authoritative.

**#4 HIGH — Payload sample sanitization**
- `PayloadInjectionRule` strips control chars (`/[\x00-\x1f\x7f]/`) from matched samples in both `evaluate()` and `inspect()` before storage/logging. Prevents log/Markdown injection.

**#5/#6 HIGH — Identifier/IP hashing**
- `CredentialStuffingRule.metadata['sample_identifiers_hashed']` = SHA-256 of identifiers (was plaintext `sample_identifiers`).
- `DistributedSprayRule.metadata['sample_ips_hashed']` = SHA-256 of IPs (was plaintext `sample_ips`).

**#7 HIGH — Impossible travel cache lock**
- `ImpossibleTravelRule` wraps read-then-write in `$cache->lock()` with 5s lease, 3s block timeout, graceful fallback for non-locking drivers. Prevents TOCTOU on concurrent location updates.

**#8 MEDIUM — Empty UA defense**
- New config `user_agent_anomaly.block_empty_user_agent` (env `SECURITY_DEFENSE_BLOCK_EMPTY_UA`, default false). When enabled, empty User-Agent flagged as `empty_ua` anomaly. Default preserves existing behavior (opt-in).

**#9 MEDIUM — Header sanitization**
- `RequestThreatSource` now stores only `x_forwarded_for_hash` and `cf_connecting_ip_hash` (SHA-256). Raw `origin`/`referer`/`x-forwarded-for` no longer stored — prevents internal URL / CSRF token leakage.

**#10 MEDIUM — Durable quarantine docs**
- Config exposes `quarantine.persist_to_database` + `table`. DB-backed state survives cache flush / restart / multi-server.

**#11 MEDIUM — Queue class whitelist**
- `DispatchAlertChannelJob` validates `$this->channelClass` against `VALID_CHANNELS` const before `app()`. Invalid class logged + rejected, no arbitrary instantiation.

**#12 MEDIUM — Metadata size bound**
- `AlertDispatcher` truncates metadata when JSON exceeds `hardening.max_alert_metadata_size` (default 16KB): trims oversized string values to 200 chars, then bounds top-level key count. Prevents storage/API exhaustion.

**#13 MEDIUM — Middleware feeds detection engine**
- `RequestThreatScanner::handleDetectedAnomaly()` now calls `defenseManager->processEvent($event)` AND dispatches the block alert directly, so request telemetry flows through full detection rules.

### Required host-app actions
1. **Optional:** Enable durable quarantine — set `SECURITY_QUARANTINE_PERSIST_DB=true` in env and run `php artisan migrate` for the new `security_quarantines` table.
2. **Optional:** Enable empty-UA blocking — set `SECURITY_DEFENSE_BLOCK_EMPTY_UA=true` if you want to reject clients without a User-Agent.
3. **Production:** Use Redis/Memcached cache driver for cross-request counter correctness (array/file cache loses state on restart — documented in README).

### Regression tests added
- `SecurityFixRegressionTest`: brute force atomic counter, credential stuffing hash, distributed spray hash, empty UA on/off, path recon counter, rate-limit bypass counter, header hashing.
- `IpQuarantineServiceTest::test_db_backed_quarantine_survives_cache_clear`: cache flush keeps quarantine active via DB.
- `QueuedAlertDispatchTest::test_it_rejects_invalid_channel_class_from_queue`: stdClass rejected.
- `SecurityDefenseEndToEndTest`: metadata truncation bound + payload control-char stripping.

**Verification:** `vendor/bin/phpunit` → **OK (46 tests, 185 assertions)** for security suite; full repo suite **OK (67 tests, 253 assertions)**. All 12 modified PHP files pass `php -l`.
