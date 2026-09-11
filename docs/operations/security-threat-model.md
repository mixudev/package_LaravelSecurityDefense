# Threat Model & Perimeter Keamanan Dashboard

Dokumen ini mendefinisikan asumsi keamanan (*assumptions*), batas tanggung jawab (*trust
boundaries*), dan prosedur operasi untuk dashboard `mixudev/security-defense`. Tujuannya:
memberi scope yang jelas soal apa yang **dilindungi package** dan apa yang **wajib dilindungi
operator/host**, serta prosedur aman saat rotasi secret.

---

## 1. Ringkasan Lapisan Pertahanan (Defense in Depth)

Semua lapisan wajib aktif bersamaan saat melindungi aset sensitif. Tidak ada satu lapisan pun
yang berdiri sendiri sebagai pengganti autentikasi.

| Lapisan | Komponen | Tanggung Jawab |
|---|---|---|
| Transport | HTTPS/TLS (host) | Mencegah sniffing secret path & session cookie di jaringan |
| Discovery barrier | Opaque capability path | URL terenkripsi AES-256-CBC + HMAC (kunci khusus HKDF atau `SECURITY_DEFENSE_KEY`), one-time nonce, session-bound; **bukan autentikasi** |
| Network boundary | `EnsureLocalAccess` (IP/CIDR allowlist) | Hanya klien dari alamat terpercaya yang bisa memulai |
| Session boundary | Require authenticated user (mode publik) | Hanya user host yang sudah login |
| Authorization | Laravel Gate (`viewSecurityDefenseDashboard`) | Hanya user yang diizinkan yang bisa membuka |
| Step-up | Opsional Gate kedua (`require_step_up`) | Verifikasi lanjutan untuk action sensitif |
| Anti-abuse | Rate limit denial | Mencegah probing berulang URL/secret |
| Anti-leak | RequestLocationRedactor | Secret path tidak masuk telemetry/log/alert/audit |
| Browser | CSP nonce, no-store, no-referrer, nosniff, XFO | Mencegah XSS, cache, referrer leak |
| Session host | Secure cookie, HttpOnly, SameSite, regenerasi session | Mencegah theft/CSRF pada sesi host |

---

## 2. Trust Boundaries

```
[Client Browser] --TLS--> [Proxy/LB/Web Server] --REMOTE_ADDR--> [Laravel App]
                                              |
                                              +-- APP_KEY (secret, host)
                                              +-- config (bukan secret)
```

### 2.1 Yang DIPERCAYA package
- `REMOTE_ADDR` sebagai alamat klien sebenarnya. **Header apa pun** (`X-Forwarded-For`,
  `X-Real-IP`, `Client-IP`, `CF-Connecting-IP`) **tidak pernah dipercaya** — selalu bisa
  dipalsukan kecuali proxy host dikonfigurasi trusted-proxy.
- `APP_KEY` host — kunci untuk enkripsi + HMAC capability.
- Route name `security-defense.*` sebagai penanda aman untuk redaksi telemetry.

### 2.2 Yang TIDAK DIPERCAYA
- Semua header HTTP lain (Host, Referer, proxy headers) — bisa diubah attacker.
- Query string dan body request — bisa diubah attacker.
- Sesi/fingerprint saja tanpa kombinasi IP+auth+Gate (lihat §4).

### 2.3 Boundary host di luar kendali package
| Aset | Pemilik | Catatan |
|---|---|---|
| TLS certificate & termination | Host/proxy | Wajib HTTPS saat non-loopback |
| `APP_KEY` | Host | Jika bocor, semua capability + session encryption bisa didekripsi. Rotasi APP_KEY membatalkan semua URL capability lama + semua sesi terenkripsi. |
| Browser history operator | Browser | Capability opaque bersifat one-time dan kedaluwarsa 60 detik; tetap gunakan private mode untuk sesi sensitif |
| `route:cache` & `config:cache` artifacts | Deploy proses | Jangan expose `bootstrap/cache/`; capability tidak pernah di-freeze di route cache |
| VPN/network boundary | Host | Paling disarankan: akses dashboard hanya via VPN, public mode jarang diperlukan |

---

## 3. Prosedur Operasional Wajib

### 3.1 Aktivasi Opaque Path
Aktifkan melalui command install atau config langsung:
```bash
php artisan security-defense:install --with-opaque-path
```
Tidak ada secret manual. `APP_KEY` Laravel host dipakai sebagai kunci enkripsi + HMAC capability; route capability di-generate per request.
```php
// config/security-defense.php
'opaque_path' => ['enabled' => true, 'ttl_seconds' => 60],
```
Rebuild cache aman kapan saja (capability tidak dibekukan):
```bash
php artisan route:cache
```
Verifikasi: URL lama `/security-defense` → gate portal; URL `/<capability>` → dashboard sekali pakai; URL acak → 404.

### 3.2 Prosedur Rotasi (revoke)
1. Rotasi kunci dashboard: set `SECURITY_DEFENSE_KEY` baru, atau omit (fallback kembali ke derivasi `APP_KEY` baru).
2. Rebuild cache: `php artisan route:cache` + `php artisan config:cache`.
3. Restart worker (Octane/queue).
4. URL capability lama otomatis kedaluwarsa (TTL) tanpa perlu langkah manual.

> Penting: dengan `SECURITY_DEFENSE_KEY`, rotasi hanya menonaktifkan URL dashboard lama.
> Enkripsi database klien (`casts = ['encrypted']`), session cookie, dan signed URLs tetap
> memakai `APP_KEY` dan **tidak terpengaruh**. Untuk insiden `APP_KEY` bocor (root trust),
> rotasi tetap butuh re-encrypt database dan force-logout — itu di luar lingkup package ini.

**Catatan route cache:** prefix route ability berupa wildcard `{opaque}` — tidak bergantung
pada secret, sehingga `route:cache` aman kapan saja dan tidak membekukan capability.

### 3.3 Jika APP_KEY Bocor
1. Rotasi `APP_KEY` segera mengikuti §3.2 (ini membatalkan semua session terenkripsi + signed cookies + capability lama).
2. Pindai telemetry/log/alert yang mungkin menyimpan URL capability lama; redaktor otomatis
   menyensor di log baru, tapi artefak lama tetap ada.
3. Hapus sesi host yang mungkin di-replay (regenerate session, revoke tokens).

---

## 4. Skenario Ancaman Lintas-Batas (Threat Scenarios)

### 4.1 Session cookie / fingerprint dicuri (infostealer, XSS di host app)
- **Dampak**: Attacker memakai sesi korban. Opaque path TIDAK melindungi ini — sesi adalah
  aset host app, bukan package defense.
- **Mitigasi wajib host**: Session regenerate saat login, cookie `HttpOnly`+`Secure`+
  `SameSite=Lax/Strict`, TLS saja, rotate session secara periodik.
- **Mitigasi package**: Session Intelligence (`SessionFingerprintRule`, UA/IP drift) memberi
  alert anomali; tidak mencegah, tapi mendeteksi.

### 4.2 Attacker di jaringan yang sama memanipulasi trafik (spoofing ARP/DNS, mitm)
- Opaque path bisa terlihat. **Semua layer lain tetap menahan**:
  - `EnsureLocalAccess` IP allowlist menolak klien non-allowlist.
  - Mode lokal: env `local` + loopback saja.
  - TLS mencegah membaca isi trafik kecuali CA milik attacker sudah terpasang.
- **Kesimpulan**: manipulasi jaringan saja TIDAK cukup untuk buka dashboard bila
  IP allowlist + auth + Gate aktif.

### 4.3 Attacker menebak URL (brute force path)
- `route:cache` + rate limit: probing ke path salah → 404 identik (tanpa oracle),
  denial ter-rate-limit (429), log redaksi path.
- Capability tidak bisa ditebak: 256-bit nonce terenkripsi + HMAC `APP_KEY`; selain itu
  one-time nonce server-side membuat replay setelah konsumsi mustahil.

### 4.4 Credential host (password admin) bocor
- Sesi host tetap aman bila MFA/step-up aktif; Gate kedua menahan.
- Package tidak pernah menyimpan password; hanya hash identifier.

### 4.5 Replay request / CSRF
- Semua POST butuh CSRF token; respon `no-store`; cookie `SameSite`; method non-GET
  pada route GET → 405.

---

## 5. Batas Tanggung Jawab (Limitations)

Package TIDAK bisa melindungi dari:
- Kompromi host/OS/container (root, file access ke `.env` / `bootstrap/cache/`) — 
  akses file opsional terhadap `.env` berarti semua secret terbaca.
- Kompromi CA/trust store browser operator.
- Keylogger/keystroke capture di mesin operator.
- Vulnerabilities di kode aplikasi host lain (XSS di app host bisa mencuri sesi).
- Physical access ke mesin operator.

Untuk threat tersebut: batasi akses fisik, gunakan hardware token/MFA, patching berkala,
dan jangan pernah menaruh secret di repo/client.

---

## 6. Checklist Verifikasi Keamanan

- [ ] HTTPS aktif, redirect HTTP → HTTPS
- [ ] `opaque_path.enabled=true` + secret 43+ karakter
- [ ] `local_only=true` di prod kecuali public mode disengaja
- [ ] IP allowlist ketat + Gate + require_auth (mode publik)
- [ ] `route:cache` aktif — rotasi wajib rebuild
- [ ] Access log dianggap sensitif (jangan publish)
- [ ] Cookie session `HttpOnly`+`Secure`+`SameSite`
- [ ] `Cache-Control: no-store` pada dashboard (otomatis)
- [ ] `Referrer-Policy: no-referrer` (otomatis)
- [ ] Log/alert/audit di-redaksi (RequestLocationRedactor — otomatis)