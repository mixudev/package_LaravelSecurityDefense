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
| Discovery barrier | Opaque path (`SECURITY_DEFENSE_DASHBOARD_PATH`) | Membuat URL dashboard sulit ditebak; **bukan autentikasi** |
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
                                              +-- env SECURITY_DEFENSE_DASHBOARD_PATH
                                              +-- config (bukan secret)
```

### 2.1 Yang DIPERCAYA package
- `REMOTE_ADDR` sebagai alamat klien sebenarnya. **Header apa pun** (`X-Forwarded-For`,
  `X-Real-IP`, `Client-IP`, `CF-Connecting-IP`) **tidak pernah dipercaya** — selalu bisa
  dipalsukan kecuali proxy host dikonfigurasi trusted-proxy.
- Nilai `SECURITY_DEFENSE_DASHBOARD_PATH` dari environment host.
- Route name `security-defense.*` sebagai penanda aman untuk redaksi telemetry.

### 2.2 Yang TIDAK DIPERCAYA
- Semua header HTTP lain (Host, Referer, proxy headers) — bisa diubah attacker.
- Query string dan body request — bisa diubah attacker.
- Sesi/fingerprint saja tanpa kombinasi IP+auth+Gate (lihat §4).

### 2.3 Boundary host di luar kendali package
| Aset | Pemilik | Catatan |
|---|---|---|
| TLS certificate & termination | Host/proxy | Wajib HTTPS saat non-loopback |
| Access log server (nginx/apache) | Host | `SECURITY_DEFENSE_DASHBOARD_PATH` akan muncul di access log — perlakukan log sebagai sensitif |
| Browser history operator | Browser | Path secret bertahan di history; logoff/private mode untuk sesi sensitif |
| `route:cache` & `config:cache` artifacts | Deploy proses | Cache berisi path secret; jangan expose `bootstrap/cache/` |
| VPN/network boundary | Host | Paling disarankan: akses dashboard hanya via VPN, public mode jarang diperlukan |

---

## 3. Prosedur Operasional Wajib

### 3.1 Aktivasi Opaque Path
1. Generate secret (43+ karakter, base64url, tanpa `/` dan `=`):
   ```bash
   php -r "echo rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '='), PHP_EOL;"
   ```
2. Set di environment host deployment:
   ```env
   SECURITY_DEFENSE_DASHBOARD_PATH=<hasil generate>
   ```
3. Aktifkan di `config/security-defense.php`:
   ```php
   'opaque_path' => ['enabled' => true],
   ```
4. Rebuild cache karena route prefix di-freeze saat boot:
   ```bash
   php artisan route:cache
   php artisan config:cache   # jika memakai config cache
   ```
5. Verifikasi: URL lama `/security-defense` → 404; URL baru `/<token>` → dashboard.

### 3.2 Prosedur Rotasi Secret (revoke)
1. Generate secret baru (script §3.1).
2. Update environment host.
3. Rebuild cache: `php artisan route:cache` + `php artisan config:cache`.
4. Restart worker (Octane/queue) agar prefix baru dipakai.
5. Hapus secret lama dari history shell/host.
6. Catat waktu rotasi; anggap URL lama **masih hidup** sampai restart selesai.

**Alasan wajib rebuild + restart:** `route:cache` men-freeze prefix ke `bootstrap/cache/routes-*.php`.
Tanpa rebuild, URL lama tetap aktif meski env sudah berubah (berlaku fail-closed, bukan open).

### 3.3 Jika Secret Bocor
1. Rotasi segera mengikuti §3.2.
2. Pindai telemetry/log/alert yang mungkin menyimpan path lama; redaktor otomatis
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
- Opaque path 256-bit entropy membuat tebakan praktis mustahil.

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