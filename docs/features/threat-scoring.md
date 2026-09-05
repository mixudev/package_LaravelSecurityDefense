# Compound Threat Scoring Engine

`ThreatScoringEngine` berfungsi mengorelasikan berbagai jenis indikasi serangan yang berbeda terhadap satu entitas yang sama sepanjang waktu.

---

## 1. Konsep & Latar Belakang

Penyerang profesional sering kali memecah serangannya agar berada di bawah ambang batas satu aturan (misal: hanya melakukan sedikit brute force, berganti user agent, lalu sesekali mencoba scanning path tersembunyi).

Engine ini mencatat skor risiko kumulatif per alamat IP atau akun dalam jendela waktu berjalan (*sliding window*, default 15 menit).

Begitu total akumulasi skor mencapai batas ambang (`threshold`, default 100), sistem otomatis menerbitkan satu alert gabungan berkategori **`compound_threat`** dengan tingkat keparahan **`critical`**, dan langsung mengisolasi IP penyerang.

---

## 2. Tabel Bobot Skor Risiko

Bobot default yang diatur pada `config/security-defense.php`:

| Vektor Serangan | Kontribusi Poin Risiko |
|---|---|
| Injeksi Payload (`payload_injection`) | +50 poin |
| Credential Stuffing (`credential_stuffing`) | +45 poin |
| Brute Force (`brute_force`) | +35 poin |
| Impossible Travel (`impossible_travel`) | +35 poin |
| Distributed Spray (`distributed_spray`) | +30 poin |
| Path Reconnaissance (`path_reconnaissance`) | +30 poin |
| Anomali Scanner UA (`user_agent_anomaly`) | +25 poin |
| Rate Limit Bypass (`rate_limit_bypass`) | +20 poin |

---

## 3. Contoh Skenario Korelasi

1. IP penyerang memindai file rahasia `/.env` (+30 poin) -> Total skor: 30.
2. IP tersebut melakukan rotasi proxy header abnormal (+20 poin) -> Total skor: 50.
3. IP tersebut mencoba injeksi SQL pada parameter form (+50 poin) -> Total skor: 100.

Hasil: Batas 100 tercapai. Engine memancarkan ancaman `compound_threat` yang merangkum ketiga riwayat insiden, mengarantina IP penyerang, dan mendispatch notifikasi instan ke seluruh channel alert.

---

## 4. Pengecekan & Reset Programatik

```php
use Mixudev\SecurityDefense\Support\Facades\SecurityDefense;

// Cek skor akumulasi risiko IP saat ini
$skor = SecurityDefense::scoring()->getScore(request()->ip());

// Reset skor (misal setelah pengguna berhasil verifikasi biometrik / 2FA)
SecurityDefense::scoring()->resetScore(request()->ip());
```
