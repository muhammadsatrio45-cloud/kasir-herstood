# Panduan Online Gratis: Herstoodio Kasir di Cloudflare

Hasil akhir: alamat seperti `https://herstoodio-kasir.NAMAKAMU.workers.dev` yang bisa dibuka 3 admin + kasir dari HP/laptop mana pun, tanpa komputer yang harus menyala. Data tersimpan di database Cloudflare D1 (gratis).

## Cara A: lewat GitHub (mirip Netlify)
1. Buat akun gratis di https://dash.cloudflare.com dan https://github.com.
2. Di GitHub buat repository baru (boleh Private), lalu unggah SEMUA isi folder ini (`src`, `public`, `wrangler.jsonc`, `package.json`, dst.) lewat "Add file > Upload files".
3. Di Cloudflare: **Storage & Databases > D1 SQL Database > Create database**, beri nama `herstoodio-db`. Salin **Database ID**-nya.
4. Di GitHub, buka file `wrangler.jsonc`, klik ikon pensil, lalu ubah baris D1 menjadi:
   `{ "binding": "DB", "database_name": "herstoodio-db", "database_id": "TEMPEL-ID-DI-SINI" }` dan simpan (commit).
5. Di Cloudflare: **Workers & Pages > Create > Import a repository (Git)**, pilih repo tadi, lalu **Deploy**. Nama worker harus `herstoodio-kasir` (sama dengan `name` di wrangler.jsonc).
6. Buka worker tadi > **Settings > Variables and Secrets > Add**, tipe **Secret**, nama `ADMIN_PASSWORD`, isi password adminmu (min. 6 karakter), lalu **Deploy** ulang.
7. Buka alamat `.workers.dev`, login `admin` + password tadi. Tabel dibuat otomatis saat pertama dibuka.

## Cara B: dari komputer (3 perintah)
Perlu Node.js (https://nodejs.org). Di folder ini:
```
npm install
npx wrangler login
npx wrangler deploy
npx wrangler secret put ADMIN_PASSWORD
```
Perintah `deploy` membuat database D1 otomatis (wrangler versi 4.45 atau lebih baru). Setelah itu buka alamat yang muncul.

## Setelah online
- Pengaturan > Akun Kasir: tambah akun 2 admin lain dan kasir. Akun baru wajib mengganti password saat pertama login.
- Login salah 5 kali dari satu jaringan dikunci 5 menit.
- Data tampil ter-update tiap 30 detik; ubah halaman atau tekan muat ulang untuk melihat seketika.
- Backup: Pengaturan > Unduh Backup (berkas .json). Lakukan rutin, misalnya mingguan.
- Ganti tema, nama toko, negara, metode bayar di Pengaturan.

## Batas gratis (cukup untuk toko kecil)
Worker: 100.000 permintaan/hari. D1: 5 juta baca dan 100 ribu tulis/hari, 5 GB. Penghitung reset sekitar jam 07.00 WIB. Cek angka terbaru di dokumentasi Cloudflare.

## Catatan
- Semua jam memakai WIB.
- Jika ingin domain sendiri (mis. kasir.herstoodio.com), tambahkan di Settings > Domains & Routes.
