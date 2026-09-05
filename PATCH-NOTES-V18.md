# PT Digdaya Inovasi Nusantara — Patch V18

Tanggal revisi: 4 September 2026

## Cakupan patch

1. Animasi menu mobile dianalisis per frame terhadap video referensi. Ikon hamburger kini dibentuk oleh tiga bar CSS dengan pivot lokal yang stabil di WebKit/iOS, sehingga state akhir menjadi `X` utuh dan simetris. Durasi pembukaan ikon 280 ms, penutupan 330 ms, dan reveal panel 200 ms memakai easing referensi.
2. Panel menu tidak lagi mewarisi posisi `bottom` dari aturan lama. Tingginya kembali mengikuti konten, berhenti tepat setelah item terakhir, dan tidak menyisakan bidang putih kosong. `contain: paint` yang berisiko memotong tile/bayangan di Safari juga dihapus; prefiks `-webkit-clip-path` ditambahkan.
3. Pembukaan melalui sentuhan mempertahankan fokus pada tombol menu. Fokus otomatis ke item pertama hanya dilakukan ketika menu dibuka dengan keyboard, sehingga focus ring yang tidak diminta tidak muncul saat tap tanpa mengurangi aksesibilitas keyboard.
4. Hero mobile `index.html` sekarang mengalir sebagai gambar → kontrol cerita 01/02/03 → kartu teks. Margin negatif 28,8 px dihapus, ketiga blok diselaraskan 100% lebarnya, dan dua pseudo-card yang masuk ke blok berikutnya dihilangkan. Target sentuh kontrol tetap minimum 44×44 px.
5. Rail vertikal “Hubungi kami” beserta seluruh selector dan reservasi ruangnya dihapus dari 38/38 footer. Gelombang, kanal kontak utama, urutan baca, dan `#footer-contact-details` tetap dipertahankan.
6. Seluruh 84 raster dikompresi adaptif tanpa mengubah nama, format, atau dimensi intrinsik. Ukuran raster turun dari 5.149.342 menjadi 4.151.488 byte (hemat 997.854 byte / 19,38%). Dua aset dipertahankan byte-asli karena kandidat re-encode tidak memenuhi manfaat/ambang keterbacaan.
7. Hash CSP di `_headers` dan `.htaccess` dibangun ulang dari isi inline aktual dengan padding Base64 SHA-256 yang valid.

## Validasi media

- 84/84 raster lolos full decode dan pemeriksaan dimensi.
- Minimum/mean PSNR keseluruhan: 34,91/39,33 dB.
- Minimum/mean SSIM-luma keseluruhan: 0,97831/0,98674.
- Untuk 72 aset watermark: penghematan 18,85%; minimum SSIM area teks 0,97216 dan edge correlation 0,95145.
- Teks watermark tetap semi-transparan dan dikomposit langsung pada gambar; tidak ada kotak, badge, panel, atau warna latar terpisah.

## Pemakaian

Ekstrak ZIP dengan struktur folder tetap, lalu unggah isi folder `PT/` ke document root hosting. Pertahankan `.htaccess` untuk Apache/cPanel atau `_headers` untuk platform static hosting agar kebijakan keamanan dan cache tetap aktif.

Rincian mesin tersedia di `VALIDATION-V18.json`, `IMAGE-COMPRESSION-MANIFEST-V18.json`, `IMAGE-WATERMARK-MANIFEST-V18.json`, dan `FILE-MANIFEST-V18.json`.
