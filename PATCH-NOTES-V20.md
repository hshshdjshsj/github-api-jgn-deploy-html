# PT Digdaya Inovasi Nusantara — Patch V20

V20 dibangun langsung di atas patch final V19. Perubahan dibuat sebagai satu lapisan CSS/JS bersama agar perilakunya identik pada seluruh 38 halaman HTML.

## Perbaikan utama

- Memisahkan 15 blok copy promo dari dua `<span>` dekoratif yang ditambahkan runtime (`.dig-photo-sheen` dan `.dig-photo-grain`). Konflik ini adalah penyebab panel copy menyusut menjadi kolom sempit pada screenshot.
- Menambahkan kelas semantik `.dig-promo-copy` pada seluruh kartu promo index dan mengembalikan kedua layer dekoratif ke posisi absolut tanpa ikut mengambil ruang layout.
- Mengubah kartu promo normal mobile menjadi komposisi dua baris: gambar 16:9 utuh, lalu panel copy navy yang mengikuti tinggi konten. Tiga kartu wide tetap 16:9.
- Mengubah kartu campaign dan newsroom lead mobile ke pola media 16:9 in-flow agar crop ekstrem dari sumber landscape tidak terjadi.
- Menambahkan state collision berbasis `IntersectionObserver`: shortcut WhatsApp ditutup dan memudar saat footer masuk zona konten, sehingga tidak lagi menutupi deskripsi, judul, atau tautan footer.
- Merapikan footer mobile: gap dua kolom fluid, brand/family grid deterministik, padding lebih ringkas, fallback satu kolom pada lebar sampai 340 px, dan panel kontak dapat digulir pada viewport pendek.
- Menyembunyikan placeholder kanal sosial yang memang belum tersedia; LinkedIn, WhatsApp, dan email yang aktif tetap dipertahankan.
- Menyamakan active state menu mobile, termasuk tautan submenu, tanpa pill, shadow, atau perubahan geometri menu.
- Menghapus offset dekoratif kartu domain pada mobile agar sisi kanan tidak terpotong.

## Hal yang sengaja dipertahankan

- Geometri, sticky behavior, safe-area, scroll lock, dan animasi morph menu V19 yang sudah lolos audit tidak diubah.
- Garis emas di atas header tetap menjadi indikator progres membaca.
- Gelombang footer dan kurva non-footer tetap pada bentuk V19.
- Seluruh 84 raster terkompresi, 72 watermark transparan, dan 2 video tidak dikodekan ulang; seluruh byte media identik dengan paket V19.

## Rujukan kualitas desain

- Webby Awards 2026 — Best User Experience dan Best User Interface: pengalaman yang mulus, fungsi yang berguna, serta antarmuka yang tidak menghalangi konten.
- Awwwards — Sites of the Year: komposisi editorial, hierarki visual, dan penggunaan motion yang terukur.
- Apple Human Interface Guidelines — accessibility: target interaksi yang dapat dikenali, fokus yang aman, dan dukungan reduced motion.

Rujukan: <https://winners.webbyawards.com/winners/websites-and-mobile-sites/features-design/best-user-experience>, <https://winners.webbyawards.com/winners/websites-and-mobile-sites/features-design/best-user-interface>, <https://www.awwwards.com/websites/sites_of_the_year/>, dan <https://developer.apple.com/design/human-interface-guidelines/accessibility>.

## Validasi

- 38 HTML terurai tanpa error dan tanpa duplicate ID.
- Footer tetap identik byte-for-byte di semua halaman.
- 4.493 referensi lokal diperiksa tanpa target hilang.
- 84 raster dan 2 stream video didekode penuh; seluruh dimensi deklaratif cocok dengan dimensi intrinsik.
- 380 pasangan source/inline V17–V20 identik byte-for-byte.
- CSP `_headers` dan `.htaccess` identik serta mengizinkan tepat hash blok inline yang dipakai.
- Manifest watermark dan kompresi tetap lolos; nol drift pada 86 file media dibanding ZIP V19.
- Model geometri statis diuji pada lebar 320, 340, 375, 393, 402, 430, dan 760 CSS px.
- Browser-rendered geometry tidak dijalankan karena environment validasi tidak memiliki executable Chromium, WebKit, atau Firefox; status ini dicatat eksplisit sebagai `NOT_EXECUTED`, bukan diklaim PASS.
