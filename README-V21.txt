PT DIGDAYA INOVASI NUSANTARA — PATCH V21
Tanggal rilis: 5 September 2026

V21 adalah catatan rilis aktif. README, manifest, dan hasil validasi V16–V20 tetap disertakan hanya sebagai riwayat; semuanya digantikan oleh dokumen V21 untuk kondisi paket terbaru.

CARA MEMASANG
- Unggah seluruh isi folder PT ke document root hosting.
- Pertahankan struktur folder assets dan assets/js.
- Situs tidak memerlukan proses build dan tidak bergantung pada CDN CSS/JavaScript saat runtime.
- Gunakan _headers pada platform yang mendukung format tersebut, atau .htaccess pada Apache. Keduanya memuat kebijakan keamanan yang sama.

CAKUPAN AKTIF
- 38 halaman HTML self-contained: CSS dan JavaScript operasional tertanam di tiap halaman.
- 19 artikel Berita & Wawasan yang mempunyai judul, ringkasan, isi, intisari, sumber HTTPS, tanggal pemeriksaan, proses editorial, dan batas penggunaan.
- 56 panduan Pusat Pengetahuan dalam 8 kategori dan 7 jenis panduan; setiap entri mempunyai rujukan HTTPS dan batas cakupan.
- 84 gambar raster dan 2 video lokal. Gambar fotografis yang ditetapkan dalam manifest watermark mempertahankan watermark; caption HTML menyatu transparan dengan media tanpa panel teks.

PERUBAHAN UTAMA
- Menu mobile memakai reveal yang dapat dibalik, tinggi submenu terukur, penguncian scroll yang aman untuk WebKit, safe-area iOS, pemulihan BFCache, manajemen fokus, dan reduced motion.
- Header/hero beranda menempatkan gambar, kontrol cerita, lalu copy sebagai tiga bagian terpisah pada layar kecil sehingga kontrol tidak menenggelamkan gambar atau menindih judul.
- Kartu media memakai rasio dan object-fit yang konsisten; kartu mobile kembali menjadi komposisi gambar 16:9 dan body berbentuk kotak/rectangle yang mengikuti isi.
- Footer seragam di seluruh halaman, memakai gelombang dua lapis, tautan terstruktur, ikon WhatsApp/email vektor, dan penanganan tabrakan tombol kontak mengambang.
- Ruang berita lama yang hanya menyimpan judul/kueri tanpa bukti tidak dipakai. Konten aktif berisi artikel faktual yang dapat ditelusuri ke sumber penerbit.
- Gambar sudah dikompresi sampai ambang mutu terukur; kandidat yang mengurangi keterbacaan watermark, ketajaman logo, atau kualitas visual ditolak.

BATAS VALIDASI
- VALIDATION-V21.json adalah sumber metrik final untuk struktur, aksesibilitas, referensi lokal, paritas source-inline, sintaks JavaScript, dataset, decode media, dan CSP.
- FILE-MANIFEST-V21.json memuat ukuran dan SHA-256 setiap file paket selain manifest itu sendiri.
- Pengujian mencakup pembacaan byte seluruh file, parsing/struktur, decode media penuh, HTTP byte-roundtrip, dan integritas ZIP.
- Paket ini tidak mengklaim pengujian perangkat Safari/iPhone fisik atau penjurian estetika manusia. Uji singkat pada perangkat target setelah deployment tetap disarankan.

KONTEN DAN KEAMANAN
- Konten hukum, pajak, perizinan, keamanan, kesehatan, pembayaran, dan platform bersifat informasi umum. Buka sumber yang ditautkan dan periksa perubahan terbaru sebelum mengambil keputusan.
- Gunakan kanal resmi situs. Jangan pernah mengirim password, OTP, PIN, CVV, private key, atau kode pemulihan melalui formulir/chat.
- Form pencarian dan kalkulator lokal tidak membuat request apabila JavaScript gagal; isian tidak dijadikan query URL.
