# PT Digdaya Inovasi Nusantara — Patch V17

Tanggal revisi: 4 September 2026

## Cakupan patch

1. Footer pada seluruh 38 halaman HTML diseragamkan dengan struktur dan proporsi referensi: gelombang ganda, warna navy/cream Digdaya, grid dua kolom pada layar kecil, serta tombol vertikal “Hubungi kami”. Urutan DOM mengikuti urutan visual untuk pembaca layar.
2. Menu mobile memakai vertical reveal 250 ms dengan easing `cubic-bezier(.25,.1,.25,1)`, baris menu tidak memudar atau bergeser, submenu membuka dengan tinggi terukur 250 ms, dan ikon hamburger berubah secara halus dengan overshoot sesuai video referensi. Posisi panel mengikuti tinggi header aktual melalui `ResizeObserver`.
3. Sebanyak 72 gambar ber-watermark direvisi. Teks “Property Of Dirac Group & CV Multi Usaha Mandiri” tetap ada sebagai teks semi-transparan yang menyatu langsung dengan gambar; tidak ada panel, kotak, badge, atau warna latar terpisah.
4. Hero `index.html` pada mobile diurutkan menjadi gambar → kontrol 01/02/03 → salinan teks. Kontrol memiliki target sentuh minimum 44×44 px dan tetap terlihat segera setelah gambar.
5. Rasio, margin bawaan `<figure>`, dan perilaku `object-fit` pada galeri, editorial, berita, promo, dan kartu media diperbaiki agar aset 16:9 tidak dipaksa masuk ke kotak yang tidak sesuai.

## Validasi

- HTML: 38/38 terurai tanpa error; 0 ID duplikat.
- Footer: 1 struktur identik pada 38/38 halaman.
- Referensi lokal: 4.149 diperiksa; 0 hilang.
- Media: 84 raster dan 2 video lolos full decode.
- Dimensi gambar: 304 elemen diperiksa; 0 ketidaksesuaian dimensi intrinsik.
- Watermark: 72/72 aset berubah; detector terkalibrasi menemukan 72 kotak pada sumber dan 0 pada hasil.
- JavaScript, CSS, JSON, JSON-LD, web manifest, dan XML lolos pemeriksaan sintaks/parse.
- CSP di `_headers` dan `.htaccess` dihitung ulang dari isi inline aktual dan identik.

Rincian mesin tersedia di `VALIDATION-V17.json`. Hash tiap gambar watermark tersedia di `IMAGE-WATERMARK-MANIFEST-V17.json`. Hash seluruh file proyek tersedia di `FILE-MANIFEST-V17.json`.

## Pemakaian

Ekstrak ZIP dengan struktur folder tetap, lalu unggah isi folder `PT/` ke document root hosting. Jangan menghapus `.htaccess` (Apache/cPanel) atau `_headers` (platform static hosting), karena keduanya memuat kebijakan keamanan dan cache yang sudah disinkronkan.

