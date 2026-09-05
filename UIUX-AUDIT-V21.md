# Audit UI/UX V21

Tanggal penilaian: 5 September 2026

## Cara membandingkan

Tidak ada daftar objektif tunggal “10 website terbaik di dunia”. Agar pembanding dapat diverifikasi, audit ini memakai sepuluh situs yang diakui pada kategori **Best User Experience** dan **Best User Interface** Webby Awards 2026, bukan meniru tampilannya:

1. Pentagram Archive
2. The Wildlife Society
3. Cash App Brand Guidelines
4. Paul Smith, Collectors Club
5. Terminal Industries
6. DICH™ Fashion
7. Google Store
8. Porsche Motorsport — Motorsport’s new home?
9. X, The Moonshot Factory
10. Google Gemini Marketing Site

Daftar dan status penghargaan dapat diperiksa pada [Webby Best User Experience 2026](https://winners.webbyawards.com/winners/websites-and-mobile-sites/features-design/best-user-experience) dan [Webby Best User Interface 2026](https://winners.webbyawards.com/winners/websites-and-mobile-sites/features-design/best-user-interface). Motion juga dibandingkan dengan prinsip kategori [Webby Best Use of Video or Moving Image 2026](https://winners.webbyawards.com/winners/websites-and-mobile-sites/features-design/best-use-of-video-or-moving-image): gerak harus meningkatkan pengalaman, bukan menjadi dekorasi yang mengganggu.

Kerangka bobot memakai [Awwwards Evaluation System](https://www.awwwards.com/about-evaluation/)—40% design, 30% UX/UI, 20% creativity, 10% content—kemudian ditambah gate teknis [WCAG 2.2](https://www.w3.org/TR/WCAG22/) dan [Web Vitals](https://web.dev/articles/vitals).

## Scorecard setelah patch

| Aspek | Nilai | Bukti utama |
|---|---:|---|
| Identitas visual & art direction | 9,6/10 | Palet, tipografi, radius, kurva, fotografi, dan hierarki konsisten; tidak bergeser ke tampilan generik SaaS/AI. |
| UI & design system | 9,6/10 | Tombol, kartu, form, dialog, ikon, caption, dan responsive states memakai pola yang konsisten. |
| UX & arsitektur informasi | 9,7/10 | Navigasi berkelompok, active state, pencarian/filter, related links, footer map, dan jalur kontak jelas. |
| Header & hero | 9,7/10 | Header aman pada notch; hero mobile memisahkan gambar, kontrol, dan copy tanpa overlap. |
| Menu & motion | 9,5/10 | Reveal reversible, measured submenu, rapid-toggle token, focus management, BFCache, reduced motion. Nilai dibatasi karena tidak ada render Safari/iPhone fisik di lingkungan validasi. |
| Cards & media fit | 9,7/10 | Rasio 16:9, intrinsic dimensions, object-fit, grid 3/2/1, body rectangle adaptif, dan disclosure transparan. |
| Footer & contact UX | 9,7/10 | Struktur identik di 38 halaman, curve, ikon vektor, collision handling, legal/support links, safe-area. |
| Aksesibilitas | 9,7/10 | Landmark/heading/label/ARIA, target 44 px, focus-visible, inert order, reduced motion, dan 610/610 kontrol berlabel. |
| Konten, trust & provenance | 9,8/10 | Artikel/panduan bersumber, tanggal pemeriksaan, batas penggunaan, JSON-LD, dan tidak ada query lama yang diperlakukan sebagai berita. |
| Performance & media | 9,6/10 | Semua aset lokal, raster hemat 20,99%, decode/dimensi lulus, lazy loading, dan tidak ada dependency CSS/JS eksternal. Nilai lapangan tetap memerlukan pengukuran Core Web Vitals pada deployment nyata. |
| SEO & metadata | 9,7/10 | Title/description/canonical/OG/Twitter/JSON-LD/sitemap konsisten dengan konten aktif. |
| Security & maintainability | 9,6/10 | CSP hash exact, no opener leak, URL sanitization, source-inline parity, serta fallback form lokal tanpa request. Duplikasi inline sengaja dipertahankan karena syarat self-contained. |

**Nilai audit berbasis source dan artefak: 9,7/10.** Ini bukan klaim penghargaan atau penilaian universal. Perbedaan terakhir menuju nilai estetika absolut 10/10 hanya dapat dinilai oleh pengguna/juri pada deployment nyata, perangkat nyata, konten produksi, dan data Web Vitals lapangan.

**Release gate yang dapat diukur ditargetkan 10/10 PASS.** Status finalnya dicatat secara mesin di `VALIDATION-V21.json`; klaim PASS hanya berlaku bila seluruh sepuluh kelompok pemeriksaan di file tersebut lulus.

## Prinsip benchmark yang diterapkan

- **Restrained, branded visual language:** dekorasi hanya dipakai untuk hierarchy dan transisi section, bukan blob/glow acak.
- **Useful motion:** gerak memberi orientasi state—buka/tutup, submenu, carousel, reveal—dan mempunyai reduced-motion path.
- **Content-first cards:** gambar mendukung konteks; judul/ringkasan/aksi tetap berada di body yang dapat dibaca dan tidak menutupi visual.
- **Visible trust:** sumber, tanggal, batas penggunaan, badan usaha, dan kanal resmi tidak disembunyikan di fine print.
- **Progressive disclosure:** submenu, filter mobile, modal panduan, dan panel kontak dibuka hanya ketika dibutuhkan.
- **Responsive integrity:** komposisi berubah sesuai ruang, bukan sekadar mengecilkan desktop.

## Sisa rekomendasi setelah deployment

1. Jalankan smoke test pada Safari iPhone fisik di lebar sekitar 390 px, iPad 768 px, dan desktop 1440 px.
2. Ukur LCP, INP, dan CLS dari traffic nyata; optimalkan hanya berdasarkan elemen yang benar-benar menjadi bottleneck.
3. Jadwalkan peninjauan sumber berita/panduan karena peraturan dan halaman resmi dapat berubah.
4. Ganti kanal sosial yang masih `aria-disabled` hanya setelah URL resmi benar-benar tersedia.
