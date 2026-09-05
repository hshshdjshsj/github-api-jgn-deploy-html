# Patch Notes V21 — PT Digdaya Inovasi Nusantara

Tanggal: 5 September 2026

## Hasil utama

V21 menutup masalah yang dilaporkan pada menu mobile, header/hero beranda, komposisi kartu, caption watermark, footer/kontak, kompresi media, Berita & Wawasan, serta Pusat Pengetahuan. Identitas navy–cream–gold, tipografi editorial, dan struktur layanan lama tetap dipertahankan.

## Menu dan motion

- Reveal menu memakai `clip-path` vertikal 300 ms dan easing yang dapat dibalik tanpa mengulang keyframe dari awal.
- Submenu tidak lagi memakai batas tinggi arbitrer; tinggi target dihitung dari `scrollHeight`, sementara durasi pembalikan menyesuaikan jarak yang tersisa.
- State cepat buka–tutup–buka memakai token generasi agar callback fokus lama tidak mencuri fokus pada interaksi baru.
- Fokus dipindahkan sebelum subtree diberi `hidden`, `inert`, atau `aria-hidden`.
- Link submenu baru masuk urutan tab setelah animasi buka selesai; selama elemen masih terpotong, link tetap inert.
- Kondisi resize, orientasi, BFCache, Escape, backdrop, link navigation, dan `prefers-reduced-motion` mempunyai jalur reset eksplisit.
- Header sticky tidak menjadi containing block panel fixed pada WebKit; safe-area notch dan bagian bawah layar dipertimbangkan.

## Header, hero, kartu, dan gambar

- Hero beranda mobile disusun sebagai gambar → kontrol cerita → copy; tidak ada overlay besar yang menenggelamkan foto atau judul.
- Kontrol slide mempunyai target sentuh minimal 44 px, keyboard panah, dan gestur swipe.
- Kartu promosi mobile memakai gambar 16:9 di atas body rectangle yang tinggi mengikuti isi, sehingga gambar tidak memanjang atau terpotong oleh kotak teks vertikal.
- Kartu Berita & Wawasan memakai grid 3/2/1 kolom, ringkasan terbatas, hierarki lead card, dan rasio gambar 16:9.
- `object-fit`, `object-position`, dimensi intrinsik, dan margin bawaan `<figure>` dinormalisasi.

## Watermark dan caption

- Watermark raster tetap berada pada aset yang diwajibkan manifest.
- Caption disclosure HTML pada newsroom, detail, editorial split, dan mosaic tidak memakai pill, box, fill, border, atau blur.
- Teks menyatu transparan dengan gambar; ukuran, opacity, dan bayangan empat arah menjaga keterbacaan pada crop terang maupun gelap.
- Label konten yang memang menjadi bagian desain kartu (kategori/judul) tidak disalahartikan sebagai watermark.

## Footer dan kontak

- Footer yang sama dipakai di 38 HTML: gelombang dua lapis, brand, hubungan CV Multi Usaha Mandiri, lima region navigasi, kanal kontak, manifesto, dan legal links.
- Elemen vertikal kosong/ornamen kontak yang tidak memiliki fungsi tidak digunakan.
- WhatsApp memakai bentuk vektor brand; email memakai envelope vektor, tanpa emoji/font icon yang berubah antarperangkat.
- Tombol kontak mengambang menghindari footer dan zona aksi; panel ikut dihitung dalam collision detection.
- Jika kontak harus disembunyikan saat menu/keyboard/collision aktif, panel ditutup dan fokus dipindahkan lebih dahulu.

## Berita & Wawasan

- Dataset lama berisi judul/kueri tanpa sumber tidak dipakai oleh UI aktif.
- Dataset aktif berisi 19 artikel dari 11 kategori dengan sumber HTTPS yang dapat dibuka, tanggal sumber/pemeriksaan, tiga intisari, tiga bagian isi, provenance, dan batas penggunaan.
- Seluruh artikel aktif berisi 181–269 kata efektif (rata-rata 211,6), sehingga halaman detail memberi konteks dan langkah praktis—bukan sekadar judul atau cuplikan.
- Judul, summary, isi artikel, sumber, metadata, related article, canonical, serta JSON-LD dibangun dari record yang sama agar tidak saling bertentangan.
- Detail artikel menampilkan sumber utama dan link asli, pemeriksaan, proses editorial, batas penggunaan, dan status integritas sebelum tombol aksi.
- Ilustrasi selalu diberi disclosure bahwa gambar bukan dokumentasi sumber/peristiwa.

## Pusat Pengetahuan

- 56 panduan lengkap, 8 kategori, 7 jenis panduan, dan rujukan HTTPS pada setiap entri.
- Filter, search, pagination, reset, modal detail, link rujukan, serta copy note diperbaiki dan diberi target sentuh minimum 44 px.
- Grid tidak dijadikan live region besar; hanya result bar yang mengumumkan perubahan secara atomic.
- Dialog memakai tinggi `dvh`, overscroll containment, dan tombol tutup sticky yang tidak menindih judul pada layar sempit.
- Rujukan asing ditulis sebagai “rujukan penerbit”, bukan disebut hukum Indonesia; setiap panduan meminta pembaca memeriksa yurisdiksi, ruang lingkup, dan perubahan terbaru.

## Kompresi media

- 84/84 raster lulus decode dan dimensi.
- Total raster turun dari 5.149.342 menjadi 4.068.376 byte (hemat 20,99% terhadap sumber pembanding).
- Optimasi tambahan V21 menghemat 83.112 byte tanpa mengubah dimensi.
- Dua logo mempertahankan alpha; logo CV mempertahankan RGB visible secara bit-exact, sedangkan logo Digdaya mempertahankan kualitas komposit dengan SSIM tinggi.
- `news-kesehatan-2.webp` berhenti pada q51 karena kandidat q50 gagal ambang PSNR.
- Detail teknis tersimpan di `IMAGE-COMPRESSION-MANIFEST-V21.json` dan `IMAGE-WATERMARK-MANIFEST-V21.json`.

## Hardening form lokal

- Sepuluh form pencarian/kalkulator yang hanya diproses di browser memakai `method="dialog"` tanpa `action`.
- Saat JavaScript aktif, listener `submit` tetap menjalankan pencarian atau kalkulator dan memanggil `preventDefault()`.
- Saat JavaScript/CSP gagal, algoritme submit berhenti tanpa navigasi atau request; nilai DIN, URL, anggaran, catatan, domain, ID gim, dan preferensi tidak masuk query URL, history, atau access log.

## Dokumen rilis

- `README-V21.txt`: cara pasang, cakupan, dan batas validasi.
- `UIUX-AUDIT-V21.md`: benchmark, scorecard, dan alasan desain.
- `VALIDATION-V21.json`: hasil release gate terukur.
- `FILE-MANIFEST-V21.json`: checksum seluruh file paket.

Dokumen V16–V20 dipertahankan sebagai histori, bukan sebagai status aktif V21.
