CATATAN RIWAYAT V16 — DIGANTIKAN OLEH README-V21.txt
Dokumen ini dipertahankan untuk audit historis dan tidak menggambarkan konten, ukuran, atau validasi paket aktif.

PT DIGDAYA INOVASI NUSANTARA — RELEASE V16 (HISTORIS)
Tanggal: 2026-09-04

Paket ini adalah situs statis siap unggah. Letakkan seluruh isi folder PT pada document root hosting; tidak ada tahap build dan tidak ada ketergantungan CSS/JavaScript eksternal saat runtime.

HTML inline dan keamanan
- Seluruh CSS dan JavaScript operasional sudah tertanam pada 38 HTML; tersisa 0 link stylesheet dan 0 script src.
- Validasi akhir menghitung 310 blok style dan 426 blok script (termasuk JSON-LD), dengan 659 blok sumber inline cocok byte demi byte terhadap salinan preservasinya.
- Salinan CSS dipertahankan di assets; salinan JavaScript dipertahankan di assets/js. HTML tidak bergantung pada salinan tersebut untuk render atau interaksi.
- Hash CSP di _headers dan .htaccess dihitung ulang dari byte final dan tidak memakai unsafe-inline untuk script.
- Deklarasi UTF-8 berada dalam 1.024 byte pertama pada seluruh HTML.

Gambar dan video
- Seluruh 72 raster fotografis/komposit foto memuat watermark persis: Property Of Dirac Group & CV Multi Usaha Mandiri.
- Sebanyak 42 target yang semula menampilkan wajah kini tidak menampilkan wajah: 37 foto diregenerasi dan 5 kartu OG dibangun ulang. Pemeriksaan mencakup wajah langsung, profil, bagian wajah, foto cetak, layar, dan pantulan.
- Dua sisa wajah yang ditemukan pada contact sheet brand-campaign-11 dan portrait brand-promo-14 juga telah diregenerasi, bukan ditutup atau ditumpuk.
- Lima kartu OG memakai format 1200×630; 67 foto WebP memakai 1200×675. Seluruhnya lulus decode dan OCR watermark.
- Dua MP4 memakai H.264/yuv420p 1280×720, lulus decode penuh, dan mempertahankan satu watermark stabil.
- Pemetaan visual halaman diselaraskan menurut konteks domain, parfum, situs web, legalitas, dukungan, transaksi, berita, dan Wawasan. Gambar kategori berita dinyatakan sebagai ilustrasi, bukan dokumentasi peristiwa.

Berita dan Wawasan
- Ruang berita berisi 71 catatan: 46 arsip judul dengan verifikasi tertunda dan 25 pantauan kueri yang secara eksplisit bukan fakta.
- Pustaka Wawasan berisi 200 topik orientasi: 50 memakai rujukan resmi umum dengan batasan sumber dan 150 menyatakan belum memiliki rujukan eksternal.
- Istilah teknis diberi padanan atau penjelasan. Klaim volume, skor viral, status terverifikasi, dan atribusi yang tidak dapat direproduksi tidak digunakan.
- Materi ini tetap merupakan orientasi; bukan jaminan hasil, nasihat hukum, pajak, keamanan, kesehatan, atau pengganti pemeriksaan sumber resmi terbaru.

Animasi dan cakupan
- Animasi lama dipertahankan. Perbaikan mencakup geometri cabang navigator, state aktif/collapse, sinkronisasi resize, requestAnimationFrame throttling, mobile alignment, reduced-motion, dan transisi halaman tanpa blur root.
- Perubahan copy dibatasi pada enam halaman Berita/Wawasan. Pada 32 HTML lain, teks terlihat dan markup terlindungi tetap sama; perubahan hanya berasal dari target visual, motion, dan reinlining yang diminta.

Struktur paket
- 163 file dalam satu root PT: 50 file langsung di PT, 98 file langsung di PT/assets, dan 15 file di PT/assets/js.
- Setiap folder berisi paling banyak 100 file langsung. Ukuran ZIP final diperiksa terpisah agar tidak melebihi 24.000.000 byte.
- Unggah seluruh folder, termasuk assets dan assets/js.

Validasi dan catatan operasional
- Lihat VALIDATION-V16.json untuk metrik gerbang akhir.
- Lihat FILE-MANIFEST-V16.json untuk ukuran dan SHA-256 setiap file selain manifest itu sendiri.
- Nomor kontak, email, harga, stok, ketersediaan, kebijakan, dan aturan dapat berubah; verifikasi kembali sebelum produksi.
- Pengujian akhir bersifat statis, decode media, HTTP byte-roundtrip, dan integritas arsip. Render Safari/iPhone nyata serta deployment produksi tidak diklaim.
