# PT Digdaya — Patch V19

Tanggal build: 2026-09-05

V19 dibangun langsung di atas patch V18 terbaru. Seluruh 38 halaman HTML mempertahankan isi, URL, metadata, footer kanonis, aksesibilitas, watermark transparan, dan aset terkompresi yang telah lolos validasi V18.

## Koreksi V19

### Menu mobile dan header saat scroll

- Scroll lock dipindahkan ke root scroller (`html`) saat `body.menu-open` aktif.
- `body` sengaja tetap `overflow:visible` agar tidak menjadi overflow ancestor baru yang memutus perilaku sticky header di iOS/WebKit.
- Header tetap pada `top:0`, berada di atas panel, dan panel tetap dimulai tepat pada tinggi header hidup (`--dig-v17-header-height`).
- Gesture pada backdrop ditahan, sedangkan panel menu tetap dapat di-scroll secara vertikal dengan overscroll terisolasi.
- State halaman aktif pada menu mobile tidak lagi memiliki kotak/shadow yang mengganggu ritme divider.
- Panel memakai reveal vertikal 300 ms. Hamburger berubah menjadi X simetris dengan dua batang 18×2 px, tanpa fase panah, tanpa diagonal terpotong, dan tanpa batang tengah tersisa.
- Durasi ikon: buka 340 ms, tutup 300 ms; cleanup JavaScript 360/320 ms agar frame akhir tidak terpotong.

### Galeri promo index

- Galeri yang sebelumnya dipaksa menjadi satu kolom dipulihkan menjadi komposisi campuran: 12 tile reguler dan 3 tile lebar.
- Mobile memakai dua kolom; tile lebar selalu satu baris penuh.
- Tile reguler memakai rasio 4:5 pada ponsel umum dan 3:4 pada layar <=340 px untuk menjaga copy tetap utuh.
- Setiap sumber 1200×675 tetap ditampilkan di band media 16:9 sehingga subjek dan watermark tidak dipotong oleh crop kotak.
- Tidak ada perubahan urutan, tautan, alt text, lazy loading, atau dimensi intrinsik.

### Hero index

- Rotasi otomatis 8 detik dinonaktifkan karena tidak memiliki kontrol pause/stop; cerita kini berubah hanya melalui tombol 01/02/03, keyboard panah, atau swipe pengguna.
- Live region hero diubah menjadi `aria-live="off"` agar perubahan manual tidak menghasilkan pengumuman berulang yang tidak perlu.
- Setiap tombol cerita memperoleh label programatis berisi judul dan posisi, misalnya “Corporate Identity, cerita 1 dari 3”.

### Ikon kontak

- 114 badge WhatsApp teks diganti glyph SVG WhatsApp yang konsisten.
- 38 badge email `@` diganti ikon amplop SVG.
- 76 mark WhatsApp lama dan 152 karakter panah eksternal diganti dengan sprite SVG lokal.
- Ikon dekoratif tidak masuk ke accessibility tree; accessible name tetap berasal dari teks kanal.

### Kurva non-footer

- Satu kurva SVG asimetris ditambahkan pada transisi manifesto navy ke layanan terang di index.
- Kurva tidak berada di footer, tidak menangkap pointer, responsif, dan memakai warna brand yang sudah ada.
- Dekorasi sengaja hanya satu agar tampilan tetap editorial dan tidak terasa generik/berlebihan.

## Dasar desain

Implementasi memakai prinsip, bukan menyalin layout merek lain: stabilitas navigasi Apple, motion yang tertahan seperti Linear, hirarki menu mobile Mailchimp, kartu responsif Airbnb, dan transisi kurva terukur seperti Stripe/Wise. Ikon WhatsApp mengikuti bentuk vektor yang terdokumentasi oleh Bootstrap Icons dan panduan aset merek Meta.

Referensi:

- https://www.apple.com/
- https://linear.app/
- https://mailchimp.com/
- https://www.airbnb.com/
- https://stripe.com/
- https://wise.com/
- https://icons.getbootstrap.com/icons/whatsapp/
- https://www.meta.com/brand/resources/whatsapp/whatsapp-brand/
- https://web.dev/articles/animations-guide
- https://www.nngroup.com/articles/menu-design/

## Aset media

- 84 raster tetap memakai byte terkompresi V18: 4,151,488 byte total, hemat 997,854 byte (19.3783%) dari baseline V17.
- Seluruh 84 raster tetap lolos full decode, dimensi cocok, SSIM minimum 0.978311, dan PSNR minimum 34.91229 dB.
- Seluruh 72 aset watermark tetap transparan/tanpa wadah teks dan lolos detektor tepi kotak dengan 0 kandidat.
- Dua MP4 tetap lolos full video-stream decode.

## Berkas baru

- `assets/revision-v19.css`
- `assets/js/revision-v19.js`
- `PATCH-NOTES-V19.md`
- `VALIDATION-V19.json`
- `FILE-MANIFEST-V19.json`

## Catatan validasi

`VALIDATION-V19.json` adalah laporan mesin final. `FILE-MANIFEST-V19.json` mencatat ukuran dan SHA-256 setiap berkas reguler dalam proyek, kecuali manifest itu sendiri untuk menghindari referensi hash sirkular.
