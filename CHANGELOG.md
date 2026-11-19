# Changelog

## v0.1.0

Versi publik pertama, berlisensi Apache-2.0. Kode berasal dari `pkg/niceauth` di repo NICE, setelah pengerasan keamanan:

- Alamat NICE dan alamat service wajib `https`; `http` hanya untuk loopback, atau dengan `AllowInsecureHTTP`.
- Panggilan SDK ke NICE tidak mengikuti redirect.
- `Client.Transport` dan `Client.HTTPClient` terikat ke alamat satu service dan menolak host lain dengan `ErrForeignHost`.
- `ExchangeClient` menyimpan token per subject token.
- Konfigurasi, token, dan klien tidak mencetak rahasianya.
- Contoh yang bisa dijalankan di `examples/` untuk empat peran: `service_account`, `service`, `exchange`, `connect`.
- `layout_test.go` menjaga agar `verify` dan `credentials` tidak saling mengimpor.
