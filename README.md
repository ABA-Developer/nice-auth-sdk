# nice-auth-sdk

SDK Go untuk NICE. Ada dua paket, satu untuk tiap sisi integrasi:

| Anda menulis | Paket |
|---|---|
| pemanggil yang mengambil token lalu memanggil service (Service Account, backend, exchange) | `credentials` |
| service yang menerima dan memeriksa token NICE | `verify` |

Kedua paket tidak saling mengimpor. `verify` hanya butuh pustaka standar dan `go-jose`, jadi service yang hanya memverifikasi tidak membawa kode sisi pemanggil.

English: [README.en.md](README.en.md).

## Pasang

```bash
go get github.com/ABA-Developer/nice-auth-sdk
```

Butuh Go 1.24 atau sesudahnya.

## Contoh yang bisa dijalankan

Tiap folder di [`examples/`](examples) adalah satu program `main` untuk satu peran. Pengaturannya dibaca dari environment dan tertulis di komentar paling atas `main.go`.

| Contoh | Peran | Yang diperlihatkan |
|---|---|---|
| [`examples/service_account`](examples/service_account/main.go) | pemanggil mesin | `ConfigFromEnv`, `HTTPClient`, membaca galat |
| [`examples/service`](examples/service/main.go) | service yang menerima token | `Middleware`, `Require`, `Sensitive`, feed, tenant |
| [`examples/exchange`](examples/exchange/main.go) | backend yang memanggil service lain atas nama user | `NewExchange`, `DoAs` |
| [`examples/connect`](examples/connect/main.go) | backend web yang melogin-kan user dan menyimpan refresh token | `AuthorizeURL`, `HandleCallback`, `Do`, `Disconnect` |

```bash
export NICE_ISSUER=https://auth.example.com NICE_SA_ID=sa_... NICE_SA_API_KEY=...
SERVICE_SLUG=nadi SERVICE_URL=https://nadi.example.com go run ./examples/service_account
```

Potongan di bawah meringkas tiga yang pertama.

## Pemanggil mesin (Service Account)

Service Account membuktikan API key-nya ke NICE (`client_credentials`), lalu memanggil service dengan token yang didapat. SDK menyimpan token di memori, memperbaruinya di latar belakang, dan mengulang request satu kali bila service menjawab 401 `token_stale`.

```go
import "github.com/ABA-Developer/nice-auth-sdk/credentials"

c, err := credentials.NewFromEnv() // NICE_ISSUER, NICE_SA_ID, NICE_SA_API_KEY
if err != nil {
	log.Fatal(err)
}
go c.Run(ctx) // perbarui token yang sedang dipakai

hc, err := c.HTTPClient(credentials.Key{Audience: "nadi"}, "https://nadi.example.com")
if err != nil {
	log.Fatal(err)
}
resp, err := hc.Get("https://nadi.example.com/devices")
```

Client dari `HTTPClient` hanya mengirim token ke alamat service yang disebut. Request atau redirect ke host lain gagal dengan `ErrForeignHost`.

## Service yang menerima token

Service memverifikasi token sendiri, tanpa bertanya ke NICE di tiap request: tanda tangan (RS256, JWKS), `iss`, `aud`, masa berlaku, dan perubahan akses dari feed.

```go
import "github.com/ABA-Developer/nice-auth-sdk/verify"

v, err := verify.New(verify.Config{
	Issuer:   "https://auth.example.com",
	Service:  "nadi",                    // slug service; token harus untuk service ini saja
	JWKSFile: "/var/lib/nadi/jwks.json", // service tetap bisa memverifikasi bila restart saat NICE mati
	Checker:  verify.NewHTTPChecker("https://auth.example.com", apiKey),
})
if err != nil {
	log.Fatal(err)
}
go v.Run(ctx)
if err := v.StartFeed(ctx, verify.FeedConfig{APIKey: apiKey}); err != nil {
	log.Fatal(err)
}

mux := http.NewServeMux()
mux.Handle("GET /devices", v.Require("nadi.devices.read")(http.HandlerFunc(list)))
mux.Handle("DELETE /devices/{id}", v.Require("nadi.devices.delete", verify.Sensitive())(http.HandlerFunc(remove)))
log.Fatal(http.ListenAndServe(":8081", v.Middleware(mux)))
```

Handler membaca siapa pemanggilnya dari context:

```go
func list(w http.ResponseWriter, r *http.Request) {
	claims, _ := verify.FromContext(r.Context())       // sub, organisasi, project, izin
	tenant, _ := verify.TenantFromContext(r.Context()) // tenant dari organisasi di token, bukan dari input klien
	// ...
}
```

- `Require` memeriksa izin dari klaim `perms`.
- `Sensitive()` menambah pemeriksaan online ke NICE; bila NICE tidak menjawab, request ditolak 503.
- `StartFeed` membuat token yang terbit sebelum akses berubah ditolak dengan `token_stale`.

Kontrak lengkapnya ada di [docs/token-verification.md](docs/token-verification.md).

## Backend yang memanggil service lain atas nama user

Backend menukar token user yang datang bersama request (RFC 8693) dengan token untuk service tujuan. Backend tidak memegang refresh token.

```go
x, err := credentials.NewExchange(credentials.ExchangeConfig{
	Issuer: "https://auth.example.com", ClientID: clientID, ClientSecret: clientSecret,
})

// userToken: token dari request, yang sudah diverifikasi backend
req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://inventaris.example.com/items", nil)
resp, err := x.DoAs(ctx, userToken, credentials.Key{Audience: "inventaris"}, req)
```

## Membaca galat

```go
var grant *credentials.GrantError
switch {
case errors.As(err, &grant) && grant.Permanent: // NICE menolak untuk seterusnya: ganti key atau minta user login lagi
case errors.As(err, &grant):                    // NICE menolak permintaan ini saja (mis. access_denied)
case credentials.IsTemporary(err):              // NICE tidak terjangkau: coba lagi nanti
case errors.Is(err, credentials.ErrForeignHost): // request ke host selain service milik client ini
}
```

## Aturan keamanan

- **HTTPS.** Alamat NICE dan alamat service harus `https`. `http` diterima untuk loopback (`localhost`, `127.0.0.0/8`, `::1`), jadi stack lokal tidak butuh pengaturan. Untuk jaringan yang TLS-nya berakhir di tempat lain, isi `AllowInsecureHTTP` di `Config`; tidak ada variabel environment untuk itu.
- **Tanpa redirect ke NICE.** Panggilan SDK ke NICE tidak mengikuti redirect, sehingga rahasia tidak pernah dikirim ke tujuan redirect.
- **Rahasia tidak tercetak.** `Config`, `ExchangeConfig`, `FeedConfig`, dan `Token` menyamarkan rahasianya saat dicetak atau dicatat ke log. Bentuk JSON `Token` tetap utuh karena itu yang disimpan `Store`: jangan mencatat struct berisi `Token` lewat encoder JSON.
- **Refresh token.** `FileStore` menyimpannya sebagai berkas yang hanya dapat dibaca pemiliknya, tanpa enkripsi. Untuk produksi, pakai `Store` milik sendiri yang mengenkripsinya.

Cara melaporkan celah ada di [SECURITY.md](SECURITY.md).

## Bahasa lain

Implementasi di bahasa lain mengikuti [docs/token-verification.md](docs/token-verification.md) dan harus memberi jawaban yang sama untuk semua vector di `verify/testdata/vectors.json`.

## Mengembangkan

```bash
go vet ./...
go test ./... -count=1 -race
```

Tes tidak butuh NICE yang berjalan.
