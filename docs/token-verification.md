# Kontrak verifikasi token

Dokumen ini adalah kontrak untuk setiap service yang terdaftar di katalog NICE. Klien memanggil service langsung dengan access token dari NICE, dan NICE tidak berada di jalur request. Karena itu **service wajib memverifikasi token sendiri** dan menegakkan izin per operasi. NICE tidak dapat memaksanya dari sisinya; kebenaran verifikasi dijaga oleh kontrak ini dan test vector bersama.

Pustaka rujukan dalam Go ada di paket `verify` repo ini (`github.com/ABA-Developer/nice-auth-sdk/verify`). Implementasi di bahasa lain harus memberi jawaban yang sama untuk semua vector di `verify/testdata/vectors.json`.

## Bentuk token

JWT RS256 dari NICE. Satu token mewakili satu principal, satu org, satu project, dan **satu** service. Klaim yang dipakai service:

| Klaim | Arti |
|---|---|
| `iss` | penerbit NICE; harus sama persis dengan yang dikonfigurasi |
| `aud` | slug service ini; harus tepat satu nilai |
| `exp`, `nbf`, `iat` | masa berlaku dan waktu terbit (detik Unix) |
| `sub` | `usr_...` atau `sa_...` |
| `nice_org_id` | org: satu-satunya kunci tenant |
| `nice_principal_type` | `user` atau `service_account` |
| `prj` | project token ini |
| `perms` | izin service ini yang dipegang principal di project itu |
| `pv` | versi kebijakan org saat token terbit |
| `act` | hanya pada token hasil token exchange: `{"sub": "<client_id>"}`, backend service yang bertindak atas nama `sub` |
| `nice_act_as` | hanya pada token act-as: `org_...` organisasi platform, tempat hak operator platform service ini diputuskan; `sub` bukan anggota `nice_org_id` |

Token hasil token exchange (lihat dokumentasi API NICE) diverifikasi dengan langkah yang sama persis: `act` tidak mengubah keputusan apa pun. `sub` tetap user dan izinnya tetap izin user, jadi handler mencatat `act.sub` sebagai pelaku perantara (mis. di log audit service: "naia-backend atas nama usr_..."). Di `verify` nilainya ada di `Claims.Actor`; kosong pada token biasa. Klaim `act` yang bukan objek membuat token `malformed`.

Token act-as diterbitkan untuk operator platform service ini (pemegang role `<slug>.operator` di organisasi platform, lihat dokumentasi API NICE) di organisasi yang bukan organisasinya. Ia diverifikasi dengan langkah yang sama dan `perms`-nya izin role operator, jadi service tidak butuh kode khusus untuk mengizinkannya. Handler dapat membacanya untuk menampilkan dan mencatat bahwa operator platform bertindak di org itu: di `verify` nilainya ada di `Claims.ActAs` dan `Claims.IsActAs()`; kosong pada token biasa. Versi `niceauth/verify` sebelum klaim ini tidak menolak token act-as yang basi setelah hak operator dicabut (hanya sampai token kedaluwarsa) dan operasi sensitifnya ditolak, jadi perbarui pustaka sebelum operator diberi role.

Token client non-sistem yang tidak meminta `nice:aud` ber-`aud` `client_id` aplikasinya, jadi selalu ditolak di langkah 5 oleh service mana pun. Token user untuk API NICE (audience `nice`, hanya untuk klien sistem seperti NICE Console) juga membawa `sid`, ID session SSO-nya. Token service tidak pernah membawanya, dan service tidak perlu membaca klaim itu. Klaim lengkap dan cara meminta token ada di dokumentasi API NICE.

## Langkah verifikasi per request

Urutannya tetap: pemeriksaan murah dulu, panggilan jaringan paling akhir. Jawaban dan alasannya (`error_description`) adalah bagian dari kontrak.

| # | Pemeriksaan | Bila gagal |
|---|---|---|
| 1 | Ada `Authorization: Bearer`; token berbentuk JWS | `401 invalid_token`, `missing_token` atau `malformed` |
| 2 | `alg` ada di allowlist **RS256**. `none`, `HS*`, dan algoritma lain ditolak | `401`, `algorithm_not_allowed` |
| 3 | `kid` ada di JWKS; tanda tangan valid | `401`, `unknown_key` atau `bad_signature` |
| 4 | `iss` sama persis | `401`, `wrong_issuer` |
| 5 | `aud` berisi **tepat satu** nilai yang sama dengan slug service; token multi-audience ditolak walaupun slug ini ada di dalamnya | `401`, `wrong_audience` |
| 6 | `exp` belum lewat lebih dari skew; `nbf` tidak lebih dari skew di masa depan. Skew paling lama **60 detik** | `401`, `expired` atau `not_yet_valid` |
| 7 | Deny-set: `iat` tidak lebih tua dari `not_before` principal (`sub` di org itu), org, atau project token; untuk token ber-`nice_act_as` juga principal `sub` di org yang disebut `nice_act_as` | `401`, `token_stale` |
| 8 | Org diterima oleh kebijakan tenant service (lihat bawah) | `403`, `org_rejected` |
| 9 | Operasi mensyaratkan izin: harus ada di `perms` | `403`, `permission_denied` |
| 10 | Bila request menyebut project, harus sama dengan `prj` | `403`, `project_mismatch` |
| 11 | Operasi sensitif: pemeriksaan akses online ke NICE | `403 access_denied` atau `503 access_check_unavailable` |

Respons galat 401 membawa `WWW-Authenticate: Bearer error="invalid_token", error_description="<alasan>"`; tanpa token hanya `Bearer`. Bodynya `{"error": "...", "error_description": "..."}`. Alasan tidak pernah memuat token. Klien yang menerima 401 `token_stale` atau `expired` memperbarui token sekali lalu mengulang request.

Izin per operasi berasal dari `x-nice-permission` pada OpenAPI service (atau turunan tag dan metode dengan aturan yang sama dengan NICE). Nama di katalog harus sama dengan nama yang ditegakkan service; NICE menolak impor yang menyimpang.

## JWKS

- Simpan kunci per `kid`. Segarkan berkala (10 menit).
- `kid` yang tidak dikenal menyegarkan paling sering **sekali per menit**, dan permintaan serentak berbagi satu penyegaran. Tanpa batas ini `kid` acak menjadi beban ke NICE.
- Bila NICE tidak terjangkau, tetap pakai kunci terakhir yang valid. Kunci yang sudah diganti tetap ada di JWKS selama TTL token ditambah skew.
- Simpan salinan JWKS ke disk dan baca saat start. Service yang restart ketika NICE mati tanpa salinan tidak dapat memverifikasi apa pun dan harus menjawab `503`.

## Feed perubahan akses

Token tebal bertahan sampai 30 menit, jadi perubahan akses perlu jalur cepat. Service membaca `GET /api/v1/access-changes` (lihat dokumentasi API NICE) dengan API key Service Account berperan `nice.service`:

- **Saat start**, putar ulang `sekarang - (TTL + skew)` supaya token yang dicabut ketika service mati tidak diterima lagi.
- Lalu baca dengan `after_seq` dan `wait_seconds=25` terus-menerus. Gagal: coba lagi dengan backoff (1 detik sampai 30 detik).
- Setiap perubahan menetapkan `not_before` pada **satu** kunci: principal di org itu bila `principal_id` ada, selain itu project bila `project_id` ada, selain itu org. Token yang `iat`-nya lebih tua dari `not_before` ditolak `token_stale` (resolusi detik; token yang terbit pada detik yang sama tidak tertangkap).
- Simpan entri hanya selama TTL ditambah skew; token yang lebih tua sudah kedaluwarsa sendiri.
- `catalog_changed` menetapkan `not_before` seperti entri lain: katalog sebuah service berubah (mis. operasi diarsip atau izin pensiun), dan setiap principal yang terdampak menerima entri sendiri, sehingga token lamanya ditolak `token_stale` dan klien mengambil token baru dengan `perms` terbaru.
- Hak operator platform (role `<slug>.operator`) berubah di organisasi platform: binding dihapus, user dikeluarkan dari organisasi platform, atau isi role berubah. Entrinya principal itu di organisasi platform, dan token act-as yang terbit sebelumnya ditolak karena langkah 7 juga memeriksa kunci principal di org `nice_act_as`.
- `role_changed` tidak membawa `principal_id` maupun `project_id`, jadi menetapkan `not_before` pada org: setiap token org itu yang terbit sebelumnya ditolak `token_stale` dan klien memperbaruinya dengan refresh token.

**Mode degradasi.** Bila feed tidak menjawab lebih dari dua kali `wait_seconds`, service mencatat dan menghitungnya. Operasi biasa tetap dilayani, dengan batas staleness sebesar TTL token. Operasi sensitif tetap memakai pemeriksaan online. Service tidak pernah mati hanya karena feed putus.

## Operasi sensitif

Operasi yang dinyatakan `x-nice-sensitive: true` pada OpenAPI diperiksa online ke NICE pada tiap request, tidak hanya dari `perms`. Bila pemeriksaan tidak dapat dilakukan, jawabannya `503` (gagal tertutup). Pemeriksaan memanggil `POST /api/v1/access-checks` di alamat publik NICE dengan `ApiKey` Service Account berperan `nice.service` (izin `nice.platform.access.check`); jawabannya `allowed`, `reason`, dan `policy_version`. Untuk token ber-`nice_act_as`, permintaannya membawa `"act_as": true`, sehingga NICE memutuskannya dari role operator service itu, bukan keanggotaan; tanpa itu operator yang bukan anggota dijawab `allowed = false`. Pustaka Go menyediakan `verify.NewHTTPChecker(baseURL, apiKey)`, yang mengirim `act_as` dengan sendirinya.

## Tenant

Tenant adalah org NICE:

- Service yang membedakan data per tenant memakai `nice_org_id` dari token terverifikasi sebagai kunci tenant, dan **tidak pernah** menentukan tenant dari input klien (header, parameter, body). Tanpa proxy, tidak ada header dari NICE yang dapat dipercaya.
- Service memilih sendiri cara org menjadi dikenal: dibuat saat pertama dipakai (token yang sah sudah membuktikan entitlement dan aktivasi), daftar putih yang diisi admin service, atau tabel `nice_org_id` ke tenant milik service sendiri untuk service lama. Org yang ditolak dijawab `403 org_rejected`.
- Service yang tidak membedakan data per tenant mengabaikan `nice_org_id` tetapi tetap menegakkan izin.

## Test vector

`verify/testdata/vectors.json` memuat JWKS dan vector (token sudah ditandatangani). Format:

```json
{
  "version": 1, "issuer": "...", "service": "navi", "jwks": { "keys": [] },
  "vectors": [{
    "name": "stale_principal", "description": "...", "token": "<jwt>", "now": 1793329000,
    "request": { "permission": "navi.orders.read", "project": "prj_...", "sensitive": false, "client_tenant": "org_..." },
    "changes": [{ "principal_id": "usr_...", "organization_id": "org_...", "project_id": "", "kind": "principal_disabled", "occurred_at": 1792000000 }],
    "tenant": { "policy": "allow_all | allow_list | provision", "orgs": ["org_..."] },
    "check": "allow | deny | down",
    "expect": { "status": 401, "error": "invalid_token", "description": "token_stale", "tenant": "org_...", "actor": "naia-backend", "act_as": "org_..." }
  }]
}
```

Runner: bangun verifier dengan `iss`, `service`, JWKS, jam tetap `now`, skew 60 detik, dan TTL 30 menit; terapkan `changes` seperti dari feed (`occurred_at` dalam detik Unix); kirim request dengan `Authorization: Bearer <token>`, header project dan tenant klien bila ada; bandingkan status, `error`, `error_description`, dan (untuk 200) tenant, aktor (`act.sub`, kosong bila tidak ada), serta `nice_act_as` (kosong bila tidak ada) yang dilihat handler. Vector `valid_act_as_token` dan `stale_act_as_operator` menguji token act-as yang sah dan yang basi karena perubahan principal di org `nice_act_as`. Implementasi baru wajib lulus **semua** vector sebelum diintegrasikan.

Untuk menambah vector: `go test ./verify -run TestWriteVectors -update-vectors`. Vector yang sudah ada di berkas dipertahankan apa adanya, dan vector baru ditandatangani dengan kunci baru yang ditambahkan ke JWKS (`vector-key-2`, dan seterusnya), sehingga implementasi lain cukup menarik tambahan. Hapus berkasnya dulu untuk menandatangani ulang semua vector dengan satu kunci. Hasilnya di-commit setelah diff ditinjau.
