# stok_takip
Flask ile depo stok takip uygulaması

## Özellikler

- SQLCipher ile şifrelenmiş SQLite veritabanı.
- Uygulama başlangıcında otomatik yedekleme.
- CRUD işlemlerini kaydeden log tablosu.
- Bootstrap 5 tabanlı duyarlı arayüz.

Çalıştırmak için gerekli ortam değişkenleri:

```
export SECRET_KEY=your_secret
export DB_KEY=your_db_password
```

Uygulama `0.0.0.0` adresinde çalışır ve `backups/` klasörüne yedek dosyaları oluşturur.
