# معماری سکه‌چی

```text
Flutter Android App  ->  HTTPS REST API  ->  PostgreSQL
Admin Panel          ->  HTTPS REST API  ->  PostgreSQL
```

در Phase 2، `StoreRepository` در Flutter یک API client است و محصولات را از `API_BASE_URL/products` می‌خواند. مقدار پیش‌فرض HTTPS است؛ برای توسعه محلی می‌توان با `--dart-define=API_BASE_URL=http://10.0.2.2:8080/api` override کرد. cleartext فقط در debug manifest فعال است و در release وجود ندارد.

Backend از `pg` برای PostgreSQL، bcrypt برای password hash، JWT کوتاه‌عمر و جدول `sessions` برای revoke/logout استفاده می‌کند. endpointهای admin با role موجود در دیتابیس محافظت می‌شوند و تغییرات مدیریتی در `audit_logs` ثبت می‌شود. در production باید API پشت HTTPS اجرا شود و cleartext traffic اندروید غیرفعال گردد. هیچ secret یا credential داخل APK قرار نمی‌گیرد.
