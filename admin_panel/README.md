# Sekkechi Admin Panel

این پوشه محل پنل وب مدیر است و باید فقط از API امن `backend` استفاده کند.

## قرارداد مرحله اول

- ورود مدیر: `POST /api/auth/login`
- داشبورد: `GET /api/admin/dashboard`
- محصولات: `GET|POST|PATCH|DELETE /api/admin/products`
- دسته‌بندی‌ها: `GET|POST|PATCH|DELETE /api/admin/categories`
- سفارش‌ها: `GET|PATCH /api/admin/orders/:id`
- کاربران: `GET /api/admin/users`
- محتوای برنامه: `GET|PATCH /api/admin/content`

تمام endpointهای `/api/admin/*` باید علاوه بر مخفی بودن در UI، نقش مدیر را در Backend بررسی کنند و هر تغییر در `audit_logs` ثبت شود.
