# Deploy: Flask messenger + Supabase + Render

## 1. Supabase
1. Create a new Supabase project.
2. In **Project Settings / Database / Connect**, copy the **Session pooler** connection string.
3. Convert it for SQLAlchemy if needed:
   - from: `postgresql://...`
   - to: `postgresql+psycopg://...`
4. Store it as `DATABASE_URL` in Render.

## 2. Storage
Recommended production path:
- database: **Supabase Postgres**
- media files: **S3-compatible bucket**

Why not local disk:
- local disk breaks when instance restarts or scales horizontally.

You can also use Supabase Storage later, but current backend already speaks S3-compatible object storage.

## 3. Render
1. Push this repo to GitHub.
2. Create a new Web Service on Render.
3. Point Render to this repo.
4. Use the included `render.yaml` or configure env vars manually.
5. Add secrets:
   - `DATABASE_URL`
   - `SECRET_KEY`
   - `TWILIO_*`
   - `S3_*`
6. Deploy.

## 4. First boot
The current MVP creates tables at app start via `db.create_all()`.
That is acceptable only for MVP/dev.
Next step: replace with Alembic migrations.

## 5. Required production changes after first deploy
- move rate limiting to Redis
- add proxy/CDN aware config if needed
- add CSP and security headers
- replace SMS stub with Twilio Verify only
- move uploads to private object storage only
- add background workers for media processing
