# WSAS Stack-Specific Security Checklists

Use this checklist during **Step 2 (Analyse)** to review trust boundaries and logic flaws that automated scanners alone may miss.

## 1. Universal Baseline (All Projects)

- [ ] **Secrets & Credentials:** No `.env`, `serviceAccountKey*.json`, `*.pem`, `*.key`, or hardcoded tokens in code or git history.
- [ ] **CI/CD Supply Chain:** All GitHub Actions and reusable workflows pinned to verified 40-char commit SHAs; minimal `permissions:` (`contents: read` by default).
- [ ] **Dependencies:** Lockfiles present (`package-lock.json` / `composer.lock`), Dependabot enabled, zero unresolved High/Critical advisories.
- [ ] **Error Handling:** Production builds do not leak stack traces, SQL errors, or internal paths.

## 2. Static Web & GitHub Pages (`static-web`)

- [ ] No unsafe DOM sinks (`innerHTML`, `outerHTML`, `document.write`) fed by URL parameters (`location.search`, `location.hash`), `localStorage`, or API responses without DOMPurify.
- [ ] External `<script>` CDN tags include Subresource Integrity (`integrity="sha384-..." crossorigin="anonymous"`) or are bundled locally.
- [ ] External links with `target="_blank"` include `rel="noopener noreferrer"`.
- [ ] Content-Security-Policy (CSP) defined via meta tag or reverse-proxy/CDN headers.
- [ ] Remember: GitHub Pages serves static frontend assets only — audit connected Firebase/Supabase/GAS backends separately!

## 3. React / Vite / Node.js (`react-node`)

- [ ] No `dangerouslySetInnerHTML` without verified `DOMPurify.sanitize(...)`.
- [ ] No private keys or server secrets prefixed with `VITE_` or `NEXT_PUBLIC_` (these are bundled into public browser JS!).
- [ ] No `eval()`, `new Function()`, or dynamic `child_process.exec()` with untrusted input.
- [ ] Express/Node APIs enforce schema validation (Zod/Joi), `helmet`, rate limiting, and explicit CORS allowlists (never `origin: '*'` with `credentials: true`).

## 4. Firebase (`firebase`)

- [ ] **Key Distinction:** Web client `apiKey` is public by design (restrict via Google Cloud HTTP referrer/API restrictions). Admin `serviceAccountKey.json` / `private_key` must NEVER touch the repo or client bundle.
- [ ] **Firestore Rules:** Zero `allow read, write: if true`. Authenticated writes must check ownership (`request.auth.uid == resource.data.ownerId`) or server-set Custom Claims (`request.auth.token.role == 'admin'`), plus field schema/size validation.
- [ ] **Storage Rules:** Restrict file size (`request.resource.size`), MIME type (`request.resource.contentType`), and per-user path ownership.
- [ ] **Realtime Database:** Zero `".read": true` or `".write": true` on non-public roots.
- [ ] **Authorization:** Admin actions are enforced by Security Rules / Cloud Functions, never solely by hiding UI buttons in React/JS.

## 5. Supabase (`supabase`)

- [ ] **Key Distinction:** `anon` key is browser-safe ONLY when PostgreSQL RLS is enabled on every exposed table. `service_role` key bypasses RLS and must ONLY run on trusted servers / Edge Functions.
- [ ] **Row Level Security (RLS):** Every table in `public` schema executes `ALTER TABLE ... ENABLE ROW LEVEL SECURITY;`.
- [ ] **Policies:** Avoid `USING (true)` / `WITH CHECK (true)` on INSERT/UPDATE/DELETE or PII SELECT policies; enforce `auth.uid() = user_id` or JWT role claims.
- [ ] **Edge Functions:** Validate `Authorization` JWT and user permissions explicitly before privileged queries.

## 6. Google Apps Script (`gas`)

- [ ] `appsscript.json` deployment avoids `executeAs: USER_DEPLOYING` paired with `access: ANYONE_ANONYMOUS` unless intentionally public and strictly sandboxed with server-side validation.
- [ ] Secrets and API keys stored in `PropertiesService.getScriptProperties()`, never hardcoded in `.gs` files.
- [ ] `HtmlService` templates use auto-escaping `<?= ... ?>` rather than unescaped force-printing `<?!= ... ?>` for dynamic data.
- [ ] OAuth scopes in `appsscript.json` follow least privilege (avoid full Drive/Gmail scopes when narrower scopes work).
- [ ] `doGet(e)` / `doPost(e)` validate caller identity (`Session.getActiveUser()` or signed tokens) before mutating Google Sheets/Drive data.

## 7. PHP / Laravel (`php-laravel`)

- [ ] `.env` excluded from git; `APP_DEBUG=false` in staging and production; `APP_KEY` rotated if ever exposed.
- [ ] Zero SQL injection: no variable interpolation inside `DB::raw()`, `whereRaw()`, `selectRaw()`, or `orderByRaw()` — always use parameter bindings `?`.
- [ ] Zero XSS: avoid `{!! ... !!}` in Blade templates unless sanitized via HTMLPurifier; never `echo $_GET/$_POST`.
- [ ] Mass assignment: use explicit `$fillable` allowlists (avoid `$guarded = []`) and `$request->validated()`.
- [ ] CSRF middleware active on all state-changing web routes; Policies/Gates enforce authorization (IDOR protection).
- [ ] `composer audit` clean of High/Critical advisories.
