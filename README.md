# `wahyu-web-security-hub` — Web Security Audit System (WSAS)

Pusat kawalan keselamatan aplikasi web (Security Hub) yang boleh digunakan semula merentasi semua projek GitHub dan **Antigravity IDE** — menyokong stack campuran (Static Web/GitHub Pages, React/Vite/Node.js, Firebase, Supabase, Google Apps Script, PHP/Laravel).

## Seni Bina WSAS

```text
Antigravity IDE (Mode A: Manual)           GitHub Actions (Mode B: Automated)
  web-security-audit skill                   reusable-audit.yml (workflow_call, SHA-pinned)
         │                                               │
         ▼                                               ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │                 WSAS Core Engine (wahyu-web-security-hub)           │
  │  1. detect-stack.py     -> Auto-detect stack & modular YAML profile │
  │  2. static-checks.py    -> Profile rules (Firebase/Supabase/GAS/PHP)│
  │  3. External Scanners   -> Gitleaks/Betterleaks, npm/composer,      │
  │                            Semgrep, CodeQL, OWASP ZAP (passive)     │
  │  4. redact.py           -> Zero raw secrets in logs/reports/AI      │
  │  5. generate-report.py  -> Markdown + JSON + Score + Release Gate   │
  │  6. ai-review.py (opt)  -> Redacted OpenRouter triage               │
  └─────────────────────────────────────────────────────────────────────┘
```

## Prinsip Keselamatan Utama (Non-Negotiable)

1. **Bukti dahulu, bukan tekaan AI:** Setiap penemuan wajib mengandungi lokasi `file:line`, rule/tool, dan bukti yang telah di-redact.
2. **Liputan jujur:** Jika scanner seperti Gitleaks atau Semgrep belum dipasang, laporan merekodkan `not_installed` — tidak pernah berpura-pura lulus.
3. **Tiada kebocoran rahsia:** Semua token, private key, dan kata laluan di-redact sebelum ditulis ke laporan atau dihantar ke OpenRouter.
4. **Kelulusan manusia:** Tiada pengubahsuaian automatik pada kod produksi atau database rules tanpa izin eksplisit.
5. **Release Gate mengatasi Security Score:** Satu penemuan `Critical` atau `High` tetap menghasilkan **`BLOCK`** walaupun skor numerik kelihatan tinggi.
6. **Tiada ujian aktif ke atas produksi:** OWASP ZAP dihadkan kepada passive baseline scan terhadap URL staging yang dibenarkan sahaja.

## Struktur Repositori

```text
wahyu-web-security-hub/
├── .github/
│   ├── dependabot.yml
│   └── workflows/
│       ├── reusable-audit.yml      # Dipanggil oleh projek lain (SHA-pinned)
│       └── security-audit.yml      # CI & self-audit untuk hub ini
├── profiles/                       # 6 profil audit modular (YAML)
│   ├── static-web.yml
│   ├── react-node.yml
│   ├── firebase.yml
│   ├── supabase.yml
│   ├── gas.yml
│   └── php-laravel.yml
├── skills/
│   └── web-security-audit/         # Skill rasmi Antigravity IDE
│       ├── SKILL.md
│       ├── references/
│       │   ├── checklist.md
│       │   ├── risk-rating.md
│       │   └── report-template.md
│       └── scripts/
│           └── run-audit.ps1
├── scripts/
│   ├── detect-stack.py             # Pengesan teknologi automatik
│   ├── redact.py                   # Enjin redaction rahsia
│   ├── static-checks.py            # Pemeriksaan statik & konfigurasi mengikut profil
│   ├── generate-report.py          # Penjana laporan Markdown + JSON + Release Gate
│   ├── ai-review.py                # Pengulas AI OpenRouter (optional & redacted)
│   ├── local-audit.ps1             # Orkestrator audit tempatan (Windows)
│   └── install-skill.ps1           # Pemasang skill ke Antigravity IDE
├── templates/
│   ├── caller-security-audit.yml   # Templat workflow untuk projek lain
│   ├── SECURITY.md
│   └── .gitignore
├── tests/
│   ├── fixtures/                   # Projek ujian sintetik (vulnerable & clean)
│   └── test_wsas.py                # Ujian automatik untuk engine & skill
├── docs/
│   ├── INSTALLATION.md
│   └── USAGE.md
└── reports/
    └── example-audit-report.md     # Contoh laporan sebenar daripada pilot fixture
```

## Mula Pantas (Quick Start)

```powershell
# 1. Jalankan ujian kendiri WSAS
python -m unittest discover -s tests -p "test_*.py" -v

# 2. Pasang skill web-security-audit ke Antigravity IDE (Global)
powershell -ExecutionPolicy Bypass -File .\scripts\install-skill.ps1 -Scope Global

# 3. Jalankan audit manual pada mana-mana projek tempatan
powershell -ExecutionPolicy Bypass -File .\scripts\local-audit.ps1 -TargetPath "C:\path\to\your-project"
```

Lihat [docs/INSTALLATION.md](docs/INSTALLATION.md) dan [docs/USAGE.md](docs/USAGE.md) untuk panduan lengkap.

## Pelan Berperingkat (Roadmap)

- **Fasa 1 — Foundation (Siap):** Struktur hub, pengesan stack, pemeriksaan statik + npm/composer/gitleaks, laporan Markdown + JSON, ujian kendiri.
- **Fasa 2 — AI Audit Skill (Siap):** Skill `web-security-audit` mengikut format rasmi Antigravity IDE dengan Self-Refinement Loop & optional OpenRouter reviewer yang di-redact.
- **Fasa 3 — GitHub Automation (Siap):** `reusable-audit.yml` (SHA-pinned), `caller-security-audit.yml`, Dependabot untuk kemas kini SHA automatik.
- **Fasa 4 — Advanced Security (Sedia diperluas):** Integrasi ujian Firebase Emulator Rules, Supabase CLI RLS testing, dan ZAP staging baseline.
- **Fasa 5 — Security Dashboard (Akan datang):** Agregasi laporan JSON merentasi semua repositori untuk pemantauan trend keselamatan.
