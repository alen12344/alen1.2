# 🧿 ALEN 1.2 (LEGAL‑PRO) — Portfolio‑Grade Security Audit (Low False Positive)

> **ALEN** adalah tools *legal-first* untuk audit keamanan **web & jaringan** yang fokus pada **minim false positive** lewat:
> **evidence-first**, **correlation**, **scope ketat**, **CONFIRMED vs INDICATOR**, dan **reporting rapi**.

⚠️ **PENTING (LEGAL):** Gunakan **hanya** pada aset yang kamu **punya izin eksplisit**.  
ALEN **tidak** menyediakan brute force, exploit automation, atau malware generator.

---

## ✨ Fitur Utama

### A) Web Security (bahasa-agnostik)
- Security Headers / Cookie audit (CSP, HSTS, XFO, SameSite, Secure, HttpOnly)
- TLS / HTTPS sanity checks
- CORS policy checks
- File/config exposure: `robots.txt`, `sitemap.xml`, `swagger/openapi`, `debug endpoints` (indikator)
- JS endpoint discovery (extract URL/paths dari JS bundle)
- API surface map (REST-ish heuristics)
- XSS & SQLi **indicator mode** (*passive heuristics*, bukan exploit)
- OWASP Top 10 mapping (2021) + risk score

### B) Attack Surface
- Passive crawling (same-host)
- Parameter discovery (query keys)
- Attack surface map (Mermaid)

### C) Integrasi Tool Kali (opsional, safe)
- **Nuclei** (severity filter + correlation)
- **Nmap safe scan** (service discovery ringan)
- **Nikto** (pasif)
- **WPScan** (fingerprint only)

> Kalau tool eksternal tidak ada, ALEN tetap jalan (mode internal), dan akan kasih saran install via `alen doctor`.

### D) Anti False Positive Engine (unggulan)
- **CONFIRMED vs INDICATOR** classification
- Evidence pack per finding (request/response excerpt yang aman)
- Dedup & clustering
- Replay verification (safe replay untuk cek konsistensi)
- Confidence scoring (LOW/MED/HIGH + alasan)

### E) Reporting (portfolio-grade)
- HTML report + Summary.md
- SOC/JSON export
- Verification checklist (manual)
- Trend compare (baseline vs scan baru)

### F) Digital Forensics (legal & passive)
- Evidence manifest + SHA-256
- Merkle root (chain-of-custody style)
- IOC extraction ringan (IP/host/header/path)

---

## 📦 Install (Kali / Linux)

### Opsi 1: pipx (direkomendasikan, anti “externally-managed environment”)
```bash
sudo apt update
sudo apt install -y pipx
pipx ensurepath
# buka terminal baru setelah ensurepath
pipx install git+https://github.com/alen12344/alen1.2.git
```

### Opsi 2: dari source
```bash
git clone https://github.com/alen12344/alen1.2.git
cd alen1.2
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
```

---

## 🚀 Cara Pakai

### 1) Jalankan menu (TUI)
```bash
alen --menu --i-have-authorization --target https://example.com
```

### 2) Quick scan (tanpa menu)
```bash
alen --i-have-authorization --target https://example.com --quick
```

### 3) Full scan (pakai nuclei/nmap bila tersedia)
```bash
alen --i-have-authorization --target https://example.com --full
```

### 4) Cek lingkungan (auto preflight)
```bash
alen doctor
```

---

## 📁 Output Report

ALEN akan buat folder report seperti:
```text
~/alen-report/alen-report-YYYYMMDD-HHMMSS/
  report.html
  findings.json
  summary.md
  attack-surface.md
  owasp-mapping.md
  verification-checklist.md
  soc-quick.json
  evidence/
    manifest.json
    merkle_root.txt
```

Buka HTML:
```bash
xdg-open ~/alen-report/alen-report-*/report.html
```

---

## ✅ Known Limitations (jujur)
- XSS/SQLi di ALEN adalah **indicator** (pasif). **Konfirmasi final wajib manual**.
- Discovery subdomain hanya **pasif** dan default **host-only** (untuk aman & cepat).
- Tool eksternal (nuclei/nmap/nikto/wpscan) bersifat **opsional**; hasilnya akan dikorelasikan untuk menekan false positive.
- ALEN **tidak** melakukan brute force, exploit automation, atau payload destruktif.

---

## 🧩 CI / GitHub Actions
Repo ini punya CI untuk:
- install dependencies
- unit tests ringan
- lint basic
- memastikan CLI `alen doctor` bisa jalan

---

## 📣 Kontak (GitHub bio / README)
- WhatsApp: 085764952471  
- Instagram: **@alen.kusumaa**

---

## License
MIT — lihat file `LICENSE`.
