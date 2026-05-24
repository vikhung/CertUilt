# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 工具用途

CertUilt 是一個 Node.js CLI 工具。輸入一張 PEM 憑證（或憑證鏈），程式會自動追溯其 Root CA，並從 [CCADB](https://www.ccadb.org/) 公開資料集查出該 Root CA 底下所有的中繼憑證機構（UCA），以樹狀結構列印完整 CA 階層，並將 UCA 憑證匯出為 `.crt` 檔案。

## 開發原則

- **執行環境**：Node.js ≥ 18，使用內建模組（`fetch`、`crypto`、`fs`、`path`、`child_process`），禁止引入第三方套件
- **執行方式**：使用 `node` 直接執行，不使用 `npx`
- **主程式**：放在根目錄（`findUCA.js`、`listPCCA.js`）
- **函式庫**：共用邏輯放在 `lib/` 目錄
- **文件語言**：一律使用繁體中文

## 執行指令

```bash
# 無引數模式：掃描 certs/ + 處理 config.json 白名單
node findUCA.js

# 單一憑證模式（支援 .pem / .crt / .cer / .p7b）
node findUCA.js <憑證路徑.pem>

# 強制重新下載 CCADB 資料（略過本機快取）
node findUCA.js --no-cache

# 說明
node findUCA.js --help

# 列出本機 Windows 所有 CA 憑證
node listPCCA.js
```

無需建置步驟、無測試套件。

**`findUCA.js` 輸出**：
- `pem/.myCert-report.html` — 互動式 HTML 樹狀報表（每次覆寫）
- `pem/.myCert.json` — 機器可讀 JSON（每次覆寫；含 tree 結構、SKI/AKI、有效期，不含 PEM；可供腳本稽核或比對）
- `pem/myCert/<Root CA>/` — 查詢到的有效 UCA 憑證（`.crt`）
- `pem/myCert/01.expire/<Root CA>/` — 查詢到的已過期 UCA 憑證
- `pem/myCert/00.new/<yyyyMMdd>/<Root CA>/` — 查詢結果中屬於 CCADB 新增的憑證副本（有新增時才出現）
- `pem/myCert/02.notExist/<Root CA>/` — 已從 CCADB 移除的 myCert 憑證（由程式自動搬移）
- `pem/ccadb/<Root CA>/` — 全部 CCADB 有效憑證（`downloadFromCCADB: true`；**增量**：已存在的檔案不重複寫入）
- `pem/ccadb/01.expire/<Root CA>/` — 全量中已過期的憑證
- `pem/ccadb/00.new/<yyyyMMdd>/<Root CA>/` — 全量中屬於 CCADB 新增的憑證（有新增時才出現）
- `pem/ccadb/02.notExist/<Root CA>/` — 已從 CCADB 移除的 ccadb 憑證（由程式自動搬移）
- `pem/.myCert-manifest.json` — myCert 指紋→路徑索引（由程式維護，支援搬移作業）
- `pem/.ccadb-manifest.json` — ccadb 指紋→路徑索引（同上）

**`listPCCA.js` 輸出**（每次執行均會覆寫）：
- `output/pc-report.html` — HTML 報表，列出本機五個憑證存放區的所有 CA
- `output/pc-result.json` — 機器可讀的 JSON 結構

## 架構

### 資料流程

1. **解析輸入** — `cert-parser.js` 讀取 PEM 檔案，以原始 DER ASN.1 位元組提取每張憑證的 SKI 與 AKI。
2. **取得 CCADB 資料** — `ccadb-client.js` 從 Mozilla/Salesforce 下載 Root CA 與 Intermediate CA 兩份 CSV，解析內嵌 PEM 欄位，並快取至 `.ccadb-cache.json`（有效期 24 小時）。
3. **識別 Root CA** — `findUCA.js` 依優先順序決定根 CA：鏈中有自簽憑證 → 鏈中最上層的 CA 憑證 → 透過 CCADB SKI→AKI 鏈結向上追溯。
4. **建構並列印樹狀結構** — `ca-tree.js` 從根 CA 的 SKI 出發，遞迴走訪 AKI 索引，附帶有效期與狀態資訊列印完整 CA 樹。
5. **匯出 UCA 憑證** — `exportUcaPems` 遞迴走訪樹狀節點，將含 PEM 資料的 UCA 依效期分流寫入 `pem/` 或 `pem/expire/`。

### 關鍵概念

- **SKI**（Subject Key Identifier）：憑證公鑰的指紋，唯一識別每個 CA 節點。
- **AKI**（Authority Key Identifier）：簽發者的 SKI，是子節點指向父節點的連結。
- **AKI index**（`Map<aki → entry[]>`）：將父節點 SKI 對應到 CCADB 中所有子憑證，用於向下建樹。
- **SKI index**（`Map<ski → entry>`）：將 SKI 對應到單一條目，用於只提供葉憑證時的向上追溯。

### 各模組職責

| 檔案 | 職責 |
|------|------|
| `lib/cert-parser.js` | 低階 DER 解析器，提取 SKI/AKI 延伸欄位；匯出 `parseCertMeta`、`parsePemChain` |
| `lib/ccadb-client.js` | 下載並快取 CCADB CSV；每筆 entry 保留原始 PEM 字串（`pem` 欄位）；比對新增項目；紀錄 `downloadHistory`；時間戳以 GMT+8 顯示；匯出 `fetchCcadbEntries`、`buildAkiIndex`、`buildSkiIndex` |
| `lib/ca-tree.js` | 遞迴建構 CA 樹（節點含完整 entry `info`）並輸出至終端機；匯出 `buildTree`、`printTree` |
| `lib/config-loader.js` | 讀取 `config.json`，驗證並回傳 `rootCAWhitelist` 與 `downloadFromCCADB`；匯出 `loadConfig` |
| `lib/logger.js` | 初始化執行日誌；monkey-patch `console.log/warn/error`，每行附 `[yyyy/MM/dd hh:mm:ss.SSS]` 時間戳寫入 `logs/YYYY-MM-DD.log`；含前綴換行的訊息各行獨立加時間戳；匯出 `initLogger` |
| `lib/report-generator.js` | 產生 `pem/.myCert-report.html`（Root CA 為樹根的互動報表）與 `pem/.myCert.json`；匯出 `generateReports` |
| `lib/pc-report-generator.js` | 產生 `output/pc-report.html` 與 `output/pc-result.json`（本機 CA 清單）；匯出 `generatePcReports` |
| `findUCA.js` | 主程式：CLI 引數處理、根 CA 識別（含追溯路徑詳細顯示）、白名單三段式比對、呼叫 `exportUcaPems` 分流匯出 `.crt`、呼叫 `initLogger` |
| `listPCCA.js` | 透過 PowerShell `execFileSync` 讀取 Windows 五個憑證存放區，產生本機 CA 報表；呼叫 `initLogger` |

### 快取機制（`.ccadb-cache.json`）

CCADB 資料來源（`lib/ccadb-client.js`）：
- **Root CA**：`https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportPEMCSV`
- **Intermediate CA**：`https://ccadb.my.salesforce-sites.com/mozilla/PublicAllIntermediateCertsWithPEMCSV`

寫入工作目錄（已列入 `.gitignore`），24 小時內重複執行直接使用快取。

- `downloadHistory[]`：每次下載的時間戳記（GMT+8）、總筆數、與前次的 diff（`addedCount`、`added[]`、`removedCount`、`removed[]`），所有項目完整記錄，無數量限制
- 使用快取時仍會顯示上次下載的 diff，確保不遺漏異動項目
- `--no-cache` 旗標會刪除快取檔後重新下載
- **快取中的 `pem` 欄位**：首次以新版本下載後才有效；現有舊快取需 `--no-cache` 重建

### 白名單比對順序（`processWhitelistEntry`）

1. `ski` 欄位 — 正規化後精確比對 CCADB SKI
2. `name` 欄位 — 名稱關鍵字模糊比對
3. `label` 欄位 — 所有單字皆須出現在憑證名稱中
4. 三者均失敗 — 從 CCADB 印出最多 5 筆名稱相近的 Root CA 及其正確 SKI

### UCA 憑證匯出（`exportUcaPems`）

在 `addResult` 內、`printTree` 之後自動呼叫，無需額外指令：
- 有效憑證（`validTo >= now`）→ `pem/myCert/<Root CA 名稱>/<UCA 名稱>.crt`
- 已過期憑證 → `pem/myCert/01.expire/<Root CA 名稱>/<UCA 名稱>.crt`
- 僅匯出 `pem` 欄位非空的項目；樹狀分析與報表不受影響
- 同名 UCA 自動附加 fingerprint 前 8 碼加以區分
- `pem/` 已列入 `.gitignore`

### 執行日誌（`logs/`）

`initLogger(logDir)` 在兩支主程式的 `main()` 最開頭呼叫：
- Session header：`====` 分隔線 + GMT+8 時間 + 執行指令
- 每行：`[yyyy/MM/dd hh:mm:ss.SSS] 訊息`
- 含 `\n` 的訊息按換行切割，各行獨立加時間戳（避免時間戳與訊息錯行）
- `logs/` 已列入 `.gitignore`

## 自訂技能（`.claude/skills/`）

- `/code-security` — 對所有 `*.js` 進行靜態安全分析（XSS、注入、路徑穿越、原型污染）及 Node.js v18 現代化審查。
- `/code-verify` — 確認所有 `.js` 能正常執行，並檢查輸出檔案格式正確。
- `/project-document` — 依程式碼實際狀態同步更新 `README.md`、`CLAUDE.md` 及相關文件。
