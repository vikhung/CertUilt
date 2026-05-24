# CertUilt

給定一張 PEM 憑證（或憑證鏈），自動追溯其 Root CA，並從 [CCADB](https://www.ccadb.org/) 公開資料集查出該 Root CA 底下所有的中繼憑證機構（Intermediate CA / UCA），以樹狀結構呈現完整的 CA 階層。

## 系統需求

- Node.js **≥ 18**（使用內建 `fetch`、`crypto.X509Certificate`，無需安裝任何第三方套件）

## 使用方式

```bash
# 無引數模式：自動掃描 certs/ + 處理 config.json 白名單
node findUCA.js

# 指定單一憑證檔案
node findUCA.js <憑證路徑.pem>

# 強制重新下載 CCADB 資料（略過本機快取）
node findUCA.js --no-cache

# 列出本機 Windows 所有 CA 憑證
node listPCCA.js
```

每次執行都會產生：
- **`pem/.myCert-report.html`** — 可在瀏覽器開啟的互動式樹狀報表（支援展開/收合）
- **`pem/.myCert.json`** — 機器可讀的完整 CA 階層資料
- **`pem/myCert/<Root CA 名稱>/<UCA 名稱>.crt`** — 有效 UCA 的憑證檔（CCADB 有提供 PEM 者）
- **`pem/myCert/01.expire/<Root CA 名稱>/<UCA 名稱>.crt`** — 已過期 UCA 的憑證檔

`.crt` 副檔名可在 Windows 直接雙擊以憑證檢視器開啟，亦可直接匯入憑證存放區。

執行紀錄同步寫入 `logs/YYYY-MM-DD.log`（GMT+8 日期），每次執行以分隔線區隔，每行附 `[yyyy/MM/dd hh:mm:ss.SSS]` 時間戳。

### 範例

```bash
# 掃描 certs/ 目錄中的所有憑證並產生報表
node findUCA.js

# 指定單一憑證
node findUCA.js certs/www.twca.com.tw.crt
```

## 運作原理

### 三種根 CA 識別模式

程式依以下優先順序決定 Root CA：

1. **鏈中有自簽憑證** — 直接使用該自簽憑證作為 Root CA 錨點。
2. **鏈中有 CA 憑證但無自簽** — 取鏈中最上層的 CA 憑證作為錨點（處理交叉簽署情境）。
3. **只提供葉憑證** — 透過 CCADB 的 SKI→AKI 鏈結，逐層向上追溯直到找到根。

### CCADB 快取

首次執行時會從 Mozilla 下載兩份 CSV（合計約 10 MB），並儲存為 `.ccadb-cache.json`（有效期 24 小時）。後續執行直接使用快取，大幅縮短等待時間。使用 `--no-cache` 可強制重新下載。

| 資料集 | 網址 |
|--------|------|
| Root CA | `https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportPEMCSV` |
| Intermediate CA | `https://ccadb.my.salesforce-sites.com/mozilla/PublicAllIntermediateCertsWithPEMCSV` |

## config.json — Root CA 白名單

`config.json` 是使用者設定檔，支援設定 `rootCAWhitelist`，讓程式在無引數模式下額外查詢指定的 Root CA：

```json
{
  "rootCAWhitelist": [
    {
      "label": "顯示用名稱（任意填寫）",
      "ski": "1d896e3fa3504238a4cd10517ce4862381c84397"
    },
    {
      "label": "也可以用名稱比對",
      "name": "DigiCert Global Root CA"
    }
  ],
  "downloadFromCCADB": false
}
```

| 欄位 | 說明 |
|------|------|
| `label` | 選填；用於 Console 顯示，同時作為關鍵字備援比對（所有單字皆需吻合） |
| `ski` | 用 SKI 十六進位字串比對（連續16進位，不加冒號），優先於 `name` |
| `name` | 用憑證名稱關鍵字比對（不區分大小寫，部分相符即可） |
| `downloadFromCCADB` | `true` 時將全部 CCADB 憑證匯出至 `pem/ccadb/`（增量，已存在的檔案略過） |

比對優先順序：`ski` → `name` → `label` 關鍵字。若三者均找不到，程式會從 CCADB 列出最多 5 筆名稱相近的 Root CA 及其正確 SKI，方便直接複製填入。

> 每筆至少需要 `ski` 或 `name` 其中一個欄位。

## 專案結構

```
findUCA.js                # 主程式：CCADB 查詢、建構 CA 樹、自動匯出 UCA PEM
listPCCA.js               # 列出本機 Windows CA 憑證
lib/
  cert-parser.js          # 解析 PEM 憑證，從 DER 位元組提取 SKI / AKI
  ccadb-client.js         # 下載、解析、快取 CCADB CSV；比對新增項目
  ca-tree.js              # 遞迴建構並列印 CA 樹狀階層
  config-loader.js        # 讀取並驗證 config.json
  logger.js               # 執行日誌：每行附時間戳，寫入 logs/YYYY-MM-DD.log
  report-generator.js     # findUCA 的 HTML / JSON 報表產生
  pc-report-generator.js  # listPCCA 的 HTML / JSON 報表產生
certs/                    # 放置待分析的憑證檔案（.pem / .crt / .cer）
output/                   # 自動產生（gitignored）
  pc-report.html          #   listPCCA 本機 CA 清單
  pc-result.json          #   listPCCA JSON 結果
pem/                      # 匯出的 UCA 憑證檔（gitignored）
  .myCert-report.html     #   findUCA CA 樹狀報表
  .myCert.json            #   findUCA JSON 結果
  .myCert-manifest.json   #   myCert 指紋→路徑索引
  .ccadb-manifest.json    #   ccadb 指紋→路徑索引
  myCert/<Root CA>/       #   有效 UCA 憑證
  myCert/01.expire/<Root CA>/    #   已過期 UCA 憑證
  myCert/00.new/<yyyyMMdd>/      #   CCADB 新增憑證副本
  myCert/02.notExist/<Root CA>/  #   已從 CCADB 移除的憑證
  ccadb/<Root CA>/        #   全部 CCADB 憑證（downloadFromCCADB: true）
  ccadb/01.expire/<Root CA>/    #   已過期 CCADB 憑證
  ccadb/00.new/<yyyyMMdd>/      #   CCADB 新增憑證副本
  ccadb/02.notExist/<Root CA>/  #   已從 CCADB 移除的憑證
logs/                     # 執行日誌（gitignored），每日一檔
config.json               # 使用者設定：Root CA 白名單與 CCADB 參數
```

## 關鍵概念

| 術語 | 說明 |
|------|------|
| **SKI** (Subject Key Identifier) | 憑證公鑰的指紋，唯一識別每個 CA 節點 |
| **AKI** (Authority Key Identifier) | 簽發者的 SKI，是子節點指向父節點的連結 |
| **CCADB** | Mozilla 維護的公開 CA 資料庫，涵蓋全球主流信任程式的根 CA 與中繼 CA |
| **UCA** | Under-CA，即中繼憑證機構（Intermediate CA） |
