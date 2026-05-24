對所有 *.js 進行靜態安全分析，並評估 Node.js v18 現代化改善空間。

---
name: code-security
description: 當使用者要求安全審查、code review 的安全面向、或提交前進行靜態分析時使用。
---


## A. 安全弱點掃描

用 Read 工具讀取以下檔案完整內容後再分析，不根據記憶判斷：
`findUCA.js`、`listPCCA.js`、`lib/report-generator.js`、`lib/pc-report-generator.js`、`lib/ccadb-client.js`、`lib/config-loader.js`

只回報信心度 >80%、有實際可利用路徑的問題：

1. **XSS（HTML 報表）**：`lib/report-generator.js` 與 `lib/pc-report-generator.js` 將 CCADB 資料（certName、caOwner、subject、issuer、status 等）和 Windows 憑證存放區資料注入 HTML 時，是否每個欄位都經過 `esc()` 轉義（需涵蓋 `&`、`<`、`>`、`"` 四個字元）。

2. **Path Traversal（憑證名稱）**：`findUCA.js` 中 `sanitizeFilename()` 以 CCADB 的 `certName`、fingerprint 等外部資料組成目錄與檔名；確認過濾字元集是否完整（至少包含 `/`、`\`、`..`、`:`、`*`、`?`、`"`、`<`、`>`、`|`、控制字元）。

3. **Command Injection（PowerShell）**：`listPCCA.js` 以 `execFileSync` 執行 PowerShell 腳本，腳本內的存放區路徑（如 `LocalMachine\\Root`）是否為靜態常數，還是有任何外部輸入拼接進指令字串。

4. **Prototype Pollution**：`lib/config-loader.js` 解析 `config.json`、`lib/ccadb-client.js` 解析 `.ccadb-cache.json`、`findUCA.js` 解析 manifest JSON；確認 `JSON.parse` 結果是否只透過固定屬性名稱存取，有無以外部資料的 key 動態設定物件屬性（如 `obj[key] = value`）。

5. **開放重新導向 / SSRF**：`lib/ccadb-client.js` 的 `fetch()` 目標 URL 是否為程式碼中的靜態常數，還是受 `config.json` 或 CLI 引數影響。

## B. Node.js v18+ 現代化評估

範圍：所有 `*.js`（`lib/` 及根目錄）

1. HTTP 請求是否使用內建 `fetch()` + `AbortSignal.timeout()`（不使用 `https` 模組或第三方套件）
2. 子行程是否使用 `execFileSync` 搭配引數陣列（不以字串拼接進 shell）
3. 主函式是否為 `async function main()` 並有 `.catch()` 錯誤處理

## 輸出格式

**安全弱點**：每筆列出檔名、行號、問題描述、利用情境、修復建議。
**現代化評估**：每項列出狀態（✓ 已符合 / ✗ 需改善）及改善方式。

若兩個維度都無問題，明確說明「無發現問題」。
