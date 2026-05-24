驗證所有 *.js 語法正確，並確認專案核心邏輯符合預期。

---
name: code-verify
description: 當使用者要求驗證程式可執行、確認環境正常、或在程式碼異動後想確認功能完整性時使用。
---


## 執行流程

### 1. 驗證開發環境版本
執行 `node --version`，確認為 v18 以上。

### 2. 語法檢查（所有 JS 檔）
分別對下列檔案執行 `node --check`：
- `findUCA.js`
- `listPCCA.js`
- `lib/cert-parser.js`
- `lib/ccadb-client.js`
- `lib/ca-tree.js`
- `lib/config-loader.js`
- `lib/logger.js`
- `lib/report-generator.js`
- `lib/pc-report-generator.js`

### 3. 確認無第三方套件依賴
用 Grep 工具在所有 `*.js` 搜尋 `require\('[^./]`（即 require 的模組名稱不以 `.` 或 `/` 開頭，排除本地相對路徑）。
允許的結果僅限內建模組：`crypto`、`fs`、`path`、`child_process`、`os`。
出現任何其他模組名稱即為異常（表示引入了第三方套件）。

### 4. 確認關鍵實作正確性
用 Grep 工具執行下列確認：

- **內建 fetch**：`fetch` 存在於 `lib/ccadb-client.js`；`require('https')` 不存在於任何 `*.js`
- **sanitizeFilename 防路徑穿越**：`findUCA.js` 中 `sanitizeFilename` 函式的正則表達式包含 `\\`（反斜線）與 `/`（斜線）
- **manifest 路徑一致**：`pem/.ccadb-manifest.json` 字串同時出現在 `findUCA.js` 中（兩處：`exportAllCcadbPems` 與 `main()`）
- **CLI 進入點**：`node findUCA.js --help` 可正常執行並顯示用法說明（不拋出錯誤）

### 5. 確認輸出目錄命名
用 Grep 工具確認 `findUCA.js` 中：
- `myCert` 出現於有效憑證路徑
- `01.expire` 出現於過期憑證路徑
- `00.new` 出現於新增憑證路徑
- `02.notExist` 出現於移除憑證路徑
- 搜尋 `'output'|"output"` 確認**字串常數** `output` 不出現（`[output]` 為 log 前綴不在此限，須以引號界定的路徑字串為準）

## 輸出格式

每個步驟顯示 ✓（通過）或 ✗（失敗），失敗時顯示錯誤訊息或不符合的行號。
所有步驟通過後，顯示「✓ 驗證完成」。
