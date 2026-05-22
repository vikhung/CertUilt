對 *.js 進行靜態安全分析，並評估 Node.js v18 現代化改善空間。

## A. 安全弱點掃描

只回報信心度 >80%、有實際可利用路徑的問題：

1. **XSS**：HTML 報表產生時，外部資料（來自 JSON 輸入或 NVD API）是否都經過正確的 HTML 轉義（需包含 `&`、`<`、`>`、`"`、`'` 五個字元）
2. **Command Injection**：`execFileSync` 的引數是否全部以陣列傳入，有無字串拼接進 shell
3. **Path Traversal**：使用者傳入的檔案路徑是否未經驗證就直接讀取
4. **Prototype Pollution**：`JSON.parse` 結果展開（`...data`）時是否有污染風險
5. **可預測的臨時檔名**：臨時檔案是否使用 `crypto.randomUUID()` 產生
6. **應隨時確保程式碼不得包含惡意程式或具備風險的撰寫方式(如SQL Injection)

## B. Node.js v18+ 現代化評估

檢查下列項目是否已採用 v18+ 最佳實踐：

1. HTTP 請求是否使用內建 `fetch()` + `AbortSignal.timeout()`（不使用 `https` 模組）
2. 檔案 I/O 是否使用 `fs.promises`（非同步）
3. 目錄建立是否使用 `fs.promises.mkdir({ recursive: true })`
4. 子行程是否使用 `execFileSync` 陣列引數（不使用 `execSync` 字串）
5. 臨時檔案是否使用 `crypto.randomUUID()`
6. 主函式是否為 `async function main()` 並有 `.catch()` 錯誤處理

## 輸出格式

**安全弱點**：每筆列出檔名、行號、問題描述、利用情境、修復建議。
**現代化評估**：每項列出狀態（✓ 已符合 / ✗ 需改善）及改善方式。

若兩個維度都沒有問題，明確說明「無發現問題」。
