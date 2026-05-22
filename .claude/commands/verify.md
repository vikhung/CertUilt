快速驗證 *.js 是否都能正常執行，並確認輸出檔案格式正確。

## 驗證步驟

### 1. 確認 Node.js 版本
執行 `node --version`，確認為 v18 以上。

### 2. 驗證關鍵 API 存在
執行以下檢查，確認所有 Node.js v18 API 都已正確使用：
- `fetch` 已使用（不使用 `https` 模組）
- `AbortSignal.timeout` 已使用
- `execFileSync` 已使用（不使用 `execSync`）
- `randomUUID` 已使用
- `fs.promises` 已使用

## 輸出格式

每個步驟顯示 ✓（通過）或 ✗（失敗），失敗時顯示錯誤訊息。
所有步驟通過後，顯示「✓ 驗證完成，兩支程式均正常」。
