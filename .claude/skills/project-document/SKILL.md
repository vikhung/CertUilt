更新專案文件，確保內容與程式碼實際行為一致。

---
name: project-document
description: 當使用者要求同步文件與程式碼、更新說明文件、或詢問現有文件是否正確時使用。
---


## 更新目標

1. **README.md** — 使用者入門說明；重點確認執行指令、CLI 旗標（`--no-cache`、`--help`）、`pem/` 輸出目錄結構、manifest 檔案名稱是否與 `findUCA.js` 實際行為一致
2. **CLAUDE.md** — 給 Claude AI 參考的架構說明；重點確認下列項目：
   - `findUCA.js` 輸出一節中的 `pem/` 目錄結構（`myCert`、`01.expire`、`00.new`、`02.notExist`）及 manifest 路徑（`.myCert-manifest.json`、`ccadb-manifest.json`）
   - 各模組職責表格中的描述是否反映最新實作
   - 快取機制一節中 `downloadHistory[]` 格式說明

## 更新原則

- **以程式碼為準**：先用 Read 工具讀取 `findUCA.js`、`lib/ccadb-client.js`、`lib/report-generator.js`、`lib/config-loader.js` 以及要更新的目標文件目前的完整內容，再逐段比對；不根據記憶修改
- 只更新與程式碼實際行為不符的地方，不改動仍然正確的內容
- 不修改人工維護的段落（如開發原則、執行環境說明等非從程式碼衍生的規範）

## 更新完畢後

列出每個文件實際修改了哪些地方（檔名 + 簡述），若某個文件不需要修改請說明原因。
