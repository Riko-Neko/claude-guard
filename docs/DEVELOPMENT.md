# 開發與測試

## 環境

目前目標為 Apple Silicon、macOS 13 以上。需要 Python 3、Node.js（前端事件測試）及 Xcode Command Line Tools（Swift／C 編譯）。實際使用另需 Clash Verge 和原版 Claude。增強模式依賴另行安裝的 LuLu 4.5.6。

## 目錄

| 路徑 | 內容 |
| --- | --- |
| `src/` | 原生選單列介面、受控代理、環境檢查、唯讀過濾驗證 |
| `interface/` | 繁中／簡中／英文設定與選單面板 |
| `tools/` | 引導、建置、維護與移除工具 |
| `tests/` | 替身、暫存檔案與本機無帳號探針測試 |
| `assets/` | 圖示與連線示意 |
| `references/lulu-cli-review/` | 固定 MIT 開發參考及其授權 |
| `build.py` | 建置應用程式與 `.pkg`；不安裝或啟動 |

個人設定、`runtime/`、診斷歷史、第三方完整參考倉庫與舊安裝包由 `.gitignore` 排除，保留在本機。發行附件位於 GitHub Releases，不進入原始碼歷史。

## 建置

```sh
python3 build.py
```

產生 `dist/ClaudeGuard-0.12.0.pkg` 與相容舊入口的 `ClaudeGuard-runtime.zip`。只有 `.pkg` 作為正式使用者下載入口。建置包含 Swift 編譯與 ad-hoc strict/deep 簽章驗證，不需要或呼叫登入中的 Claude。尚未提供 Apple Developer ID 簽章及公證。

## 自動測試

```sh
python3 -m unittest discover -s tests
node tests/test_interface_flow.js
node tests/test_guard_alerts.js
node tests/test_setup_selection.js
node tests/test_ip_risk_ui.js
```

測試不啟動 Claude、不安裝 LuLu、不修改正在使用的網路。部分測試會編譯 Swift／C、在暫存目錄產生格式相容性資料或使用本機回環連線。獨立的 `tests/verify_lulu_flow.py` 是安裝向導的驗收入口，會檢查實際過濾和外網探針，不屬於上述 unittest 指令。

## 安裝與執行邊界

不要從開發目錄直接執行系統維護腳本或以真實 Claude 帳號自動測試。使用建好的安裝包，由使用者完成 macOS 原生授權及真實安裝驗收。個人執行目錄位於 `~/Library/Application Support/Claude Guard/Runtime`；開發倉庫不是安裝後的執行依賴。

## 連線恢復

臨時連通故障先關閉受控連線，每次復查結束約 5 秒後再試。只有原節點、批准出口及所選保護檢查均通過才恢復。曾觀察到出口或節點參數改變時，必須重新批准。使用者主動暫停／退出不會被自動恢復。

## IP 來源檢查與人工批准

`src/ip_reputation.py` 只處理正規化、快取及並行更新，傳輸由 Session 注入，所有 HTTPS 查詢固定經私有核心與已選節點，沒有直連降級。來源結果以 `IP_REPUTATION` 事件增量送往介面，舊 IP 的遲到結果不更新目前畫面。

介面透過私有 stdin 管道送出 `approve_ip`（IP 與隨機 proposal_id）或 `risk_refresh`。人工批准再次檢查出口、國家、節點、TUN 及增強過濾狀態，通過後原子寫入新基準，閘門版本必須仍一致。來源風險評分不參與放行決策；純檢查會話不會啟動 Claude。`tools/network_status.py` 只讀取本機 Clash 控制器與 macOS 代理設定，開啟選單時更新；執行中的 Session 沿用既有配置輪詢發布 `NETWORK_MODE`。TUN 狀態本身僅提示，不改變閘門，首次設定的系統代理明確確認由 DiscoverySession 保留。相關測試使用替身、暫存設定與假來源，完整來源限制見 [IP_REPUTATION.md](IP_REPUTATION.md)。

## 錯誤詳情與提示卡片

`src/diagnostics.py` 將例外正規化為階段、原始類型、errno、TLS reason、驗證代碼及原始位置等可用欄位，經 `BLOCKED`／`CHECK_FAILED`／`RESUME_FAILED` 的 `diagnostic` 傳給介面。只呈現實際可取得的位址，不推測記憶體資訊；敏感授權資訊先遮罩，命令逾時不輸出完整命令參數。

原生提示依文字測量設定內容高度，保留非激活與恢復後 1 秒收起行為。`prepareCriticalAlert` 可在隔離程序中只建構／量測視圖，不顯示視窗或啟動帳號程式。

## 發行

先執行測試、建置與公開內容檢查，再上傳 `.pkg` 及 `SHA256SUMS.txt`。勿上傳 `settings.json`、執行日誌、真實 IP、VPN 訂閱、聊天資料或開發用系統快照。更新 `interface/strings.json` 時應同步產生 `strings.js`。
