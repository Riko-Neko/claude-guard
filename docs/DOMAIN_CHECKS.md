# 域名通過率

此為實驗性的加權檢查指標，並非安全、零洩漏或帳號可用機率。與 IP 風險顯示在同一張選單卡片，獨立於初次設定的出口確認；開啟檢查或受控會話後並行更新，不阻塞 Claude 啟動。約每小時更新，也可手動重新查詢。結束會話後停止。

## 兩類依據

1. 具體主機先經 Guard 私有代理核心，以 HTTPS 請求該主機的 `/cdn-cgi/trace`。只接受該 HTTPS 主機返回的有效 Cloudflare trace（含相符主機、公開 IP、地區與機房）；將來源 IP 與本次核驗的 VPN IP 比較。不借用 Cloudflare 主站的 IP 結果替其他網站背書。
2. 站點不支援 trace、無有效回應或連線失敗時，另以本機證據檢查 Guard 的指定代理路徑。核對其啟動時的完整設定指紋與仍在執行的私有核心；該設定為唯一無條件 `MATCH,ApprovedNode`，沒有目標直連降級，也沒有對外控制介面。展開頁會明示「代理路徑」及 trace 未取得原因，不聲稱已看到站點的來源 IP。

`anthropic.com`、`claude.ai`、`claude.com` 同時檢查根主機 trace 與整個後綴的指定代理路徑。通配範圍不能逐一列舉、也不向虛構子域發請求；其他通配範圍只做路徑覆蓋核對。根主機的返回 IP 不代表所有子域。範圍與其中列出的關鍵主機分別計分，但不對同一主機重複發送請求。

私有核心的路徑證據僅適用於**經 Guard 的連線**，不證明系統其他應用、外部瀏覽器、SSH 或繞過 Guard 的元件皆使用該代理。相同節點也可能由服務商按目標使用不同出口；取得 trace 的主機才有逐站 IP 證據。

## 權重

| 檢查項 | 百分點 |
| --- | ---: |
| `anthropic.com` 及子域（核心） | 15 |
| `claude.ai` 及子域（核心） | 15 |
| `api.anthropic.com` | 10 |
| `claude.com` 及子域 | 8 |
| `platform.claude.com` | 8 |
| `sso.claude.com` | 6 |
| `mcp-proxy.anthropic.com` | 5 |
| `*.claudeusercontent.com` | 4 |
| `*.claudemcpcontent.com` | 4 |
| `assets-proxy.anthropic.com` | 3 |
| `downloads.claude.ai` | 3 |
| `bridge.claudeusercontent.com` | 3 |
| `*.claude.app` | 3 |
| `statsig.anthropic.com` | 1 |
| `http-intake.logs.us5.datadoghq.com` | 1 |
| `browser-intake-us5-datadoghq.com` | 1 |
| 合計 | 90 |

兩個核心範圍必須都完成並通過，才解鎖起步 30 分。核心範圍內任何清單項的路徑失效，或**任一具體站點返回來源 IP 不一致**，整體顯示 0%。其他未知、檢查中或未通過項不加分；核心尚無結論時不顯示確定分數。整數顯示，0 為紅色，30 為橙色，90–100 為綠色。未取得 trace 但代理路徑已核對時，可取得該項權重，詳情保留其不同證據級別。

前面全數通過達 90 後，才計入 geosite 補充分：`floor(10 × 補充通過數 / 補充總數)`。完整解析的清單若沒有補充項，代表既有範圍已覆蓋該份清單，可得完整 10 分；下載失敗、未知格式或空清單則不能加分。

## geosite 補充

從 [MetaCubeX 的 anthropic 清單](https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/anthropic.list) 取得同名分類的文字版本。它不一定與使用者本機 geosite.dat 的版本相同。按完整域名／後綴語義去重，只補充前面尚未涵蓋的項目；補充項以相同私有核心路徑核對，不大量請求額外站點。展開顯示本次補充列表與來源內容 SHA-256。不聲稱涵蓋資料庫未收錄的網站。

解析只接受完整主機及 `+.` 後綴格式；未知語法不悄悄略過。原始清單只用於本次解析，不重新散發。依 [Mihomo 規則說明](https://wiki.metacubex.one/config/rules/)，後綴涵蓋根域與子域，MATCH 無條件匹配。

## 更新、保護與隱私

- 每個返回結果即時更新。查詢最多四路並行、每次傳輸設置超時及大小限制，不跟隨轉址，沒有直連重試。
- 不帶 Claude 登入憑證、Cookie、聊天內容或 VPN 訂閱。目標站點仍可觀察一般 HTTPS 診斷請求與其來源 IP；清單來源同樣經指定節點取得。
- 記錄僅含檢查項、返回 IP、證據種類、狀態、錯誤類型、時間及來源摘要，不記錄完整 trace、Cookie 或伺服器回應。私人快取為 0600；分享日誌前請移除 IP。
- 新 IP 不沿用舊 IP 的結果。過期、網路切換前啟動的檢查或舊世代較晚返回的結果，不作為本次有效分數。恢復連線後重新檢查。
- 本指標只供觀察；**不自動批准新 IP，也不改變既有出口／節點／過濾的暫停及人工確認機制**。0% 不會自行新增封鎖；使用者仍可看到具體差異並決定如何處理。

建置及回歸使用虛構回應與隔離頁面；不自動啟動已登入的 Claude，也不探測使用者目前的真實帳號環境。
