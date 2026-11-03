# 第三方依賴與授權

## LuLu

- 上游：[Objective-See / LuLu](https://github.com/objective-see/LuLu)。
- 增強模式固定驗證官方 **4.5.6** 發行版、下載 SHA-256 與發行者簽章。
- LuLu 上游採用 GNU GPL v3；請參閱[上游授權](https://github.com/objective-see/LuLu/blob/master/LICENSE.md)。
- 本倉庫及 Guard 安裝包不包含 LuLu 二進位或完整原始碼。增強設定流程另行下載官方原版，保留其簽章、名稱、授權及 macOS 權限流程。
- 普通模式不需要 LuLu。Guard 沒有重新簽署或以自有簽章取代 LuLu 網路擴展。

## lulu-cli 開發參考

`references/lulu-cli-review/main.swift` 保留自 [woop/lulu-cli](https://github.com/woop/lulu-cli) 的固定原始碼快照，供隔離的格式相容性測試使用。上游 MIT 版權為 **Copyright (c) 2026 Willem Pienaar**，完整條款保留在 [references/lulu-cli-review/LICENSE](references/lulu-cli-review/LICENSE)。

`tools/build_lulu_staging_cli.py` 在建置時套用相容性與僅限暫存檔案的限制，不更改上游快照；建出的 CLI 不隨 Guard 安裝包發行，也不能重載系統擴展。

## 其他執行依賴

Clash Verge／Mihomo、Claude、Python 與 macOS 系統元件由使用者自行安裝，遵循各自授權。Guard 安裝包不攜帶 VPN 訂閱、節點憑證、Claude 帳號或上述應用程式。

Claude 與 Anthropic 為各權利人的名稱及商標。本工具與 Anthropic、Objective-See 或 Clash Verge 無隸屬關係。
