# fuckAce

降低腾讯 ACE 反作弊进程（`SGuard64.exe` / `SGuardSvc64.exe`）对系统的影响，把它们的 CPU 占用压到最低。

对每个扫描到的目标进程执行三项设置：

| 项 | 操作 |
| --- | --- |
| PRI | 优先级降为 `IDLE_PRIORITY_CLASS` |
| AFF | 亲和性绑定到最后一个逻辑 CPU |
| ECO | 开启 EcoQoS（`ProcessPowerThrottling`） |

## 构建

需要 MinGW-w64（`gcc` 与 `windres` 在 PATH 中）：

```powershell
.\build.ps1
```

产物为 `fuckAce.exe`，内嵌 manifest，双击即以管理员身份运行。

## 使用

直接运行 `fuckAce.exe`。启动会扫描进程、逐项设置并以表格输出结果：

- 成功（退出码 `0`）→ 10 秒倒计时后自动退出，也可按 Enter / Esc 立即退出
- 失败或部分成功 → 5 秒倒计时后自动重试，也可按 Enter 立即重试、按 Esc 退出

### 退出码

| 码 | 含义 |
| --- | --- |
| `0` | 全部目标进程三项设置均成功 |
| `1` | 未找到目标进程 / 扫描失败 / 缺少管理员权限 |
| `2` | 部分成功 |
| `3` | 找到进程但无任何设置生效（多为受保护进程） |

## 说明

- 必须在管理员权限下运行，并启用 `SeDebugPrivilege`。
- ACE 会自我防护，若进程以保护模式运行或重新拉起，部分或全部操作可能返回 `access denied`，此时程序按退出码 `2` / `3` 提示。
- 仅在本地运行，不联网、不修改任何文件。
