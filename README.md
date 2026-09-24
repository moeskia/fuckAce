# fuckAce

降低腾讯 ACE 反作弊进程（`SGuard64.exe` / `SGuardSvc64.exe`）对系统的影响，把它们的 CPU 占用压到最低。

对每个扫描到的目标进程执行七项设置：

| 列 | 项 | 操作 |
| --- | --- | --- |
| PRIO | 优先级 | 降为 `IDLE_PRIORITY_CLASS` |
| AFF | 亲和性 | 绑定到最后一个逻辑 CPU |
| ECO | EcoQoS | `ProcessPowerThrottling`（`EXECUTION_SPEED`） |
| CAP | CPU 硬上限 | Job Object `CPU_RATE_CONTROL` + `HARD_CAP`（默认 3%/CPU） |
| IO | I/O 优先级 | 进程级 + 每个线程 `IoPriorityVeryLow` |
| MEM | 内存优先级 | `MEMORY_PRIORITY_VERY_LOW` |
| THR | 线程优先级 | 每个线程 `THREAD_PRIORITY_IDLE` |

每项设置后都会回读校验（`IO` 进程级用 `NtQueryInformationProcess(ProcessIoPriority)`、线程级用 `NtQueryInformationThread(ThreadIoPriority)`，`THR` 用 `GetThreadPriority` 逐个线程复核）；只有真正生效才算 OK，否则标 `✗` 并在下一行给出错误码与原因。回读本身失败时同样按未生效处理，显示为 `✗nv`，不会被当成成功。

## 构建

需要 MinGW-w64（`gcc` 与 `windres` 在 PATH 中）：

```powershell
.\build.ps1
```

产物为 `fuckAce.exe`，内嵌 manifest，双击即以管理员身份运行。

## 使用

```
fuckAce.exe [--rate=PERCENT] [--no-cap] [process.exe ...]
```

| 参数 | 说明 |
| --- | --- |
| `--rate=N` | CPU 硬上限，单位是**单个逻辑 CPU 的百分比**，默认 `3` |
| `--no-cap` | 关闭 CPU 硬上限（`--rate=0` 等价） |
| `process.exe` | 追加目标进程名（最长 31 个字符），默认已包含 `SGuard64.exe` 与 `SGuardSvc64.exe` |

`--rate=` 只接受 `0`–`100` 的十进制整数；`--rate=abc`、`--rate=`、负数等写法会直接报错退出，不会静默把上限关掉；大于 `100` 会提示并钳位到 `100`。

直接运行 `fuckAce.exe` 即可。启动会检查权限、扫描进程、逐项设置并以表格输出结果：

- 成功（退出码 `0`）→ 10 秒倒计时后自动退出，也可按 Enter / Esc 立即退出
- 其余退出码 → 5 秒倒计时后自动重试，也可按 Enter 立即重试、按 Esc 退出

### 退出码

| 码 | 含义 |
| --- | --- |
| `0` | 全部目标进程的所有已尝试设置均生效 |
| `1` | 未找到目标进程 / 扫描失败 / 缺少管理员权限 |
| `2` | 部分成功 |
| `3` | 找到进程但无任何设置生效（多为受保护进程） |

## 说明

- 必须在管理员权限下运行，并启用 `SeDebugPrivilege`。
- **CPU 硬上限用 Job Object 实现，程序退出后依然生效**（只要目标进程还活着）。进程无法离开一个不是自己创建的 Job，所以这一项无法被 ACE 自行解除；这也是唯一"解不掉"的限流手段。
- Job 的 `CpuRate` 是**整机**比例，不是单核比例。程序按 `--rate / 逻辑 CPU 数` 换算：在 16 核机器上 `--rate=3` 约为 0.03 个核心。若游戏出现卡顿或 ACE 异常，调大 `--rate` 或使用 `--no-cap`。
- `PRIO` / `AFF` / `ECO` / `MEM` 是进程级设置；`IO` 同时设置进程级与每个已存在线程的 I/O 优先级（线程级设置需要 `SeIncreaseBasePriorityPrivilege`，程序会尽力启用，失败时按真实错误码标出）；`THR` 只作用于执行瞬间已存在的线程（并逐个回读校验），之后新建的线程由进程优先级兜底。
- 拿不到 `PROCESS_SET_QUOTA` + `PROCESS_TERMINATE` 权限时跳过 `CAP`（该列显示 `-`）并在汇总处提示；进程已在别的 Job 中且拒绝嵌套时 `AssignProcessToJobObject` 会失败，此时 `CAP` 列标 `✗` 并给出错误码。两种情况都不影响其余设置。
- ACE 会自我防护，若进程以保护模式运行，部分或全部操作可能返回 `access denied`，此时程序按退出码 `2` / `3` 提示。
- 扫描与设置之间若 PID 被回收，程序会在打开后比对进程名并跳过该条目（汇总处显示 skipped 数）。
- 仅在本地运行，不联网、不修改任何文件。
