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

`ECO` 是唯一例外：Windows 的 `GetProcessInformation(ProcessPowerThrottling)` 在不少版本上并未实现（返回 `87`），无法回读。此时设置已下发但无法核实，显示为 `OK~`（黄色）并按成功计入退出码；若回读成功却读到未开启，仍按 `✗` 处理。

## 提权链：TrustedInstaller → SYSTEM → admin

ACE 的 `SGuardSvc64.exe` 跑在 SYSTEM 下，某些操作管理员权限也够不着。程序在开始扫描之前，会按 **TrustedInstaller → SYSTEM → admin** 的顺序依次尝试拿到更高身份的令牌，谁先成功就用谁：

| 档位 | 令牌来源 | 拿到令牌的方式 |
| --- | --- | --- |
| TrustedInstaller | `NT SERVICE\TrustedInstaller`（`S-1-5-80-956008885-…`） | 先找已在运行的 `TrustedInstaller.exe`；找不到就用 SCM 启动 `TrustedInstaller` 服务并等它就绪，取进程令牌 |
| SYSTEM | `NT AUTHORITY\SYSTEM`（`S-1-5-18`） | **首选自建临时 LocalSystem 服务做令牌供体**；失败才去别的进程里找 |
| admin | 当前登录管理员（`S-1-5-32-544`） | 进程已经提升就直接用；否则用 `runas` 走一次 UAC 自提权并等待子进程 |

### SYSTEM 这一档为什么能稳定

"从 `winlogon` / `services` / `lsass` 里偷令牌"这件事在现代 Windows 上**本身就不可靠**，而且原来那版还有个必挂的 bug：

> `OpenProcessToken` 一次要了 `TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT`。
> 其中 `TOKEN_ADJUST_*` **只授予令牌持有者本人**，对任何别人（包括 SYSTEM）的令牌都会被整体拒绝并返回 `ERROR_ACCESS_DENIED(5)`。
> 结果就是 SYSTEM 档在管理员下也**从来没有成功过**。

现在的做法分两层：

1. **自建供体（主路径，`--no-service` 可关）**：`CreateServiceW` 注册一个临时服务，`binPath` 指向**本程序自己**并带 `--syndonor`，以 `LocalSystem` 启动。供体进程调用 `StartServiceCtrlDispatcherW` 干净地报 `SERVICE_RUNNING`，父进程从 SCM 查到 pid，复制它的令牌；用完 `SERVICE_CONTROL_STOP` + `DeleteService`。令牌来源是我们自己的二进制，不受目标机器上"跑了哪些进程"、也不受 PPL 影响。
   - 打开令牌只要 `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE`，`TOKEN_ADJUST_*` 留到**复制出来的**句柄上再要（那个句柄是我们自己创建的）。
   - 供体带 60 秒兜底寿命，父进程中途没了也不会把它永远留在系统里。
   - 每次创建前先清掉同名残留服务：`HKLM\SYSTEM\CurrentControlSet\Services\fuckAceSystemDonor` 指向用户可写路径本身就是本地提权隐患，不能留。
2. **进程令牌兜底**：自建供体失败时，才按 `winlogon.exe` → `services.exe` → … 顺序找现成的 SYSTEM 进程，逐个核对 SID；都不行且已启用 `SeDebugPrivilege` 时再全量扫描。

顺带修掉的同类问题：`OpenServiceW(TrustedInstaller, SERVICE_START | SERVICE_STOP | …)` 也会因为多要了 `SERVICE_STOP` 而整体失败，现在启动路径只请求 `SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_INTERROGATE`。

### TrustedInstaller 这一档拿不到是常态

实测（Windows 10/11，管理员完全提升）：`TrustedInstaller.exe` 是 **PPL**，其令牌只授予 SYSTEM 和 TI 自己的服务 SID，`Administrators` 连 `TOKEN_DUPLICATE` 都拿不到 —— 服务能起来，令牌复制一定 `ERROR_ACCESS_DENIED`。界面会直接写 `PPL token not granted to Administrators`，然后正常回退到 SYSTEM。这一档保留是因为部分系统版本仍然可拿。

拿到令牌后默认**就地把当前线程切到那个身份**（`DuplicateTokenEx` → `SetThreadToken`），全程一个进程，界面、退出码、重试循环都不受影响：

- 落地前先 `AdjustTokenPrivileges` 把令牌里的**全部特权打开**（`Luid=0` 的约定用法），否则拿到的令牌往往连 `SeDebugPrivilege` 都是关闭的。
- 切换后立刻回读线程令牌，SID 对不上就 `RevertToSelf()` 并继续向下回退——**只有真正到位才算这一档成功**。
- 如果这一档是我们自己启动的 `TrustedInstaller` 服务，用完即 `SERVICE_CONTROL_STOP` 停掉，不把系统留在被改过的状态（`--keep-ti` 可关掉这个行为）。
- `--spawn` 则改用 `CreateProcessWithTokenW`（失败再退到 `CreateProcessAsUserW`）以该令牌**重新拉起自身**：子进程先以 `CREATE_SUSPENDED` 创建，父进程核验它的令牌身份无误、画完提权链再 `ResumeThread`，子进程跑完把退出码传回父进程。

### admin 档为什么要单独说

`admin` 档在**已经提升**的进程里就地进行；只有进程没提升时才会走 UAC 自提权。而 UAC 拉起来的进程**总是带自己的控制台**，它报告留在那个窗口里——所以父进程不会把子进程的输出当成自己的：

- 先把提权链面板画完（`UIClearToEnd` 会 `fflush`，画面不会堵在缓冲区里），**再**去 `WaitForSingleObject`；
- 子进程结束后补一张摘要（档位、pid、退出码），并在自己的控制台里倒计时停留，不会一闪而过；
- 退出码原样透传。

看不到输出通常不是“提权失败”，而是这个窗口切换的锅：跑 `fuckAce.exe --diagnose` 会直接打印每一档的结果（含来源进程、错误码、令牌的 elevation / 完整性 / 会话），`--diagnose` 只报告、不扫描也不改任何进程。

SSDT 之外的影响：`SeImpersonatePrivilege`、`SeAssignPrimaryTokenPrivilege`、`SeIncreaseQuotaPrivilege`、`SeDebugPrivilege` 等特权会在提权前逐个启用，失败不致命，只记录首个错误码并在界面上提示。

`--no-elevate` 可以整条链关掉，退回原来的“直接以当前权限跑”。链上每一档的成功/失败、来源进程 PID 和错误码都会画在界面上；全部失败时不会静默降级——引擎头部会打出 `token none` 并附 `! escalation chain exhausted`。

## 构建

需要 MinGW-w64（`gcc` 与 `windres` 在 PATH 中）：

```powershell
.\build.ps1
```

产物为 `fuckAce.exe`，内嵌 manifest，双击即以管理员身份运行。

运行参数、结果判定和子进程集成测试：

```powershell
.\test.ps1
```

测试只创建并操作自身启动的子进程，不扫描或修改 ACE。

## 使用

```
fuckAce.exe [--rate=PERCENT] [--no-cap] [--nest] [--as=TIER] [--no-elevate] [--no-fallback] [--impersonate|--spawn] [--keep-ti] [process.exe ...]
```

| 参数 | 说明 |
| --- | --- |
| `--rate=N` | CPU 硬上限，单位是**单个逻辑 CPU 的百分比**，默认 `3` |
| `--no-cap` | 关闭 CPU 硬上限（`--rate=0` 等价） |
| `--nest` | 目标已在其它 Job 中时，尝试把自己的 Job 嵌套进去以继续施加 `CAP`；默认跳过。详见下方说明 |
| `--as=TIER` | 指定提权链从哪一档开始：`ti` / `system` / `admin`（也接受 `trustedinstaller`、`administrator`）；`auto`（默认）从 TrustedInstaller 开始，`off` 等价于 `--no-elevate` |
| `--no-elevate` | 完全不提权，直接用当前令牌运行（旧行为） |
| `--no-fallback` | 只试 `--as=` 指定的那一档，失败就带着当前权限继续，不向下回退 |
| `--impersonate` | 只用线程模拟（默认行为之一） |
| `--spawn` | 只用令牌重新拉起自身，不做线程模拟 |
| `--keep-ti` | 用完不停止自己启动的 TrustedInstaller 服务 |
| `--no-service` | 不用临时 LocalSystem 服务做 SYSTEM 供体，只从现有进程里找 SYSTEM 令牌（不建议） |
| `--diagnose` | 只跑提权链并把每一档的结果、令牌 elevation/完整性/会话打印出来，不扫描也不改任何进程；全部失败时退出码 `1` |
| `--escalated=N` | 内部参数，父进程用它告知子进程“你已经处在第 N 档”，防止无限递归 |
| `process.exe` | 追加目标进程名（最长 31 个字符），默认已包含 `SGuard64.exe` 与 `SGuardSvc64.exe` |

`--rate=` 只接受 `0`–`100` 的纯十进制整数；空值、正负号、空白、十六进制或混合文本都会报错退出；大于 `100`（含超长整数）会提示并钳位到 `100`，`--rate=0` 等价于 `--no-cap`。`--as=` 与 `--escalated=` 同样只接受合法取值，非法值直接报错退出。

直接运行 `fuckAce.exe` 即可。启动会检查权限、扫描进程、逐项设置并以表格输出结果：

- 成功（退出码 `0`）→ 10 秒倒计时后自动退出，也可按 Enter / Esc 立即退出
- 其余退出码 → 5 秒倒计时后自动重试，也可按 Enter 立即重试、按 Esc 退出
- 提权链一档都没拿到时例外：画一次提权链面板直接以 `1` 退出，不重试（重试也拿不到权限）

### 退出码

| 码 | 含义 |
| --- | --- |
| `0` | 全部目标进程的所有已尝试设置均生效 |
| `1` | 未找到目标进程 / 扫描失败 / 缺少管理员权限 |
| `2` | 部分成功 |
| `3` | 找到进程但无任何设置生效（多为受保护进程） |

## 说明

- 必须在管理员权限下运行，并启用 `SeDebugPrivilege`。默认还会先沿 TrustedInstaller → SYSTEM → admin 依次回退拿到最高可用令牌，见上文；`--no-elevate` 可关掉。
- **CPU 硬上限用 Job Object 实现，程序退出后依然生效**（只要目标进程还活着）。进程无法离开一个不是自己创建的 Job，所以这一项无法被 ACE 自行解除；这也是唯一"解不掉"的限流手段。
- Job 的 `CpuRate` 是**整机**比例，不是单核比例。程序按 `--rate / 逻辑 CPU 数` 换算：在 16 核机器上 `--rate=3` 约为 0.03 个核心。若游戏出现卡顿或 ACE 异常，调大 `--rate` 或使用 `--no-cap`。
- `PRIO` / `AFF` / `ECO` / `MEM` 是进程级设置；`IO` 同时设置进程级与每个已存在线程的 I/O 优先级（线程级设置需要 `SeIncreaseBasePriorityPrivilege`，程序会尽力启用，失败时按真实错误码标出）；`THR` 只作用于执行瞬间已存在的线程（并逐个回读校验），之后新建的线程由进程优先级兜底。
- 拿不到 `PROCESS_SET_QUOTA` + `PROCESS_TERMINATE` 权限时跳过 `CAP`（该列显示 `-`）并在汇总处提示。目标若已在其它 Job 中（ACE 常见情形），默认跳过 `CAP` 并在汇总处提示；加 `--nest` 后，程序会在 Windows 8+ 上尝试把自己的 Job 嵌套进那个 Job 下方（`AssignProcessToJobObject`），成功则 `CAP` 照常生效，失败则跳过并在该行注明真实错误码，其余六项照常执行。
- 提权链只影响**本进程的有效身份**，不写注册表、不装服务、不留后门：`TrustedInstaller` 服务是 Windows 自带的组件，只有在我们把它拉起来时才会去停；`--spawn` 模式下父进程会等子进程跑完并把退出码原样传回。
- 引擎对“够权限”的判定看的是**实际身份**（admin / SYSTEM / TrustedInstaller 任一档）而不是单纯的管理员组：TrustedInstaller 令牌里的 `Administrators` 是 deny-only，只用 `CheckTokenMembership` 判定会把已提权的进程误判成无权限。
- 新建的 Job 使用 `本地会话名称 + PID + 进程创建时间` 标识。目标原本不在任何 Job 中时，自动重试或再次运行会复用并更新同一个 Job，不会重复限流；关闭本程序句柄后上限仍保留。但目标已在其它 Job 中（即 `--nest` 生效）时，嵌套出来的 Job 在句柄关闭后**名称不再可查**，再次运行/重试会再嵌套一层；嵌套的 `CpuRate` 是相对父 Job 的比例，会**逐层叠加**（两层 3% 实际约为 0.09%）。因此 `--nest` 建议每次会话只运行一次，确认 ACE 已被压住后不必重复运行。`--no-cap` 只跳过本次设置，不撤销已有上限。
- ACE 会自我防护，若进程以保护模式运行，部分或全部操作可能返回 `access denied`，此时程序按退出码 `2` / `3` 提示。
- 扫描与设置之间若 PID 被回收，程序会在打开后比对进程名并跳过该条目（汇总处显示 skipped 数）。
- 仅在本地运行，不联网、不修改任何文件。
