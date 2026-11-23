# fuckAce

把腾讯 ACE 反作弊进程（`SGuard64.exe` / `SGuardSvc64.exe`）对系统的影响压到最低。

它**不绕过、不关闭、不注入** ACE：只在 Windows 允许的范围内降低这些进程的调度优先级、绑核、节能限制、CPU 硬上限以及 I/O / 内存 / 线程优先级，每一项设置完都回读校验。

> **运行前必读**
>
> - 需要管理员权限，并会自行提权到 `TrustedInstaller`；过程中会**临时改写 `TrustedInstaller` 服务的 `ImagePath`**（几百毫秒内还原，配套三层兜底）。
> - 为了拿到 TI 身份会**无条件停掉正在运行的 `TrustedInstaller`**，撞上 Windows 更新时会把那次维护打断。
> - 用完不会替你重新拉起 `TrustedInstaller` —— 它是按需启动的，Windows 需要时会自己起来。

## 目录

- [它做什么](#它做什么)
- [快速开始](#快速开始)
- [输出示例](#输出示例)
- [使用](#使用)
- [注意事项](#注意事项)
- [已知限制](#已知限制)
- [提权链（原理）](#提权链原理)
- [源码结构](#源码结构)
- [构建与测试](#构建与测试)
- [许可与免责](#许可与免责)

## 它做什么

对每个扫描到的目标进程执行七项设置：

| 输出列 | 项 | 操作 |
| --- | --- | --- |
| `PRIO` | 优先级 | 降为 `IDLE_PRIORITY_CLASS` |
| `AFF` | 亲和性 | 绑定到最后一个逻辑 CPU |
| `ECO` | EcoQoS | `ProcessPowerThrottling`（`EXECUTION_SPEED`） |
| `CAP` | CPU 硬上限 | Job Object `CPU_RATE_CONTROL` + `HARD_CAP`（固定 `3%/CPU`） |
| `IO` | I/O 优先级 | 进程级 + 每个线程 `IoPriorityVeryLow` |
| `MEM` | 内存优先级 | `MEMORY_PRIORITY_VERY_LOW` |
| `THR` | 线程优先级 | 每个线程 `THREAD_PRIORITY_IDLE` |

每项设置后都会回读校验（`IO` 进程级用 `NtQueryInformationProcess(ProcessIoPriority)`、线程级用 `NtQueryInformationThread(ThreadIoPriority)`，`THR` 用 `GetThreadPriority` 逐个线程复核）；只有真正生效才算成功。

结果单元格的六种取值：

| 显示 | 含义 |
| --- | --- |
| `OK` | 设置已下发，且回读一致 |
| `OK~` | 设置已下发但无法回读（目前只有 `ECO`，见[已知限制](#已知限制)） |
| `✗<code>` | 回读 API 本身失败，`code` 是该 API 的真实错误码 |
| `✗nv` | 回读成功，但读到的值不符 |
| `-` | 该项未执行（如权限不足跳过 `CAP`） |

后四种会在下一行给出具体原因，不会被当成成功。

## 快速开始

需要 Windows 10/11 和 MinGW-w64（`gcc` 与 `windres` 在 PATH 中）：

```powershell
.\build.ps1
.\fuckAce.exe
```

产物 `fuckAce.exe` 内嵌 manifest，双击即以管理员身份运行。

## 输出示例

```text
┌────────────────────────────────────────────────────────────────────────────┐
│ fuckAce · SGuard64 / SGuardSvc64 limiter                                   │
├────────────────────────────────────────────────────────────────────────────┤
│  ✓ admin · ✓ SeDebugPrivilege · 16 CPUs → CPU 15 · cap 3%/CPU              │
│  token TrustedInstaller · NT SERVICE\TrustedInstaller · session 1          │
├────────────────────────────────────────────────────────────────────────────┤
│  #  PROCESS         PID   PRIO   AFF    ECO    CAP    IO     MEM    THR    │
│  1  SGuard64.exe    6812  OK     OK     OK~    OK     OK     OK     OK     │
│  2  SGuardSvc64.exe 6804  OK     OK     OK~    OK     OK     OK     OK     │
├────────────────────────────────────────────────────────────────────────────┤
│  found 2 · full 2 · partial 0 · failed 0                                   │
│  applied prio 2 · aff 2 · eco 2 · cap 2 · io 2 · mem 2 · thr 2             │
│            opened 2/2 · cpu cap 2 · io: proc+threads · eco/mem: proc       │
│  diagnostics  no errors — attempted operations verified                    │
│  ✓ SUCCESS - all attempted settings verified on 2 processes                │
├────────────────────────────────────────────────────────────────────────────┤
│  targets SGuard64.exe ×1 · SGuardSvc64.exe ×1                              │
│  started 21:04:37 · 412 ms · DESKTOP-ABC123                                │
└────────────────────────────────────────────────────────────────────────────┘
 Auto-exit in 10 s  (Enter = exit now)
```

框线宽度随控制台宽度变化，内容以实际输出为准。

## 使用

```text
fuckAce.exe [--diagnose] [process.exe ...]
```

| 参数 | 说明 |
| --- | --- |
| `--diagnose` | 只读打印进程令牌、有效身份和 TI 残留备份状态（`clean` / `STALE`），不尝试提权档、不启动服务、不修改注册表或进程；当前离线身份没有可用档位时退出码 `1` |
| `process.exe` | 追加目标进程名（1–31 个字符）。默认已包含 `SGuard64.exe` 与 `SGuardSvc64.exe`，最多再追加 **30** 个 |

`--escalated=N`、`--syndonor`、`--tirepair=` 是程序自己拉起子进程时用的内部参数，不属于用户界面。任何其它以 `-` 开头的参数都会以 `unknown option` 报错退出。

直接运行 `fuckAce.exe` 即可，启动后依次检查权限、扫描进程、逐项设置并以表格输出结果：

- 成功（退出码 `0`）→ 10 秒倒计时后自动退出，也可按 Enter / Esc 立即退出
- 其余退出码 → 5 秒倒计时后自动重试，也可按 Enter 立即重试、按 Esc 退出
- 提权链一档都没拿到时例外：画一次提权链面板直接以 `1` 退出，不重试（重试也拿不到权限）

正常运行时看不到输出，通常不是提权失败，而是走 UAC 自提权时子进程带自己的控制台（见 [admin 档](#admin-档为什么要单独说)）。

### 退出码

| 码 | 含义 |
| --- | --- |
| `0` | 全部目标进程的所有已尝试设置均生效 |
| `1` | 未找到目标进程 / 扫描失败 / 缺少管理员权限 |
| `2` | 部分成功 |
| `3` | 找到进程但无任何设置生效（多为受保护进程） |

## 注意事项

- **权限**：必须在管理员权限下运行并启用 `SeDebugPrivilege`。程序会沿 TrustedInstaller → SYSTEM → admin 依次回退拿到最高可用令牌，且必须成功，没有关闭入口。
- **权限判定看实际身份**，不看管理员组：admin / SYSTEM / TrustedInstaller 任一档都算够权限。TI 令牌里的 `Administrators` 是 deny-only，只用 `CheckTokenMembership` 会把已提权的进程误判成无权限。
- **提权链不常驻**：SYSTEM 档的临时供体服务用完即 `DeleteService` 并带 60 秒兜底寿命；TI 服务劫持后会停掉并由三层机制还原 `ImagePath`。唯一的持久副作用是劫持本身，暴露窗口只有几百毫秒。
- **CPU 上限程序退出后依然生效**：`CAP` 用 Job Object 实现，只要目标进程还活着就一直有效。进程无法离开一个不是自己创建的 Job，所以这是唯一 ACE 自己解不掉的限流手段。
- **`CpuRate` 是整机比例**：固定 `3%/CPU`（`DEFAULT_CPU_CAP=3`）按逻辑 CPU 数换算，16 核机器上约为 0.03 个核心。要调大或关掉，改 `src/core/common.h` 里的 `DEFAULT_CPU_CAP` 后重新构建，命令行不提供开关。
- **别反复重跑**：Job 用「本地会话名称 + PID + 进程创建时间」命名。目标原本不在任何 Job 里时，重跑会复用同一个 Job；目标已在别的 Job 里时，嵌套出来的 Job 在句柄关闭后名称不可查，重跑会再嵌一层，而嵌套的 `CpuRate` 是相对父 Job 的比例，会**逐层叠加**（两层 3% 实际约为 0.09%）。确认 ACE 已被压住后不必重复运行。
- **七项的作用域**：`PRIO` / `AFF` / `ECO` / `MEM` 是进程级；`IO` 同时设进程级和每个已存在线程的 I/O 优先级（线程级需要 `SeIncreaseBasePriorityPrivilege`，程序尽力启用，失败时标出真实错误码）；`THR` 只作用于执行瞬间已存在的线程（并逐个回读校验），之后新建的线程由进程优先级兜底。
- **`CAP` 的特殊情况**：拿不到 `PROCESS_SET_QUOTA` + `PROCESS_TERMINATE` 时跳过 `CAP`（显示 `-`）并在汇总处提示。目标已在别的 Job 中（ACE 常见情形）时，程序在 Windows 8+ 上把自己的 Job 嵌套进那个 Job 下方（`AssignProcessToJobObject`）；失败不跳过，而是把该调用的真实错误码记到 `CAP` 列按失败处理，其余六项照常执行。
- **目标数量**：一次最多 256 个进程，超出会截断并提示。
- **多处理器组**（>64 逻辑 CPU）：亲和性只落在 group 0，界面会提示。
- **ACE 会自我防护**：目标以保护模式运行时可能返回 `access denied`，此时按退出码 `2` / `3` 提示。
- **PID 回收**：扫描与设置之间若 PID 被复用，程序会在打开后比对进程名并跳过该条目（汇总处显示 skipped 数）。
- **只在本机跑**：不联网、不修改任何文件。

## 已知限制

以下都是本机（Windows 11 客户端，管理员完全提升）实测过的结论，换机器或系统版本可能不同：

| 现象 | 结论 |
| --- | --- |
| 自建 LocalSystem 服务拿到的令牌导出后共 28 个特权，`SeDebug` / `SeImpersonate` / `SeTcb` / `SeBackup` 都有，**唯独没有 `SeCreateTokenPrivilege`** | Windows 11 客户端上 `NtCreateToken` 必然返回 `STATUS_PRIVILEGE_NOT_HELD`（界面显示 `err 1300`），TI 只能走镜像劫持。伪造路径保留（Server 或被策略显式授予过该特权的机器可用），但动手前会先检查令牌，缺特权时直接写 `no SeCreateTokenPrivilege in the SYSTEM token`，不让你对着一个 NTSTATUS 猜 |
| 管理员提升后复制 `TrustedInstaller.exe` 的令牌失败 | 它是 PPL，`Administrators` 连 `TOKEN_DUPLICATE` 都拿不到，界面写 `PPL token not granted to Administrators`；在 SYSTEM 身份下这条路可以成功 |
| 部分 Windows 版本的 `GetProcessInformation(ProcessPowerThrottling)` 返回 `87`（未实现） | `ECO` 无法回读，显示 `OK~`（黄色）并按成功计入退出码；若回读成功却读到未开启，仍按 `✗` 处理 |
| `Administrators` 对 `HKLM\SYSTEM\CurrentControlSet\Services\TrustedInstaller` 只有 `ReadKey` | 还原 `ImagePath`、启动自检都必须先借一次 SYSTEM 令牌，普通管理员根本写不回去 |
| 三层还原机制实测 | ① 服务到 `RUNNING` 就地还原：`ImagePath` 逐字节复原、备份键删除；② 在暴露窗口里强杀父进程：SYSTEM 守护进程在 **134 ms** 内把键修回；③ 手工造出残留后另起一次运行：键被复原、备份键从 HKLM 消失 |

## 提权链（原理）

ACE 的 `SGuardSvc64.exe` 跑在 SYSTEM 下，某些操作管理员权限也够不着。程序在开始扫描之前，会按 **TrustedInstaller → SYSTEM → admin** 的顺序依次尝试拿到更高身份的令牌，谁先成功就用谁；顺序固定，命令行不提供改起始档或只试一档的入口：

| 档位 | 令牌来源 | 拿到令牌的方式 |
| --- | --- | --- |
| TrustedInstaller | `NT SERVICE\TrustedInstaller`（`S-1-5-80-956008885-…`） | ① 复制现成 `TrustedInstaller.exe` 的令牌；② 在借来的 SYSTEM 底座上 `NtCreateToken` 造一张；③ 临时改写 TI 服务的 `ImagePath`（固定强制路径，Windows 11 客户端上只有这条能用） |
| SYSTEM | `NT AUTHORITY\SYSTEM`（`S-1-5-18`） | **首选自建临时 LocalSystem 服务做令牌供体**；失败才去别的进程里找 |
| admin | 当前登录管理员（`S-1-5-32-544`） | 进程已经提升就直接用；否则用 `runas` 走一次 UAC 自提权并等待子进程 |

### 令牌落地（所有档共用）

拿到令牌后固定先**就地把当前线程切到那个身份**（`DuplicateTokenEx` → `SetThreadToken`），全程一个进程，界面、退出码、重试循环都不受影响：

- 落地前先枚举 `TokenPrivileges`，把令牌里**已经存在的**特权逐个启用——拿到的令牌往往连 `SeDebugPrivilege` 都是关闭的。注意 `AdjustTokenPrivileges` 并不存在「`Luid = 0` 表示全部特权」的约定，传 0 等于什么都没开，所以必须逐项打开：SYSTEM 令牌里的 `SeAssignPrimaryTokenPrivilege` 不显式打开的话，`CreateProcessAsUser` 必然 `ERROR_PRIVILEGE_NOT_HELD`。
- 切换后立刻回读线程令牌，SID 对不上就 `RevertToSelf()` 并继续向下回退——**只有真正到位才算这一档成功**。
- 如果这一档是我们自己启动的 `TrustedInstaller` 服务，用完即 `SERVICE_CONTROL_STOP` 停掉，不把系统留在被改过的状态。
- 线程模拟失败时自动改用 `CreateProcessWithTokenW`（失败再退到 `CreateProcessAsUserW`）以该令牌**重新拉起自身**：子进程先以 `CREATE_SUSPENDED` 创建，父进程核验它的令牌身份无误、画完提权链再 `ResumeThread`，子进程跑完把退出码传回父进程。

提权前会尝试启用 `SeImpersonatePrivilege`、`SeAssignPrimaryTokenPrivilege`、`SeIncreaseQuotaPrivilege`、`SeDebugPrivilege` 等特权；失败不致命，只记录首个错误码并在界面上提示。

链上每一档的成功/失败、来源进程 PID 和错误码都会画在界面上；全部失败时画出提权链面板并要求管理员权限，随后以退出码 `1` 结束。

### TrustedInstaller 档

TI 档按「副作用从小到大」依次试三条路，谁先成谁算数：

| 顺序 | 办法 | 需要什么 | 持久副作用 |
| --- | --- | --- | --- |
| 1 | 复制现成 `TrustedInstaller.exe` 的令牌 | 非 PPL 的旧系统，或**已经在 SYSTEM 上**且真有 TI 进程 | 无 |
| 2 | 在 SYSTEM 底座上 `NtCreateToken` 造一张 | LocalSystem **且它的令牌里有 `SeCreateTokenPrivilege`** | 无 |
| 3 | 临时改写 TI 服务的 `ImagePath` | SYSTEM 或已提升的管理员 | 有，但立即还原 |

#### 为什么「造」比「偷」更对

访问检查认的是**令牌里的组 SID**，不是「你是不是那个进程」。一个组里带着 `NT SERVICE\TrustedInstaller`（enabled、非 deny-only）的令牌，在所有授予 TI 的 ACL 上和真 TI 令牌**等价**。

所以链的形态是：**TI 不再独立地排在 SYSTEM 前面硬试，而是先借一个 SYSTEM 身份当底座，再在底座上做 TI**。对用户可见的顺序仍然是 `TrustedInstaller → SYSTEM → admin`，只是 TI 档内部会先用一次 SYSTEM 底座（拿到就缓存，SYSTEM 档再走时不重复建供体服务）：

1. 先按老办法直接复制现成的 TI 进程令牌（零成本，能中就中）；
2. 失败的，`AcquireSystemToken()` 取一个 SYSTEM 主令牌（就是下面那条稳定路径：自建临时 LocalSystem 服务），把当前线程切过去；
3. 在 SYSTEM 身份上 `NtCreateToken(...)` 造令牌：
   - `TokenUser = NT SERVICE\TrustedInstaller`；
   - 组里补上 `SYSTEM`、`Administrators`、`SERVICE`、`Users`、`Everyone`、`Authenticated Users`，全部 enabled —— 造出来的是**真 TI 的超集**，不会因为少一条组 SID 在别处被拦；
   - 常见特权全部置 `SE_PRIVILEGE_ENABLED`；
   - 完整性级别单独设成 `System`（`NtCreateToken` 不认组里的 `S-1-16-*`，不设会被内核按 Medium 处理，写 High IL 对象会被拦）；会话号设成当前会话（不设的话重拉出来的子进程会掉进 session 0，没有桌面）；
   - 默认 DACL 显式给 SYSTEM / Administrators / TI 完全控制（留 NULL 等于给大家完全控制）。
4. 造出来立刻核对：**组里没有 enabled 的 TI SID 就按失败处理**，绝不拿「看起来像」的东西当成功。`NtCreateToken` 返回的 `STATUS_*` 会翻成等价 Win32 码显示。

这条路人称「令牌锻造」，部分 EDR 会盯 `NtCreateToken`，被拦时会以真实错误码显示并继续往下走。

#### 镜像劫持：拿真正的 TI 服务身份

把 `TrustedInstaller` 服务的 `ImagePath` 临时换成自己，让 SCM 用真实的 TI 服务身份把本程序拉起来。该服务的 `ServiceSidType = 1`（`SERVICE_SID_TYPE_UNRESTRICTED`），SCM 会往令牌里补上 `NT SERVICE\TrustedInstaller` —— 这个 SID 由服务名派生，伪造不来。

每一步顺序都是钉死的，因为**改注册表这件事一旦崩在中间，留下的就是一个永久本地提权后门**（服务指向用户可写的二进制）。所以：

1. 先尝试停掉原服务；TI 正忙着打补丁而拒绝停止时放弃这一档，不强杀进程。停 TI 要单独开一个 `SERVICE_STOP` 句柄 —— 把它和 `SERVICE_START` 一起要会让 `OpenService` 整个失败；
2. 把原始 `ImagePath` 存进 `HKLM\SOFTWARE\fuckAce\TiImagePathBackup`。**存 HKLM 而不是文件**：低权限用户写不了 HKLM，否则「恢复路径」就等于「让低权限用户指定 TI 的镜像」；
3. 用一个 SYSTEM 身份拉起**守护进程**（`--tirepair=<pid>`，session 0、无控制台），它盯着父进程，父进程一消失就先做一次幂等还原再退出；
4. 这才改写 `ImagePath` 并 `StartServiceW`；
5. 服务一到 `RUNNING` **立刻**还原 `ImagePath` —— 镜像已经加载进内存，不用等服务退出；
6. 复制供体令牌，按**组**核对 TI SID（供体是 LocalSystem 起的，TI 在组里、不在 `TokenUser` 里；按 `TokenUser` 核对会把成功判成失败），然后把供体停掉 —— 停不了也不要紧，供体自带 60 秒寿命。

还原是幂等的，而且只在「当前值确实是我们写的」（劫持写入的 `ImagePath` 包含内部参数 `--syndonor`）时才覆盖回去，不会把系统修复过的值改坏。三层兜底（服务到 `RUNNING` 就地还原、SYSTEM 守护进程、每次启动读一次备份并就地借 SYSTEM 身份修）的实测结果见[已知限制](#已知限制)。`--diagnose` 会把这个状态画出来（`clean` / `STALE`），而且它只读不改。

> **「都提到 TrustedInstaller 了，为什么还是 SYSTEM？」**
>
> 因为 TI 身份本来就长这样：`TokenUser` 是 `NT AUTHORITY\SYSTEM`，`NT SERVICE\TrustedInstaller` 在**组**里。真正的 `TrustedInstaller.exe` 服务进程用的就是同一副令牌 —— 它的 `ServiceSidType = 1` 会让 SCM 把服务 SID 加进这个 LocalSystem 令牌的组。
>
> 访问检查认的是**组 SID**，所以能力是实打实的 TI（`C:\Windows\servicing\Packages` 这类只有 TI 能写的地方，落地后由 denied 变成 ALLOWED）；但只看 `TokenUser` 的地方 —— `whoami`、任务管理器、进程资源管理器的「用户」列 —— 永远会显示 SYSTEM，那是 `TokenUser`，不是访问身份。
>
> `--diagnose` 的 `effective token` 一栏把两者分开写：`identity` 是真正的访问身份（`TrustedInstaller` / `SYSTEM` / `admin`），`logon` 是令牌的 `TokenUser`。引擎头部那个徽章也打 `NT SERVICE\TrustedInstaller` 而不是 `TokenUser`，免得看起来像提权没生效。

劫持必须先把服务停掉，而且劫持完绝不能把供体留在系统里——那就是一个 TI 身份的后门。所以「保留自己拉起的 TI 服务」这种诉求在本工具里不存在。

### SYSTEM 档

「从 `winlogon` / `services` / `lsass` 里偷令牌」这件事在现代 Windows 上本身不可靠，而且打开令牌时多要权限位会整体失败：

> `OpenProcessToken` 一次要了 `TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT` 的话，其中 `TOKEN_ADJUST_*` **只授予令牌持有者本人**，对任何别人（包括 SYSTEM）的令牌都会被整体拒绝并返回 `ERROR_ACCESS_DENIED(5)`。

所以分成两层：

1. **自建供体（主路径）**：`CreateServiceW` 注册一个临时服务，`binPath` 指向**本程序自己**并带内部参数 `--syndonor`，以 `LocalSystem` 启动。供体进程调用 `StartServiceCtrlDispatcherW` 干净地报 `SERVICE_RUNNING`，父进程从 SCM 查到 pid，复制它的令牌；用完 `SERVICE_CONTROL_STOP` + `DeleteService`。令牌来源是我们自己的二进制，不受目标机器上「跑了哪些进程」、也不受 PPL 影响。
   - 打开令牌只要 `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE`，`TOKEN_ADJUST_*` 留到**复制出来的**句柄上再要（那个句柄是我们自己创建的）。
   - 供体带 60 秒兜底寿命，父进程中途没了也不会把它永远留在系统里。
   - 每次创建前先清掉同名残留服务：`HKLM\SYSTEM\CurrentControlSet\Services\fuckAceSystemDonor` 指向用户可写路径本身就是本地提权隐患，不能留。
2. **进程令牌兜底**：自建供体失败时，才按 `winlogon.exe` → `services.exe` → … 顺序找现成的 SYSTEM 进程，逐个核对 SID；都不行且已启用 `SeDebugPrivilege` 时再全量扫描。

同理，`OpenServiceW(TrustedInstaller, SERVICE_START | SERVICE_STOP | …)` 因为多要了 `SERVICE_STOP` 会整体失败，所以启动路径只请求 `SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_INTERROGATE`。

### admin 档为什么要单独说

`admin` 档在**已经提升**的进程里就地进行；只有进程没提升时才会走 UAC 自提权。而 UAC 拉起来的进程**总是带自己的控制台**，它的报告留在那个窗口里——所以父进程不会把子进程的输出当成自己的：

- 先把提权链面板画完（`UIClearToEnd` 会 `fflush`，画面不会堵在缓冲区里），**再**去 `WaitForSingleObject`；
- 子进程结束后补一张摘要（档位、pid、退出码），并在自己的控制台里倒计时停留，不会一闪而过；
- 退出码原样透传。

## 源码结构

```text
src/
├─ app/         入口、参数配置与主流程
├─ core/        跨模块公共类型和常量
├─ elevation/   提权 API、身份查询、令牌、服务与 TrustedInstaller
├─ system/      进程限制与令牌构造
└─ ui/          控制台界面
tests/          集成测试入口
```

## 构建与测试

构建（需要 MinGW-w64 的 `gcc` 与 `windres`）：

```powershell
.\build.ps1
```

产物为 `fuckAce.exe`，内嵌 manifest，双击即以管理员身份运行。

测试（运行参数、结果判定、提权档与子进程集成测试）：

```powershell
.\test.ps1
```

测试只创建并操作自身启动的子进程，不扫描或修改 ACE。

## 许可与免责

本仓库未提供 `LICENSE` 文件，如需再分发请自行确认授权。

程序会修改进程与服务状态（见[注意事项](#注意事项)与[已知限制](#已知限制)），可能打断正在进行的 Windows 更新，风险自担。它不绕过 ACE 的检测逻辑，也不为其提供任何屏蔽或卸载能力。
