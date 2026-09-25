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
| TrustedInstaller | `NT SERVICE\TrustedInstaller`（`S-1-5-80-956008885-…`） | ① 复制现成 `TrustedInstaller.exe` 的令牌；② 在借来的 SYSTEM 底座上 `NtCreateToken` **造一张**；③ 临时换 TI 服务的 `ImagePath`（默认开，**Windows 11 客户端上只有这条能用**，见下文） |
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

### TrustedInstaller 这一档：先"造"，造不出来就换身份

默认档位就是 TrustedInstaller：`--as=auto` 从 TI 开始，TI 拿不到才往 SYSTEM 回退，SYSTEM 也不行才到 admin（`--no-fallback` 可只试一档）。

实测（Windows 11，管理员完全提升）：`TrustedInstaller.exe` 的令牌，`Administrators` 连 `TOKEN_DUPLICATE` 都拿不到 —— **"去偷它的令牌"这条路对管理员来说在现代 Windows 上注定失败**，界面会写 `PPL token not granted to Administrators`。

所以 TI 档按"副作用从小到大"依次试三条路，谁先成谁算数：

| 顺序 | 办法 | 需要什么 | 持久副作用 | 本机实测 |
| --- | --- | --- | --- | --- |
| 1 | 复制现成 `TrustedInstaller.exe` 的令牌 | 非 PPL 的旧系统，或**已经在 SYSTEM 上**且真有 TI 进程 | 无 | 管理员下失败（PPL）；SYSTEM 下成功 |
| 2 | 在 SYSTEM 底座上 `NtCreateToken` 造一张 | LocalSystem **且它的令牌里有 `SeCreateTokenPrivilege`** | 无 | **Windows 11 客户端不可用**，见下 |
| 3 | 临时改写 TI 服务的 `ImagePath`（默认开，见下文） | SYSTEM 或已提升的管理员 | 有，但立即还原 | **验证通过** |

#### 实测：Windows 11 客户端的 LocalSystem 里没有 `SeCreateTokenPrivilege`

`NtCreateToken` 需要只有 LocalSystem 才有的 `SeCreateTokenPrivilege`。把本机自建 LocalSystem 服务拿到的令牌整个导出来看，**28 个特权里就是没有它**（`SeDebug` / `SeImpersonate` / `SeTcb` / `SeBackup` 都有，唯独没有它），于是 `NtCreateToken` 必然返回 `STATUS_PRIVILEGE_NOT_HELD`，界面上是 `err 1300`。

所以结论很直接：**Windows 11 客户端上 TI 只能走镜像劫持**（默认已开）。伪造那条路照样保留（零持久状态，Server 或者被策略显式授予过该特权的机器上可用），只是在动手前先问一句令牌里有没有这个特权，没有就写 `no SeCreateTokenPrivilege in the SYSTEM token`，不让你对着一个 NTSTATUS 猜。

#### 为什么"造"比"偷"更对

访问检查认的是**令牌里的组 SID**，不是"你是不是那个进程"。一个组里带着 `NT SERVICE\TrustedInstaller`（enabled、非 deny-only）的令牌，在所有授予 TI 的 ACL 上和真 TI 令牌**等价**。

于是链的形态变了：**TI 不再独立地排在 SYSTEM 前面硬试，而是先借一个 SYSTEM 身份当底座，再在底座上做 TI**。对用户可见的顺序仍然是 `TrustedInstaller → SYSTEM → admin`，只是 TI 档内部会先用一次 SYSTEM 底座（拿到就缓存，SYSTEM 档再走时不重复建供体服务）：

1. 先按老办法直接复制现成的 TI 进程令牌（零成本，能中就中）；
2. 失败的，`AcquireSystemToken()` 取一个 SYSTEM 主令牌（就是上面那条稳定路径：自建临时 LocalSystem 服务），把当前线程切过去；
3. 在 SYSTEM 身份上 `NtCreateToken(...)` 造令牌：
   - `TokenUser = NT SERVICE\TrustedInstaller`；
   - 组里补上 `SYSTEM`、`Administrators`、`SERVICE`、`Users`、`Everyone`、`Authenticated Users`，全部 enabled —— 造出来的是**真 TI 的超集**，不会因为少一条组 SID 在别处被拦；
   - 常见特权全部置 `SE_PRIVILEGE_ENABLED`；
   - 完整性级别单独设成 `System`（`NtCreateToken` 不认组里的 `S-1-16-*`，不设会被内核按 Medium 处理，写 High IL 对象会被拦）；会话号设成当前会话（不设的话 `--spawn` 出来的子进程会掉进 session 0，没有桌面）；
   - 默认 DACL 显式给 SYSTEM / Administrators / TI 完全控制（留 NULL 等于给大家完全控制）。
4. 造出来立刻核对：**组里没有 enabled 的 TI SID 就按失败处理**，绝不拿"看起来像"的东西当成功。`NtCreateToken` 返回的 `STATUS_*` 会翻成等价 Win32 码显示。

`--no-ti-forge` 关掉这条路；`--no-service` 下 SYSTEM 底座退回"从现有进程里找"，伪造照常可用。这条路人称"令牌锻造"，部分 EDR 会盯 `NtCreateToken`，被拦时会以真实错误码显示并继续往下走。

#### `--ti-hijack`：拿真正的 TI 服务身份，代价是动一次注册表

把 `TrustedInstaller` 服务的 `ImagePath` 临时换成自己，让 SCM 用真实的 TI 服务身份把本程序拉起来。该服务的 `ServiceSidType = 1`（`SERVICE_SID_TYPE_UNRESTRICTED`），SCM 会往令牌里补上 `NT SERVICE\TrustedInstaller` —— 这个 SID 由服务名派生，伪造不来。

这条路的每一步顺序都是钉死的，因为**改注册表这件事一旦崩在中间，留下的就是一个永久本地提权后门**（服务指向用户可写的二进制）。所以：

1. 先确认原服务能**停下来**（TI 正忙着打补丁就放弃这一档，不硬停）；停 TI 要单独开一个 `SERVICE_STOP` 句柄 —— 把它和 `SERVICE_START` 一起要会让 `OpenService` 整个失败；
2. 把原始 `ImagePath` 存进 `HKLM\SOFTWARE\fuckAce\TiImagePathBackup`。**存 HKLM 而不是文件**：低权限用户写不了 HKLM，否则"恢复路径"就等于"让低权限用户指定 TI 的镜像"；
3. 用一个 SYSTEM 身份拉起**守护进程**（`--tirepair=<pid>`，session 0、无控制台），它盯着父进程，父进程一消失就先做一次幂等还原再退出；
4. 这才改写 `ImagePath` 并 `StartServiceW`；
5. 服务一到 `RUNNING` **立刻**还原 `ImagePath` —— 镜像已经加载进内存，不用等服务退出。**暴露窗口只有几百毫秒**；
6. 复制供体令牌，按**组**核对 TI SID（供体是 LocalSystem 起的，TI 在组里、不在 `TokenUser` 里；按 `TokenUser` 核对会把成功判成失败），然后把供体停掉 —— 停不了也不要紧，供体自带 60 秒寿命。

还原是幂等的，而且只在"当前值确实是我们写的"（命令行里带 `--syndonor`）时才覆盖回去，不会把系统修复过的值改坏。三层兜底，本机都实测过：

| 层 | 干什么 | 实测 |
| --- | --- | --- |
| 1 | 服务一到 `RUNNING` 就地立刻还原 | 跑完 `ImagePath` 逐字节复原，备份值也删掉了 |
| 2 | SYSTEM 守护进程：父进程没了就替它收尾 | 在窗口里强杀父进程，键在 **134 ms** 内被修回去 |
| 3 | 每次启动读一次备份，脏了就地借 SYSTEM 身份修 | 手工造出残留后另起一次运行，键被复原、备份键从 HKLM 消失 |

注意第 3 层也**必须借 SYSTEM**：`Administrators` 对 `HKLM\SYSTEM\CurrentControlSet\Services\TrustedInstaller` 只有 `ReadKey`，普通管理员根本写不回去 —— 所以"启动自检"不是读一下就走，而是真的去取一次 SYSTEM 令牌。`--diagnose` 会把这个状态画出来（`clean` / `STALE`），而且它只读不改。

> **"都提到 TrustedInstaller 了，为什么还是 SYSTEM？"**
>
> 因为 TI 身份本来就长这样：`TokenUser` 是 `NT AUTHORITY\SYSTEM`，`NT SERVICE\TrustedInstaller` 在**组**里。真正的 `TrustedInstaller.exe` 服务进程用的就是同一副令牌 —— 它的 `ServiceSidType = 1` 会让 SCM 把服务 SID 加进这个 LocalSystem 令牌的组。
>
> 访问检查认的是**组 SID**，所以能力是实打实的 TI（`C:\Windows\servicing\Packages` 这类只有 TI 能写的地方，实测在落地后由 denied 变成 ALLOWED）；但只看 `TokenUser` 的地方 —— `whoami`、任务管理器、进程资源管理器的"用户"列 —— 永远会显示 SYSTEM，那是 `TokenUser`，不是访问身份。
>
> `--diagnose` 的 `effective token` 一栏把两者分开写：`identity` 是真正的访问身份（`TrustedInstaller` / `SYSTEM` / `admin`），`logon` 是令牌的 `TokenUser`。引擎头部那个徽章也改成打 `NT SERVICE\TrustedInstaller` 而不是 `TokenUser`，免得看起来像提权没生效。

默认**开**（`TI_HIJACK_SAFE`）：TI 是这套工具的默认档位，而 Windows 11 客户端上只有劫持能拿到 TI，所以它不能是可选件。但它默认**不去打断一个正在跑的 `TrustedInstaller`** —— 它跑起来基本就是在装更新，硬停会把维护打断；那种情况下直接往 SYSTEM 回退。三种强度：

| 取值 | 参数 | 行为 |
| --- | --- | --- |
| `TI_HIJACK_SAFE` | 默认 | 只在 TI **本来就没在跑**时才劫持；已经在跑就跳过并回退 |
| `TI_HIJACK_FORCE` | `--ti-hijack` | 连正在跑的也停掉再劫持（停不掉就放弃并回退）。用完**不会**替你把它重新拉起来 —— 它是按需启动的，Windows 需要时会自己起来 |
| `TI_HIJACK_OFF` | `--no-ti-hijack` | 完全不动 TI 服务，`--as=auto` 就落在 SYSTEM |

判据取的是**我们动手之前**的服务状态：方法一为了拿令牌会自己把 TI 拉起来，若拿"当前状态"当判据，默认配置会把自己刚启动的服务误判成"系统正在维护"，于是永远跳过劫持、永远落不到 TI。

`--keep-ti` 与劫持语义冲突（前者要"别停我拉起来的 TI 服务"，后者必须先停服务，而且劫持完绝不能把供体留在系统里——那就是一个 TI 身份的后门），所以 `--keep-ti` 会让劫持**跳过**并往 SYSTEM 回退，而不是直接报错。

拿到令牌后默认**就地把当前线程切到那个身份**（`DuplicateTokenEx` → `SetThreadToken`），全程一个进程，界面、退出码、重试循环都不受影响：

- 落地前先把令牌里**已经存在的**特权逐个打开，否则拿到的令牌往往连 `SeDebugPrivilege` 都是关闭的。
  > 这里修了一个一直在骗人的写法：老代码给 `AdjustTokenPrivileges` 传一个 `Luid = 0` 的单项，注释说"这是'全部特权'的约定"。**那个约定并不存在** —— 实际效果是什么都没打开，实测拿到的 SYSTEM 令牌里 `SeAssignPrimaryTokenPrivilege` 一直是 off，于是 `CreateProcessAsUser` 必然 `ERROR_PRIVILEGE_NOT_HELD`，TI 劫持的"守护进程"兜底其实从来没起来过（它现在起来了，上面第 2 层的 134 ms 就是证据）。现在改成老老实实枚举 `TokenPrivileges` 逐个开。
- 切换后立刻回读线程令牌，SID 对不上就 `RevertToSelf()` 并继续向下回退——**只有真正到位才算这一档成功**。
- 如果这一档是我们自己启动的 `TrustedInstaller` 服务，用完即 `SERVICE_CONTROL_STOP` 停掉，不把系统留在被改过的状态（`--keep-ti` 可关掉这个行为）。
- `--spawn` 则改用 `CreateProcessWithTokenW`（失败再退到 `CreateProcessAsUserW`）以该令牌**重新拉起自身**：子进程先以 `CREATE_SUSPENDED` 创建，父进程核验它的令牌身份无误、画完提权链再 `ResumeThread`，子进程跑完把退出码传回父进程。

### admin 档为什么要单独说

`admin` 档在**已经提升**的进程里就地进行；只有进程没提升时才会走 UAC 自提权。而 UAC 拉起来的进程**总是带自己的控制台**，它报告留在那个窗口里——所以父进程不会把子进程的输出当成自己的：

- 先把提权链面板画完（`UIClearToEnd` 会 `fflush`，画面不会堵在缓冲区里），**再**去 `WaitForSingleObject`；
- 子进程结束后补一张摘要（档位、pid、退出码），并在自己的控制台里倒计时停留，不会一闪而过；
- 退出码原样透传。

看不到输出通常不是“提权失败”，而是这个窗口切换的锅：`fuckAce.exe --diagnose` 只读查询当前进程/有效身份的令牌信息（elevation、完整性、会话）和 TI 残留备份；它不尝试任何提权档、不启动服务、不修改注册表或进程。

SSDT 之外的影响：`SeImpersonatePrivilege`、`SeAssignPrimaryTokenPrivilege`、`SeIncreaseQuotaPrivilege`、`SeDebugPrivilege` 等特权会在提权前逐个启用，失败不致命，只记录首个错误码并在界面上提示。

`--no-elevate` 可以整条链关掉，退回原来的“直接以当前权限跑”。链上每一档的成功/失败、来源进程 PID 和错误码都会画在界面上；全部失败时不会静默降级——引擎头部会打出 `token none` 并附 `! escalation chain exhausted`。

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
fuckAce.exe [--rate=PERCENT] [--no-cap] [--nest] [--as=TIER] [--no-elevate] [--no-fallback] [--impersonate|--spawn] [--keep-ti] [--no-ti-forge] [--no-ti-hijack] [process.exe ...]
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
| `--no-ti-forge` | 关掉"在 SYSTEM 底座上 `NtCreateToken` 造 TI 令牌"这条路（默认开） |
| `--ti-hijack` | **强制**：连正在跑的 `TrustedInstaller` 也停掉再换 `ImagePath`（默认只在它本来就没在跑时才动它） |
| `--no-ti-hijack` | 关掉镜像劫持；`--as=auto` 就退回 SYSTEM 保底。详见上文 |
| `--diagnose` | 只读打印当前进程/有效身份与 TI 残留备份，不尝试提权档、不启动服务、不修改注册表或进程；当前身份没有可用档位时退出码 `1` |
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
- 提权链只影响**本进程的有效身份**，不装服务、不留后门：SYSTEM 那一档的临时供体服务用完即 `DeleteService`；`TrustedInstaller` 服务是 Windows 自带的组件，只有在我们把它拉起来时才会去停；`--spawn` 模式下父进程会等子进程跑完并把退出码原样传回。唯一的例外是 TI 档的镜像劫持（**默认开**）：它会把 TI 服务的 `ImagePath` 临时改成自己并在几百毫秒内还原，配套 HKLM 备份、SYSTEM 守护进程、启动自检三层兜底（见上文）。不想让它碰注册表就加 `--no-ti-hijack`，代价是 TI 拿不到、落回 SYSTEM。
- 引擎对“够权限”的判定看的是**实际身份**（admin / SYSTEM / TrustedInstaller 任一档）而不是单纯的管理员组：TrustedInstaller 令牌里的 `Administrators` 是 deny-only，只用 `CheckTokenMembership` 判定会把已提权的进程误判成无权限。
- 新建的 Job 使用 `本地会话名称 + PID + 进程创建时间` 标识。目标原本不在任何 Job 中时，自动重试或再次运行会复用并更新同一个 Job，不会重复限流；关闭本程序句柄后上限仍保留。但目标已在其它 Job 中（即 `--nest` 生效）时，嵌套出来的 Job 在句柄关闭后**名称不再可查**，再次运行/重试会再嵌套一层；嵌套的 `CpuRate` 是相对父 Job 的比例，会**逐层叠加**（两层 3% 实际约为 0.09%）。因此 `--nest` 建议每次会话只运行一次，确认 ACE 已被压住后不必重复运行。`--no-cap` 只跳过本次设置，不撤销已有上限。
- ACE 会自我防护，若进程以保护模式运行，部分或全部操作可能返回 `access denied`，此时程序按退出码 `2` / `3` 提示。
- 扫描与设置之间若 PID 被回收，程序会在打开后比对进程名并跳过该条目（汇总处显示 skipped 数）。
- 仅在本地运行，不联网、不修改任何文件。
