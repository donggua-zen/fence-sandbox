# Changelog

本文件记录 AI Sandbox 的显著变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Changed
- Windows（Restricted Token 后端）：工作区 ACE 从「每次调用随机 SID + 授权 + 回收」改为**按工作区确定性派生 + 常驻授权 + 命中即跳过**。原先每次命令都要付**两遍** eager 全树传播（`SetNamedSecurityInfoW` 会立即遍历每个后代，实测大工作区上授权 ≈233 s、回收 ≈292 s，合计 ~525 s/条），现在只在**每台机器每个工作区**付一次，之后每条命令的 ACL 成本降到一次 DACL 读取
  - 新增 `deriveWorkspaceSid()`：`sha256("ai-sandbox-workspace\0" + 规范化工作区路径)` → `S-1-4-x-y`。路径先经 `GetFinalPathNameByHandleW` 规范化，保证同一目录的不同拼写收敛到同一身份；域名前缀保证与其它产品（如 deepseek-harness 的 windows-acl 沙盒）派生的能力 SID 不冲突
  - 工作区 ACE 改为**常驻**（`cleanupWorkspaceGrants` 不再回收）——它就是跨调用复用缓存；回收会迫使下一次调用重新传播整棵树
  - `ensureWorkspaceWriteAcl` 新增**快路径**：读到的 DACL 已含精确 ACE 且无僵尸 ACE 时，**完全跳过 `SetNamedSecurityInfoW`**
  - `isSandboxSid()` 语义收敛为「旧随机命名空间（`S-1-5-10-*`）」，新增 `isWorkspaceCapabilitySid()`（`S-1-4-x-y`）；僵尸清理显式**永不回收**工作区能力 SID（否则等于删掉缓存）
  - 新增 `AclPathLock`：以 `LockFileEx` 对 `<workspace>\.sandbox\acl.lock` 加**跨进程**独占锁，把 DACL 的读-改-写整段串行化。既修掉并发丢更新，也让 N 条并发首命令只做**一次**传播（其余在锁上等待后命中快路径），而不是各做一次

### Fixed
- Windows（Restricted Token 后端，**安全**）：`--read-only` 的 restricting SID 列表不再包含工作区能力 SID。该 SID 的 ACE 是常驻的，若仍留在只读列表里，**上一次 workspace-write 留下的授权会满足受限写检查、把只读重新打开**。改为只读列表 = `[logon SID, Everyone]`（与 deepseek-harness 同构）。随机的每次调用 SID 原本在只读模式下天然惰性（它从来没有 ACE），确定性 SID 不是——这是本次改动引入的、必须同时修掉的陷阱，已加回归测试
- Windows（AppContainer 后端）：`Experimental_CreateProcessInSandbox` 失败时**不再静默回退**，改为打印 `[diagnostic] ... falling back to the restricted-token backend`。静默回退会把「没有读隔离」的弱后端藏在成功退出码后面
- Windows（AppContainer 后端）：调用引擎前 `SetLastError(ERROR_SUCCESS)`，否则 `CreateAppContainerProfile` 遗留的错误码会被误读成引擎自身的失败码
- Windows（AppContainer 后端）：`CreateAppContainerProfile` 返回 `ERROR_ALREADY_EXISTS` 时按**失败**处理（原为按成功）。实测引擎对「曾经注册过」的 identity 一律拒绝启动，接受它只会浪费一次注定失败的引擎调用

### Added
- `sandbox/tests/test_standing_grant_windows.bat` + CTest 用例 `standing_grant_tests`（10 项）：钉住两个后端各自的授权生命周期——Restricted Token 的能力 ACE **常驻且跨运行 SID 稳定**；AppContainer 的每次运行 ACE **被回收、不累积**；以及两者共有的安全用例「同一工作区先 workspace-write 再 `--read-only` 必须仍然拒绝写入」
- 环境变量 `SANDBOX_ACL_DIAG=1`：在 stderr 打印每次 `ensureWorkspaceWriteAcl` 的判定（`sid=` / `exact=` / `keep=N/M`），用于定位「为什么这次没有命中快路径」
- 环境变量 `SANDBOX_FORCE_APPCONTAINER=1`：显式启用已退役的 AppContainer 后端（仅供实验/回归）

### Retired
- Windows：**AppContainer 后端（`Experimental_CreateProcessInSandbox` / mxc BaseContainer 层）退出默认选择路径**。代码保留（`runWithSandboxApi` 等完整可用，`SANDBOX_FORCE_APPCONTAINER=1` 可启用），但默认一律走 Restricted Token 后端
  - 原因是**结构性不兼容**而非性能调参：引擎对「曾经注册过」的 identity 一律返回 `ERROR_ALREADY_EXISTS`（在 profile 已被 `DeleteAppContainerProfile` 删除后实测仍然如此），因此 profile 名必须每次运行全新 → 派生 SID 每次运行变化 → 工作区 ACE 无法常驻 → **每次调用都要付两遍 eager 全树传播**，正是确定性工作区 SID 要消除的那笔成本
  - 即：该 API 的 identity 语义是「一次性、唯一命名的容器实例」，不是「可复用的账户引用」。对「同一工作区反复执行大量短命令」的 agent 场景属于用法错配
  - 其唯一剩余优势是**读侧默认拒绝**，而本产品的语义明确只承诺写隔离（「读取不受影响」），且要拿到读侧隔离同样需要对每个待读路径改 host DACL——即同一笔批发式 DACL 变更成本
  - `SANDBOX_FORCE_RESTRICTED_TOKEN=1` 语义不变（「不要尝试 AppContainer」），两者同时设置时它优先
  - 若未来引擎版本接受复用 identity，把该分支恢复为默认即可（代码路径未删）

## [1.2.0] - 2026-09-18

### Changed
- CI: Windows 平台跳过测试步骤，仅验证构建——默认 shell 为 powershell（`4c12a93`）时，受限令牌启动的 `powershell.exe` 在 GitHub runner 上无限阻塞导致 ctest 挂起；测试保留在 Linux/macOS CI 与本地 Windows 运行，所有 job 增加 15 分钟超时保护
- Windows: 工作目录 ACE 从 `GENERIC_WRITE | GENERIC_EXECUTE | DELETE` 改为显式掩码（`FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE | FILE_DELETE_CHILD`，剔除 `WRITE_DAC | WRITE_OWNER`，保留 `READ_CONTROL` 使 generic 请求可映射）——子进程不再能通过 `icacls`/夺权重写工作区内 DACL；`FILE_DELETE_CHILD` 保证子项删除与重命名不受子项自身 DACL 影响（授权形状对齐 deepseek-harness 的 windows-acl 沙盒）
- Windows: `CreateRestrictedToken` 曾随 `eb7788e` 加入 `LUA_TOKEN`，现**移除**——`WRITE_RESTRICTED` 令牌的写操作要求**正常检查与受限检查同时通过**，而 `LUA_TOKEN` 会把调用者的管理员 SID 标记为 deny-only：在提权调用者（如 GitHub runner）且文件 ACL 仅授予 `Administrators:(F)`+`Users:(RX)` 的环境下，**沙盒运行前就存在的文件**的删除/覆盖会因正常检查失败而被拒（即便受限检查因工作区 SID 的 ACE 而通过），沙盒内新建文件不受影响。移除后提权能力仍受 `DISABLE_MAX_PRIVILEGE` 约束，写隔离由受限检查强制

### Added
- Windows: 环境变量 `SANDBOX_FORCE_RESTRICTED_TOKEN=1` 强制走 Restricted Token 回退后端，便于在 24H2+ 机器上对回退后端做回归测试
- Windows 集成测试扩充至 12 项（`sandbox/tests/test_windows.bat`）：新增「默认 shell 确为 PowerShell」断言（PS-only 语法通过 + cmd-only 对照拒绝），以及 Restricted Token 后端下默认 shell / `--shell cmd` 的写入内、写入外用例——24H2+ 上 Sandbox API 后端优先，回退后端此前缺乏覆盖

### Added
- Apache-2.0 开源协议
- CI 自动化：GitHub Actions 三平台（Windows/Linux/macOS）构建+测试+打包，打 `v*` tag 自动发布 Release 附件
- 本地打包脚本 `package.sh`（按当前平台生成与 CI 一致的压缩包）
- macOS: Seatbelt (sandbox-exec) 沙盒实现（工作目录内读写、目录外只读、多工作目录与 `--read-only`，支持 `sh`/`bash`/`zsh`，含 `realpath` 规范化与 SBPL 路径转义）
- 集成测试（跨平台）：工作目录内写入、目录外写入拒绝、只读模式、退出码透传
- 安全测试套件（16 项用例）：写入/删除/创建目录/移动/读取/多工作区/退出码透传
- GitHub Actions CI（Windows + Linux）
- .gitignore
- CONTRIBUTING.md 贡献指南
- DESIGN.md 设计文档
- 源文件 SPDX 版权声明
- 源文件 Doxygen 风格英文注释
- build_project.bat 自动探测 Visual Studio 路径

### Fixed
- Windows: **AppContainer 后端首次真正生效**。identity 原本固定为 `AISandbox.Container.v1`，而引擎把该参数当作 AppContainer profile 名并自行创建/打开——profile 已存在即返回 FALSE + `GetLastError=183`（ERROR_ALREADY_EXISTS），于是除首次外每次运行都静默回退到 Restricted Token。改为**每次运行生成唯一 identity**（`AISandbox-<pid>-<16 位随机十六进制>`），用后 `DeleteAppContainerProfile` 清理（含全部失败路径）。实测 16/16 用例全部由 AppContainer 承接，无回退
- Windows: `buildSandboxSpec` 现在同时下发 `fs_read_write` 与 `fs_read_only`（此前二选一、共用同一 table 槽位）。AppContainer 对**读**同样是默认拒绝，只声明工作区会让子进程失去目录外读取能力，与"工作目录外只读"的产品语义冲突。现把各本地盘根（`GetLogicalDriveStringsW` 取 `DRIVE_FIXED|DRIVE_REMOVABLE|DRIVE_CDROM`）作为只读根一并声明，网络盘刻意排除以免不可达 UNC 拖住进程创建。附带修好了默认 shell：`C:\` 不可读时 PowerShell 的 FileSystem provider 初始化失败、相对路径被解析成 `C:\`，补上只读根后相对路径恢复正常。实测（build 26200）PS 绝对/相对写内、目录外写删拒绝、目录外读放行、只读模式写拒读放、退出码透传、多工作区全通过
- Linux: Landlock `WRITE_ACCESS_MASK` 未 handle `REMOVE_DIR`，工作目录外空目录可被 `rmdir` 删除（所有 Linux 构建受影响）；补上该权限位并新增 rmdir 回归用例
- Linux: 无 `<linux/landlock.h>` 时的 fallback 常量与内核 UAPI 位值错位（REMOVE_FILE 从 bit2 起），按官方位序修正（v5.13/v6.2/master 三处核对一致）；`packed` 与内核 UAPI 相同属正确写法，保留；ABI < 3 内核增加 truncate 缺口警告
- Windows: AppContainer 后端用 `-1` 兼作"回落"哨兵与子进程退出码，退出码 ≥ 0x80000000 的命令（如 `exit -1`）会被 Restricted Token 后端重复执行——退出码改由出参传递
- Windows: restricting SID 列表改为 `{随机 workspace SID, logon SID, Everyone}`。`ee5c242` 曾将其收窄为仅 workspace SID，导致受限令牌下**进程初始化失败**：`powershell.exe` 以 `0xC0000142`（STATUS_DLL_INIT_FAILED）退出、`where.exe` 一类工具静默无法运行（`cmd.exe` 不受影响）；`4c12a93` 将默认 shell 改为 powershell 后该回归在默认路径上必现。A/B 构建实测（Win11 build 26200，同源码仅改 restricting 列表与 token 标志）：仅 workspace → `0xC0000142`；workspace+Everyone → `0xC0000142`；workspace+logon → `0xFFFF0000`；三者齐备 → 正常。**logon SID 与 Everyone 缺一不可，与 `LUA_TOKEN` 无关**。工作区写隔离仍由随机 workspace SID 的 ACE 强制，不受影响；SID 获取失败时打印显式告警而非静默降级
- Windows: `removeWorkspaceWriteAcl` 按 `sizeof(ACCESS_ALLOWED_ACE)` 估算重建 DACL 缓冲（真实 ACE 更大，必然不足）且 `AddAce` 失败不检查，残缺 DACL 被写回目录——改为按实际 `AceSize` 累加，构建失败不写回；ACL/lock 建立失败时中止运行（fail-closed）
- Windows: 工作目录经 `GetFullPathNameW` 规范化后统一使用；子进程改为挂起创建、挂入 Job Object 后再恢复（消除孙进程逃逸窗口）；删除每次运行向 stderr 打印的 SandboxSpec 调试转储
- CI: 恢复 Windows cmd-only 测试（`SANDBOX_TEST_SKIP_DEFAULT_SHELL` 跳过默认 powershell 用例），Restricted Token 后端重新获得回归保护

### Known issues
- Windows: Restricted Token 回退后端能否拦截**工作目录外的删除**取决于内核对 `WRITE_RESTRICTED` 的实现。2026-09 在 Win11 25H2（build 26200）实测：内核的 restricted 检查已覆盖 `DELETE`（绕过 cmd 直接调 `DeleteFileW` 的探针亦被拒），回退后端可正常拦截工作目录外删除；在更旧的 Windows 构建上该检查可能不覆盖 `DELETE`，缺口仍会存在。CI 暂以 `SANDBOX_TEST_SKIP_DELETE_OUTSIDE` 跳过该用例，待多 Windows 版本矩阵验证后再决定是否移除。彻底的机制级修复（默认拒绝）需以 AppContainer 后端为主（Win11 24H2+）；在不牺牲"工作目录外可读"的前提下，纯 Restricted Token 机制无法强制拦截（全 RESTRICTED 令牌会同时拦截读取，破坏产品语义）
- Linux: 子进程未 `chdir()` 到工作目录，导致相对路径命令在工作目录外执行（Windows 通过 `CreateProcessAsUserW` 的 `lpCurrentDirectory` 正确设置，Linux 缺失）
- Windows: **Restricted Token 回退后端**的 restricting SID 含 `Everyone`，因此在无 ACL 的卷（FAT/exFAT/网络共享，Everyone 被隐式授予）上，工作目录外的写入/删除不会被拦截——这是"受限令牌下进程可正常启动"与"无 ACL 卷可拦截"之间的取舍。24H2+ 上默认走 AppContainer（默认拒绝，无此问题）。`Everyone` **有意保留**（连同 logon SID）：旧设备/旧 Windows 构建上回退后端仍是主路径，移除会导致进程无法初始化（见上文 Fixed 条目）
- Windows: AppContainer 后端下，PowerShell 启动时仍会向 stderr 打印 `尝试对 FileSystem 提供程序执行 InitializeDefaultDrives 操作失败`。这是 PS 在受限容器内的既有噪音，**不影响行为**（当前目录正确、相对路径正常、读写均正常），暂不处理
- Windows: 每次运行都会创建并删除一个 AppContainer profile；若 launcher 被强杀，profile 会残留（名字含 pid，无毒但会累积）。暂未做陈旧 profile 清理

## [1.0.0] - 2025-07-31

### Added
- Windows: Restricted Token + ACL 沙盒实现
- Linux: Landlock LSM 沙盒实现
- 跨平台 CMake 构建系统
- Node.js 集成示例
- Docker 编译环境支持
- 心跳与僵尸 ACE 清理机制
