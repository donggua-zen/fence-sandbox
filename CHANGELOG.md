# Changelog

本文件记录 AI Sandbox 的显著变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Changed
- CI: Windows 平台跳过测试步骤，仅验证构建——默认 shell 为 powershell（`4c12a93`）时，受限令牌启动的 `powershell.exe` 在 GitHub runner 上无限阻塞导致 ctest 挂起；测试保留在 Linux/macOS CI 与本地 Windows 运行，所有 job 增加 15 分钟超时保护
- Windows: 工作目录 ACE 从 `GENERIC_WRITE | GENERIC_EXECUTE | DELETE` 改为显式掩码（`FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE | FILE_DELETE_CHILD`，剔除 `WRITE_DAC | WRITE_OWNER`，保留 `READ_CONTROL` 使 generic 请求可映射）——子进程不再能通过 `icacls`/夺权重写工作区内 DACL；`FILE_DELETE_CHILD` 保证子项删除与重命名不受子项自身 DACL 影响（授权形状对齐 deepseek-harness 的 windows-acl 沙盒）
- Windows: `CreateRestrictedToken` 增加 `LUA_TOKEN`，提权调用者派生出的也是过滤令牌，子进程不会继承管理员能力

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
- Windows: restricting SID 含 `Everyone`，因此在**无 ACL 的卷**（FAT/exFAT/网络共享，Everyone 被隐式授予）上，工作目录外的写入/删除不会被拦截——这是"受限令牌下进程可正常启动"与"无 ACL 卷可拦截"之间的取舍。彻底解法是以默认拒绝的 AppContainer 后端为主（见下条），或对非 NTFS 卷检测后拒绝运行
- Windows: 已知问题——AppContainer 主后端在本机未生效。Win11 25H2（build 26200）实测 `Experimental_CreateProcessInSandbox` 返回 FALSE 且 `GetLastError=183`（ERROR_ALREADY_EXISTS），每次调用都静默回退到 Restricted Token 后端；本机 `processmodel.dll` 存在且导出可用，故非系统版本问题。当前 Windows 侧全部隔离语义实际由回退后端承担，AppContainer 的默认拒绝能力（含无 ACL 卷与工作目录外删除）尚未兑现，已列为后续修复项

## [1.0.0] - 2025-07-31

### Added
- Windows: Restricted Token + ACL 沙盒实现
- Linux: Landlock LSM 沙盒实现
- 跨平台 CMake 构建系统
- Node.js 集成示例
- Docker 编译环境支持
- 心跳与僵尸 ACE 清理机制
