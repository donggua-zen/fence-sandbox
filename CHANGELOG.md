# Changelog

本文件记录 AI Sandbox 的显著变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Changed
- CI: Windows 平台跳过测试步骤，仅验证构建——默认 shell 为 powershell（`4c12a93`）时，受限令牌启动的 `powershell.exe` 在 GitHub runner 上无限阻塞导致 ctest 挂起；测试保留在 Linux/macOS CI 与本地 Windows 运行，所有 job 增加 15 分钟超时保护

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
- Windows: restricting SID 去掉 Everyone/logon SID，仅保留随机 workspace SID；`--read-only` 模式下该 SID 不授予任何 ACE，修复无 ACL 卷（FAT/exFAT）上写保护与只读模式失效
- Windows: `removeWorkspaceWriteAcl` 按 `sizeof(ACCESS_ALLOWED_ACE)` 估算重建 DACL 缓冲（真实 ACE 更大，必然不足）且 `AddAce` 失败不检查，残缺 DACL 被写回目录——改为按实际 `AceSize` 累加，构建失败不写回；ACL/lock 建立失败时中止运行（fail-closed）
- Windows: 工作目录经 `GetFullPathNameW` 规范化后统一使用；子进程改为挂起创建、挂入 Job Object 后再恢复（消除孙进程逃逸窗口）；删除每次运行向 stderr 打印的 SandboxSpec 调试转储
- CI: 恢复 Windows cmd-only 测试（`SANDBOX_TEST_SKIP_DEFAULT_SHELL` 跳过默认 powershell 用例），Restricted Token 后端重新获得回归保护

### Known issues
- Windows: `WRITE_RESTRICTED` 令牌的 restricting SID 检查只覆盖 `GENERIC_WRITE` 映射的访问，不含 `DELETE`——**工作目录外文件的删除在 Restricted Token 后端上目前不会被拦截**。本次接入 CI 的安全用例首次暴露此问题，属存量模型缺口（修改前 Everyone/logon 在 restricting 集合时同样可删），与本次修复无关。CI 暂以 `SANDBOX_TEST_SKIP_DELETE_OUTSIDE` 跳过该用例；可行的修复方向：ACL 显式授权（授予"仅 workspace SID 可删"并依赖继承，参见 OpenAI Codex Windows 沙盒的做法）或以默认拒绝的 AppContainer 后端为主（Win11 24H2+）
- Windows: ACL 未授予 DELETE 权限，导致工作目录内无法删除文件（`GENERIC_WRITE` 不包含 `DELETE`）
- Linux: 子进程未 `chdir()` 到工作目录，导致相对路径命令在工作目录外执行（Windows 通过 `CreateProcessAsUserW` 的 `lpCurrentDirectory` 正确设置，Linux 缺失）

## [1.0.0] - 2025-07-31

### Added
- Windows: Restricted Token + ACL 沙盒实现
- Linux: Landlock LSM 沙盒实现
- 跨平台 CMake 构建系统
- Node.js 集成示例
- Docker 编译环境支持
- 心跳与僵尸 ACE 清理机制
