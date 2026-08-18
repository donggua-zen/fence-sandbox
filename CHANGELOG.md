# Changelog

本文件记录 AI Sandbox 的显著变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

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
