# 贡献指南

感谢你对 AI Sandbox 的关注！欢迎提交 Issue 和 Pull Request。

## 开发环境

### Windows

- Visual Studio 2019+ (含 C++ 桌面开发工作负载)
- CMake 3.20+

```bat
build_project.bat
```

### Linux

- GCC 12+ 或 Clang 15+
- CMake 3.20+
- 内核 ≥ 5.13 (Landlock)

```bash
./build_project.sh
```

## 代码风格

- C++17 标准
- 命名：`camelCase` 函数/变量，`PascalCase` 类/结构体
- 缩进：4 空格
- 头文件保护使用 `#pragma once`
- 每个源文件顶部必须有 SPDX 许可声明

## 提交规范

- Commit message 使用英文，格式：`<type>: <description>`
- type: `feat` / `fix` / `docs` / `refactor` / `test` / `ci` / `chore`
- 示例：`feat: add macOS sandbox-exec support`

## 测试

提交前请确保：

1. 构建通过（Windows 或 Linux）
2. 集成测试全部通过：

```bash
cd build && ctest --output-on-failure
```

## 安全相关贡献

本项目是安全工具，安全相关的修改需特别注意：

- 不得引入静默降级逻辑（沙盒不可用时必须报错退出）
- ACL 清理路径必须有对应的清理测试
- 新增的权限限制不得影响读操作（工作目录外只读是核心需求）

## 许可

提交的代码将遵循 [Apache-2.0](LICENSE) 许可协议。
