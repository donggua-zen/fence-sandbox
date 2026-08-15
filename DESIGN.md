# 设计文档

## 目标

防止 AI 在执行命令时因幻觉写入/删除工作目录外的文件。

- 安全目标：工作目录内全读写，其他目录只读（不防黑客，只防 AI 幻觉）
- 技术路线：OS 原生沙盒机制，零注入、零钩子

## 平台方案

| 平台 | 沙盒机制 | 核心思路 |
|------|---------|---------|
| Windows | Restricted Token + ACL | 生成随机 SID，仅授予该 SID 对工作目录的写权限，用受限令牌启动子进程 |
| Linux | Landlock LSM | 创建 Landlock ruleset 限制写操作，为工作目录添加"允许写入"规则 |
| macOS | sandbox-exec (Seatbelt) | 待实现 |

## Windows: Restricted Token + ACL

### 流程

1. **生成随机 SID**：每次执行通过 `CryptGenRandom` 生成 `S-1-5-10-{rand}-{rand}-{rand}-{rand}` 格式的唯一标识
2. **授予写权限**：将该 SID 的 `GENERIC_WRITE | GENERIC_EXECUTE` ACE 添加到工作目录的 DACL
3. **创建 Restricted Token**：用 `CreateRestrictedToken` + `WRITE_RESTRICTED` 限制令牌，添加 `Everyone` SID 作为 restricting SID，使子进程仅能写该 SID 有权访问的目录
4. **启动子进程**：用 `CreateProcessAsUserW` 以受限令牌执行 `cmd.exe /c <命令>`
5. **清理**：执行完毕后删除 ACE 和 lock 文件

### 心跳与僵尸清理

- 后台线程每 10 分钟更新 lock 文件时间戳
- 每次启动时自动清理超过 30 分钟未更新的残留 ACE

### 为什么不用低完整性（Low Integrity）？

低完整性级别会阻止大多数读取操作，不符合"工作目录外只读"的需求。Restricted Token + WRITE_RESTRICTED 只限制写操作，读操作不受影响。

## Linux: Landlock LSM

### 流程

1. **查询 ABI 版本**：通过 `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` 获取内核 Landlock ABI 版本
2. **构建写权限掩码**：根据 ABI 版本选择支持的访问标志（v1 基线、v2 REFER、v3 TRUNCATE）
3. **创建 ruleset**：通过 `landlock_create_ruleset` 创建限制所有写操作的规则集
4. **添加允许写入规则**：为每个工作目录添加"允许写入"规则（read-only 模式跳过）
5. **Fork + 限制自身**：子进程执行 `prctl(PR_SET_NO_NEW_PRIVS)` + `landlock_restrict_self()`，然后 `execl("sh", "sh", "-c", ...)`

### 内核级强制

- 限制由内核裁决，无法绕过
- 进程异常退出时限制自动失效，无残留
- `PR_SET_PDEATHSIG` 确保父进程退出时子进程也被终止

### 安全失败

如果运行环境不支持 Landlock（内核 < 5.13 或 Docker seccomp 拦截了 landlock syscall），sandbox 会输出明确的错误信息并退出，**不会静默降级为无保护运行**。

## 透明性保证

- **stdin/stdout/stderr 直通**：无缓存，子进程的输入输出直接传递
- **退出码透传**：子进程无论正常退出还是异常崩溃，都以相同退出码退出
- **错误信息透传**：无权限写入时由系统返回错误码，不额外打印
- **环境变量继承**：子进程自动继承父进程环境变量

## 行为规则

| 操作 | 工作目录内 | 工作目录外 |
|------|----------|----------|
| 读取 | ✅ | ✅ |
| 写入 | ✅ | ❌ 被拒绝 |
| 删除 | ✅ | ❌ 被拒绝 |
| 创建 | ✅ | ❌ 被拒绝 |
| `--read-only` 模式写入 | ❌ 被拒绝 | ❌ 被拒绝 |

写入被拒绝时，子进程收到操作系统返回的 `ACCESS_DENIED`（Windows）或 `EACCES`（Linux），行为与权限不足时完全一致。

## 演进历史

### v1: Detours Hook 方案（已弃用）

最初设计使用 Microsoft Detours 进行用户态 API Hook，钩住 `CreateFileW`、`DeleteFileW`、`MoveFileW`、`RemoveDirectoryW` 等 5 个 Win32 API。该方案存在以下问题：

- DLL 注入容易被杀软（360、火绒）误杀
- 用户态 Hook 可被绕过（直接调用 Nt* 系统调用）
- 仅 Windows，无法跨平台

### v2: OS 原生沙盒（当前实现）

改用 OS 原生沙盒机制，优势：

- 零注入、零钩子，杀软无感
- 内核级强制，无法绕过
- 跨平台（Windows + Linux）
