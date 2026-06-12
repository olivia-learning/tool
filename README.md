# AI SSH MCP

这是一个本地 MCP 工具服务，用来让其他 agent 以受控方式连接一台 Linux/BusyBox 嵌入式设备：先生成诊断计划，经过用户在聊天里确认后，再通过 SSH 登录、`su -` 提权并执行只读诊断命令。

第一版只做诊断查询，不做配置修改、升级、重启、删除文件等高风险操作。

## 功能

- `configure_device`：保存单台设备的 host、port、username，并把 SSH 密码和 su 密码存入本机 keyring。
- `test_connection`：验证 SSH 登录、`su -` 提权和命令执行。
- `plan_diagnostic_task`：根据自然语言任务生成只读诊断命令计划。
- `run_approved_plan`：执行已经生成且用户确认的计划。
- `list_whitelist_commands`：查询当前可用的内置/自定义白名单命令。
- `add_whitelist_commands`：新增一批自定义只读白名单命令。
- `delete_whitelist_commands`：删除自定义白名单命令，或禁用内置白名单命令。
- `download_device_files`：通过 SFTP over SSH 将设备文件下载到本机指定目录。
- `run_interactive_tool`：进入指定目录启动交互式后台工具，输入指令并读取提示符前的多行结果。
- `run_shell_commands`：顺序执行用户确认的普通 shell 命令，并返回每条命令的退出码和输出。
- `list_recent_runs`：查看最近执行记录。
- `get_run_detail`：查看某次诊断的完整详情。

## 安装

```powershell
cd C:\Users\olivi\Documents\Create_tool
py -m venv .venv
.\.venv\Scripts\python -m pip install -U pip
.\.venv\Scripts\python -m pip install -e .
```

如果你的系统没有 `py`，用 Python 的完整路径执行同样命令即可。

## 运行 MCP 服务

```powershell
.\.venv\Scripts\python -m ai_ssh_mcp
```

在支持 MCP 的客户端里可以配置类似：

```json
{
  "mcpServers": {
    "ai-ssh-device": {
      "command": "C:\\Users\\olivi\\Documents\\Create_tool\\.venv\\Scripts\\python.exe",
      "args": ["-m", "ai_ssh_mcp"],
      "cwd": "C:\\Users\\olivi\\Documents\\Create_tool"
    }
  }
}
```

## 在 opencode 中使用

opencode 使用 `opencode.json` 配置 MCP。推荐把这个 MCP 配成全局工具，这样任何 opencode 会话都能调用。

全局配置文件通常在：

```text
C:\Users\olivi\.config\opencode\opencode.json
```

如果文件不存在，就新建它。如果已经存在，只合并下面的 `mcp` 部分，不要覆盖你原来的 provider、model 或其他配置。

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "ai_ssh_device": {
      "type": "local",
      "command": [
        "C:\\Users\\olivi\\Documents\\Create_tool\\.venv\\Scripts\\python.exe",
        "-m",
        "ai_ssh_mcp"
      ],
      "cwd": "C:\\Users\\olivi\\Documents\\Create_tool",
      "enabled": true,
      "timeout": 10000
    }
  }
}
```

也可以用 opencode 的交互式命令添加：

```powershell
opencode mcp add
```

添加时选择 local MCP，并填写：

```text
command: C:\Users\olivi\Documents\Create_tool\.venv\Scripts\python.exe -m ai_ssh_mcp
cwd: C:\Users\olivi\Documents\Create_tool
```

添加后检查 MCP 是否被识别：

```powershell
opencode mcp list
```

### opencode 对话示例

首次配置设备：

```text
use ai_ssh_device。调用 configure_device，配置我的嵌入式设备：
host 是 <DEVICE_IP>，port 是 22，username 是 <DEVICE_USER>。
ssh_password 和 su_password 我会提供。
```

测试连接：

```text
use ai_ssh_device。调用 test_connection，测试设备 SSH 登录和 su 是否正常。
```

生成诊断计划，不直接执行：

```text
use ai_ssh_device。帮我检查设备网络为什么不通。
先调用 plan_diagnostic_task，把计划和命令展示给我，不要直接执行。
```

确认后执行：

```text
我确认执行 approval_id 为 xxx 的计划。
use ai_ssh_device 调用 run_approved_plan，user_confirmed=true。
```

注意：诊断任务必须先 `plan_diagnostic_task`，等你在聊天里确认后再 `run_approved_plan`。工具本身也会要求 `user_confirmed=true`，防止 agent 绕过确认直接执行。

### 白名单命令管理

查询白名单：

```text
use ai_ssh_device。调用 list_whitelist_commands，列出当前所有白名单命令。
```

新增自定义白名单命令：

```text
use ai_ssh_device。调用 add_whitelist_commands，新增这些命令：
[
  {"command": "cat /etc/os-release", "purpose": "读取系统发行版本"},
  {"command": "cat /proc/interrupts", "purpose": "读取中断统计"}
]
```

删除自定义白名单命令，或禁用内置命令：

```text
use ai_ssh_device。调用 delete_whitelist_commands，command_ids 为：
["custom:xxxxxxxxxxxxxxxx", "netstat"]
```

如果删除的是自定义命令，会从本地白名单移除；如果删除的是内置命令，会被标记为禁用。再次调用 `add_whitelist_commands` 添加同一条内置命令时，会重新启用它。

将指定白名单命令加入诊断计划：

```text
use ai_ssh_device。调用 plan_diagnostic_task：
task = "查看系统版本和中断状态"
command_ids = ["custom:xxxxxxxxxxxxxxxx"]
```

### 下载设备文件

文件下载使用 SFTP over SSH，复用 `configure_device` 保存的 SSH 凭据。它不是明文 FTP；这样更安全，也不需要额外保存 FTP 账号密码。

下载前先让 agent 展示远端文件列表和本机目标目录，确认后再执行：

```text
use ai_ssh_device。调用 download_device_files：
remote_paths = ["/var/log/messages", "/tmp/debug.log"]
local_dir = "C:\\Users\\olivi\\Downloads\\device_logs"
user_confirmed = true
```

下载限制：

- 只接受明确的绝对文件路径，例如 `/var/log/messages`。
- 不支持通配符，例如 `/var/log/*.log`。
- 不下载目录。
- 默认单文件最大 50 MB，可用 `max_bytes_per_file` 调整。
- 会拒绝常见敏感路径，例如 `/etc/shadow`、`.ssh/`、`ssl/private/`、`/proc/kcore`。
- SFTP 权限通常是 SSH 登录用户权限；如果某些 root-only 文件无法下载，后续可以再加 root shell 打包下载模式。

### 运行交互式后台工具

适合这种手工流程：

```text
cd /path/to/tool
./tool_name
xxx>
show status
line 1
line 2
xxx>
```

调用示例：

```text
use ai_ssh_device。调用 run_interactive_tool：
work_dir = "/path/to/tool"
tool_command = "./tool_name"
inputs = ["show status", "show detail"]
prompt_pattern = "xxx>$"
prompt_settle_seconds = 0.8
user_confirmed = true
```

读取逻辑：

- 先进入 `work_dir`，再启动 `tool_command`。
- 等待出现 `prompt_pattern`，例如 `xxx>$`。
- 每输入一条指令，就持续读取输出。
- 看到提示符后，不会立刻返回；会继续等待 `prompt_settle_seconds` 秒。
- 如果这段时间没有新内容，才认为本次输出结束。
- 返回时会去掉输入回显和最后一个提示符，只保留中间的多行结果。

安全限制：

- `work_dir` 必须是绝对路径。
- `tool_command` 必须类似 `./tool_name`，只允许简单参数。
- 每条 `inputs` 只能是一行，不能包含换行。
- 仍然需要 `user_confirmed=true`。
- 默认单条输出会按全局输出限制截断，避免超大内容撑爆上下文。

### 运行普通 shell 命令

适合 `pwd`、`ls -l`、`cd /path` 这类普通后台命令。命令会在同一个 root shell 里按顺序执行，所以前一条 `cd` 会影响后一条命令。

调用示例：

```text
use ai_ssh_device。调用 run_shell_commands：
commands = ["pwd", "cd /var/log", "ls -l", "cd /path/not-exist"]
user_confirmed = true
```

返回结果里每条命令都有：

- `command`：实际执行的命令。
- `output` / `stdout`：命令产生的输出；在交互式 PTY 里，错误输出通常也会合并到这里。
- `stderr`：保留字段；多数设备交互 shell 下为空。
- `exit_status`：退出码，`0` 表示成功，非 `0` 表示失败。
- `success`：根据 `exit_status == 0` 得出的布尔值。
- `duration_ms`：耗时。
- `truncated`：输出是否被截断。

例子：

- `ls -l` 有输出：`output` 会包含文件列表，`exit_status=0`。
- `cd /var/log` 成功但没有输出：`output=""`，`exit_status=0`，所以你仍然知道它成功了。
- `cd /not-exist` 失败：`output` 会包含 shell 的错误文本，`exit_status` 通常非 `0`。

安全限制：

- 每条命令只能是一行。
- 会拦截明显危险命令和命令链，例如 `rm`、`reboot`、`;`、`&&`、`||`、重定向写文件等。
- 会拦截常见敏感路径读取，例如 `/etc/shadow`、`.ssh/`、`/etc/ssl/private`。
- 仍然需要 `user_confirmed=true`。

## 推荐使用流程

1. 调用 `configure_device` 保存设备信息和密码。
2. 调用 `test_connection` 检查登录与 `su` 是否可用。
3. agent 调用 `plan_diagnostic_task` 生成计划，把命令和风险说明展示给用户。
4. 用户在聊天里确认后，agent 调用 `run_approved_plan`，并传入 `user_confirmed=true`。
5. 如需下载日志或诊断文件，agent 展示文件列表和目标目录后调用 `download_device_files`，并传入 `user_confirmed=true`。
6. 如需操作厂商交互式工具，agent 展示目录、工具命令、提示符和输入指令后调用 `run_interactive_tool`。
7. 如需执行普通 shell 查询命令，agent 展示命令列表后调用 `run_shell_commands`。
8. 查看返回结果，必要时用 `list_recent_runs` 和 `get_run_detail` 追溯。

## 安全边界

- 命令采用精确白名单，不能由 agent 任意拼接 shell。
- 自定义白名单命令仍会经过危险命令扫描。
- 计划生成后会保存命令哈希，执行前再次校验。
- 同一个计划只能执行一次。
- 输出会被截断，避免超大日志撑爆上下文。
- 第一版虽然登录后立即 `su -`，但仍只允许只读诊断命令。
- 文件下载必须显式传入 `user_confirmed=true`。
- 交互式工具执行必须显式传入 `user_confirmed=true`。
- 普通 shell 命令执行必须显式传入 `user_confirmed=true`。

## 本地测试

```powershell
.\.venv\Scripts\python -m unittest discover
```

没有真实设备时，本地测试仍可以覆盖配置、凭据键名、命令白名单、审批哈希、输出截断、计划执行门禁、下载路径校验、交互式输出清洗和普通 shell 命令门禁。
