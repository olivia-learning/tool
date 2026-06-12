# AI SSH MCP

这是一个本地 MCP 工具服务，用来让其他 agent 以受控方式连接一台 Linux/BusyBox 嵌入式设备：先生成诊断计划，经过用户在聊天里确认后，再通过 SSH 登录、`su -` 提权并执行只读诊断命令。

第一版只做诊断查询，不做配置修改、升级、重启、删除文件等高风险操作。

## 功能

- `configure_device`：保存单台设备的 host、port、username，并把 SSH 密码和 su 密码存入本机 keyring。
- `test_connection`：验证 SSH 登录、`su -` 提权和命令执行。
- `plan_diagnostic_task`：根据自然语言任务生成只读诊断命令计划。
- `run_approved_plan`：执行已经生成且用户确认的计划。
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

## 推荐使用流程

1. 调用 `configure_device` 保存设备信息和密码。
2. 调用 `test_connection` 检查登录与 `su` 是否可用。
3. agent 调用 `plan_diagnostic_task` 生成计划，把命令和风险说明展示给用户。
4. 用户在聊天里确认后，agent 调用 `run_approved_plan`，并传入 `user_confirmed=true`。
5. 查看返回结果，必要时用 `list_recent_runs` 和 `get_run_detail` 追溯。

## 安全边界

- 命令采用精确白名单，不能由 agent 任意拼接 shell。
- 计划生成后会保存命令哈希，执行前再次校验。
- 同一个计划只能执行一次。
- 输出会被截断，避免超大日志撑爆上下文。
- 第一版虽然登录后立即 `su -`，但仍只允许只读诊断命令。

## 本地测试

```powershell
.\.venv\Scripts\python -m unittest discover
```

没有真实设备时，本地测试仍可以覆盖配置、凭据键名、命令白名单、审批哈希、输出截断和计划执行门禁。
