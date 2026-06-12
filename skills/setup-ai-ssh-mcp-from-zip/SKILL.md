---
name: setup-ai-ssh-mcp-from-zip
description: Guide a user through installing and configuring the AI SSH MCP project from ai-ssh-mcp-tool.zip on a new Windows computer, including Python setup, OpenCode MCP config, project agent discovery, device credential setup, and verification.
---

# Setup AI SSH MCP From ZIP

Use this skill when the user has `ai-ssh-mcp-tool.zip` on a new Windows computer and wants OpenCode to configure the `ai_ssh_device` MCP and `device-maintainer` agent.

## Safety Rules

- Do not ask for or store passwords in files.
- Use `core_configure_device` to save SSH and `su` passwords into the local keyring.
- Do not copy `config.json`, `state.json`, `allowlist.json`, `policy.json`, `.ai_ssh_mcp/`, or `runbooks/` from another computer unless the user explicitly understands the contents.
- Keep `opencode.example.json` as a template; create or edit the real `opencode.json` for the new computer.

## Install The ZIP

1. Ask the user where they want to install the project. Recommend a simple path such as:

```powershell
C:\Tools\ai-ssh-mcp-tool
```

2. Extract `ai-ssh-mcp-tool.zip` into that folder.

3. Confirm these files exist:

```text
pyproject.toml
README.md
opencode.example.json
.opencode\agents\device-maintainer.md
src\ai_ssh_mcp\
```

## Create Python Environment

From the extracted project folder, run:

```powershell
py -m venv .venv
.\.venv\Scripts\python -m pip install -U pip
.\.venv\Scripts\python -m pip install -e .
```

If `py` is unavailable, find Python and use its full path. Python 3.10 or newer is expected.

Verify the MCP package imports:

```powershell
.\.venv\Scripts\python -c "from ai_ssh_mcp.server import REGISTERED_TOOL_NAMES; print(len(REGISTERED_TOOL_NAMES))"
```

The expected count is `16`.

## Configure OpenCode MCP

1. Open or create the user's OpenCode config file. On Windows it is usually:

```text
C:\Users\<USER>\.config\opencode\opencode.json
```

2. Use `opencode.example.json` as the base and set:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "ai_ssh_device": {
      "type": "local",
      "command": [
        "C:\\Tools\\ai-ssh-mcp-tool\\.venv\\Scripts\\python.exe",
        "-m",
        "ai_ssh_mcp"
      ],
      "cwd": "C:\\Tools\\ai-ssh-mcp-tool",
      "enabled": true,
      "timeout": 10000
    }
  }
}
```

Adjust both paths to the actual extraction folder.

3. Restart OpenCode after editing config.

## Configure The Device

In OpenCode, call the MCP tool:

```text
use ai_ssh_device. Call core_configure_device with host, port, username, ssh_password, and su_password.
```

Then verify:

```text
use ai_ssh_device. Call core_test_connection.
```

If connection fails, check host, port, username, SSH password, `su` password, network reachability, and whether the device allows password SSH login.

## Use The Maintenance Agent

The project includes:

```text
.opencode\agents\device-maintainer.md
```

When the user wants the maintenance workflow, ask OpenCode:

```text
Use device-maintainer. Help me inspect the device network issue and give me an execution plan first.
```

The agent must:

- Produce a plan before maintenance.
- Let the user revise the plan.
- Execute only after final user approval.
- Use `ai_ssh_device` MCP tools only.
- Report execution results and verification.

For runbooks, require the two-step flow:

```text
maint_runbook(name, user_confirmed=false)
maint_runbook(name, plan_id=<shown plan_id>, user_confirmed=true)
```

## Final Verification

Run local tests if the user wants confidence before using a real device:

```powershell
$env:PYTHONPATH='src'
.\.venv\Scripts\python -m unittest discover -v
```

Expected result: all tests pass.
