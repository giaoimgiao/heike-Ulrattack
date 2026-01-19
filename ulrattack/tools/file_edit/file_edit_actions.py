import json
import re
from pathlib import Path
from typing import Any, cast

from ulrattack.tools.registry import register_tool


def _parse_file_editor_output(output: str) -> dict[str, Any]:
    try:
        pattern = r"<oh_aci_output_[^>]+>\n(.*?)\n</oh_aci_output_[^>]+>"
        match = re.search(pattern, output, re.DOTALL)

        if match:
            json_str = match.group(1)
            data = json.loads(json_str)
            return cast("dict[str, Any]", data)
        return {"output": output, "error": None}
    except (json.JSONDecodeError, AttributeError):
        return {"output": output, "error": None}


@register_tool
def str_replace_editor(
    command: str,
    path: str,
    file_text: str | None = None,
    view_range: list[int] | None = None,
    old_str: str | None = None,
    new_str: str | None = None,
    insert_line: int | None = None,
    agent_state: Any = None,
) -> dict[str, Any]:
    from openhands_aci import file_editor

    try:
        path_obj = Path(path)
        if not path_obj.is_absolute():
            path = str(Path("/workspace") / path_obj)
        
        # 权限检查：只有 Report Agent 才能创建报告文件
        if command == "create" and "attack_report.md" in path:
            agent_name = getattr(agent_state, "agent_name", "") if agent_state else ""
            if "Report" not in agent_name and "report" not in agent_name.lower():
                # 向父节点报告异常
                if agent_state and hasattr(agent_state, 'parent_id') and agent_state.parent_id:
                    try:
                        from ulrattack.tools.agents_graph.agents_graph_actions import send_message_to_agent
                        
                        send_message_to_agent(
                            agent_state=agent_state,
                            target_agent_id=agent_state.parent_id,
                            message=f"""<permission_violation>
⚠️ Agent 权限异常报告

**违规 Agent**: {agent_name} ({agent_state.agent_id})
**尝试操作**: 创建攻击报告文件 (attack_report.md)
**违规原因**: 该 Agent 无权创建最终报告

**Agent 任务**: {agent_state.task}

**建议处理**:
1. 如果需要生成报告，请创建 "Attack Report Agent"
2. 或者指导该 Agent 专注于其职责范围内的任务
3. 该 Agent 应调用 agent_finish 结束当前任务

**注意**: 只有名称包含 "Report" 的 Agent 才能生成最终报告。
</permission_violation>""",
                            message_type="information",
                            priority="high"
                        )
                    except Exception as e:
                        import logging
                        logging.warning(f"Failed to notify parent agent: {e}")
                
                return {
                    "output": "",
                    "error": (
                        f"❌ 权限拒绝：Agent '{agent_name}' 无权创建攻击报告文件。\n"
                        f"只有 'Attack Report Agent' 才能生成最终报告。\n"
                        f"你的职责是：{agent_state.task if agent_state else '未知'}\n"
                        f"已向父节点 (Root Agent) 报告此异常。\n"
                        f"请等待父节点的指示，或调用 agent_finish 结束你的任务。"
                    )
                }

        result = file_editor(
            command=command,
            path=path,
            file_text=file_text,
            view_range=view_range,
            old_str=old_str,
            new_str=new_str,
            insert_line=insert_line,
        )

        parsed = _parse_file_editor_output(result)

        if parsed.get("error"):
            return {"error": parsed["error"]}

        return {"content": parsed.get("output", result)}

    except (OSError, ValueError) as e:
        return {"error": f"Error in {command} operation: {e!s}"}


@register_tool
def list_files(
    path: str,
    recursive: bool = False,
) -> dict[str, Any]:
    from openhands_aci.utils.shell import run_shell_cmd

    try:
        path_obj = Path(path)
        if not path_obj.is_absolute():
            path = str(Path("/workspace") / path_obj)
            path_obj = Path(path)

        if not path_obj.exists():
            return {"error": f"Directory not found: {path}"}

        if not path_obj.is_dir():
            return {"error": f"Path is not a directory: {path}"}

        cmd = f"find '{path}' -type f -o -type d | head -500" if recursive else f"ls -1a '{path}'"

        exit_code, stdout, stderr = run_shell_cmd(cmd)

        if exit_code != 0:
            return {"error": f"Error listing directory: {stderr}"}

        items = stdout.strip().split("\n") if stdout.strip() else []

        files = []
        dirs = []

        for item in items:
            item_path = item if recursive else str(Path(path) / item)
            item_path_obj = Path(item_path)

            if item_path_obj.is_file():
                files.append(item)
            elif item_path_obj.is_dir():
                dirs.append(item)

        return {
            "files": sorted(files),
            "directories": sorted(dirs),
            "total_files": len(files),
            "total_dirs": len(dirs),
            "path": path,
            "recursive": recursive,
        }

    except (OSError, ValueError) as e:
        return {"error": f"Error listing directory: {e!s}"}


@register_tool
def search_files(
    path: str,
    regex: str,
    file_pattern: str = "*",
) -> dict[str, Any]:
    from openhands_aci.utils.shell import run_shell_cmd

    try:
        path_obj = Path(path)
        if not path_obj.is_absolute():
            path = str(Path("/workspace") / path_obj)

        if not Path(path).exists():
            return {"error": f"Directory not found: {path}"}

        escaped_regex = regex.replace("'", "'\"'\"'")

        cmd = f"rg --line-number --glob '{file_pattern}' '{escaped_regex}' '{path}'"

        exit_code, stdout, stderr = run_shell_cmd(cmd)

        if exit_code not in {0, 1}:
            return {"error": f"Error searching files: {stderr}"}
        return {"output": stdout if stdout else "No matches found"}

    except (OSError, ValueError) as e:
        return {"error": f"Error searching files: {e!s}"}


# ruff: noqa: TRY300
