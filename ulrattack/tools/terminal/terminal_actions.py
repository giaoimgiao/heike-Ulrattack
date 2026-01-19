from typing import Any

from ulrattack.tools.registry import register_tool


@register_tool
def terminal_execute(
    command: str,
    is_input: bool = False,
    timeout: float | None = None,
    terminal_id: str | None = None,
    no_enter: bool = False,
    agent_state: Any = None,
) -> dict[str, Any]:
    from .terminal_manager import get_terminal_manager

    # 权限检查：防止非 Report Agent 通过 terminal 创建报告
    if "attack_report.md" in command and (">" in command or "cat" in command or "echo" in command):
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
⚠️ Agent 权限异常报告 (Terminal 操作)

**违规 Agent**: {agent_name} ({agent_state.agent_id})
**尝试命令**: {command[:200]}...
**违规原因**: 尝试通过 terminal 创建攻击报告文件

**建议处理**: 请指导该 Agent 停止当前操作并专注于其职责范围内的任务。
</permission_violation>""",
                        message_type="information",
                        priority="high"
                    )
                except Exception as e:
                    import logging
                    logging.warning(f"Failed to notify parent agent: {e}")
            
            return {
                "error": (
                    f"❌ 权限拒绝：Agent '{agent_name}' 无权创建攻击报告文件。\n"
                    f"只有 'Attack Report Agent' 才能生成最终报告。\n"
                    f"已向父节点报告此异常。请等待指示或调用 agent_finish 结束任务。"
                ),
                "command": command,
                "terminal_id": terminal_id or "default",
                "content": "",
                "status": "permission_denied",
                "exit_code": 1,
                "working_dir": None,
            }

    manager = get_terminal_manager()

    try:
        return manager.execute_command(
            command=command,
            is_input=is_input,
            timeout=timeout,
            terminal_id=terminal_id,
            no_enter=no_enter,
        )
    except (ValueError, RuntimeError) as e:
        return {
            "error": str(e),
            "command": command,
            "terminal_id": terminal_id or "default",
            "content": "",
            "status": "error",
            "exit_code": None,
            "working_dir": None,
        }
