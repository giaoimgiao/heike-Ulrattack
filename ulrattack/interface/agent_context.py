"""Agent 对话上下文编辑与运行时模型切换。"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from typing import Any

from ulrattack.config import Config
from ulrattack.llm.memory_compressor import MemoryCompressor

logger = logging.getLogger(__name__)


def _content_preview(content: Any, max_len: int = 400) -> str:
    if isinstance(content, list):
        text = "[多模态内容]"
    elif isinstance(content, str):
        text = content
    else:
        text = str(content)
    if len(text) > max_len:
        return text[:max_len] + "…"
    return text


def _get_agent(agent_id: str) -> Any | None:
    from ulrattack.tools.agents_graph.agents_graph_actions import _agent_instances

    return _agent_instances.get(agent_id)


def get_agent_context(agent_id: str) -> dict[str, Any]:
    agent = _get_agent(agent_id)
    if not agent:
        return {"success": False, "error": f"Agent '{agent_id}' 未找到或未在运行"}

    items = []
    for index, msg in enumerate(agent.state.messages):
        content = msg.get("content", "")
        items.append(
            {
                "index": index,
                "role": msg.get("role", "unknown"),
                "preview": _content_preview(content),
                "length": len(content) if isinstance(content, str) else 0,
            }
        )

    return {
        "success": True,
        "agent_id": agent_id,
        "agent_name": agent.state.agent_name,
        "model": agent.llm.config.model_name,
        "message_count": len(items),
        "messages": items,
    }


def get_agent_message(agent_id: str, index: int) -> dict[str, Any]:
    agent = _get_agent(agent_id)
    if not agent:
        return {"success": False, "error": f"Agent '{agent_id}' 未找到"}

    messages = agent.state.messages
    if index < 0 or index >= len(messages):
        return {"success": False, "error": f"消息索引 {index} 无效"}

    msg = messages[index]
    content = msg.get("content", "")
    if isinstance(content, list):
        content = str(content)

    return {
        "success": True,
        "index": index,
        "role": msg.get("role"),
        "content": content if isinstance(content, str) else str(content),
    }


def edit_agent_message(agent_id: str, index: int, content: str) -> dict[str, Any]:
    agent = _get_agent(agent_id)
    if not agent:
        return {"success": False, "error": f"Agent '{agent_id}' 未找到"}

    messages = agent.state.messages
    if index < 0 or index >= len(messages):
        return {"success": False, "error": f"消息索引 {index} 无效"}

    messages[index]["content"] = content
    logger.info("Agent %s: edited message at index %s", agent_id, index)
    return {"success": True, "message": "消息已更新", "index": index}


def truncate_agent_context(agent_id: str, from_index: int) -> dict[str, Any]:
    agent = _get_agent(agent_id)
    if not agent:
        return {"success": False, "error": f"Agent '{agent_id}' 未找到"}

    messages = agent.state.messages
    if from_index < 0 or from_index > len(messages):
        return {"success": False, "error": f"截断索引 {from_index} 无效"}

    removed = len(messages) - from_index
    agent.state.messages = messages[:from_index]
    logger.info("Agent %s: truncated context from index %s (%s removed)", agent_id, from_index, removed)
    return {
        "success": True,
        "message": f"已删除索引 {from_index} 及之后的 {removed} 条消息",
        "remaining": from_index,
    }


async def _cancel_agent_task(agent: Any) -> None:
    task = getattr(agent, "_current_task", None)
    if task and not task.done():
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
    agent._current_task = None


async def regenerate_agent(agent_id: str, from_index: int | None = None) -> dict[str, Any]:
    agent = _get_agent(agent_id)
    if not agent:
        return {"success": False, "error": f"Agent '{agent_id}' 未找到"}

    await _cancel_agent_task(agent)

    messages = agent.state.messages
    if from_index is None:
        from_index = len(messages)
        for i in range(len(messages) - 1, -1, -1):
            if messages[i].get("role") == "assistant":
                from_index = i
                break

    if from_index < 0 or from_index > len(messages):
        return {"success": False, "error": f"索引 {from_index} 无效"}

    removed = len(messages) - from_index
    agent.state.messages = messages[:from_index]
    agent.state.resume_from_waiting()

    from ulrattack.telemetry.tracer import get_global_tracer
    from ulrattack.tools.agents_graph.agents_graph_actions import _agent_graph

    tracer = get_global_tracer()
    if tracer:
        tracer.update_agent_status(agent_id, "running")
        tracer.clear_streaming_content(agent_id)
    if agent_id in _agent_graph.get("nodes", {}):
        _agent_graph["nodes"][agent_id]["status"] = "running"

    logger.info("Agent %s: regenerate from index %s", agent_id, from_index)
    return {
        "success": True,
        "message": f"已回退上下文并触发重新生成（移除 {removed} 条）",
        "from_index": from_index,
        "remaining": from_index,
    }


def switch_runtime_model(
    model: str,
    *,
    api_base: str | None = None,
    api_key: str | None = None,
    agent_id: str | None = None,
) -> dict[str, Any]:
    """仅切换运行中 Agent 的模型，不改动 API Base/Key，不写磁盘配置。"""
    _ = api_base, api_key  # 运行时切换不接受改 API，避免误覆盖
    if not model.strip():
        return {"success": False, "error": "模型名称不能为空"}

    model = model.strip()
    os.environ["ULRATTACK_LLM"] = model
    os.environ["LLM_MODEL_NAME"] = model
    os.environ["LITELLM_MODEL"] = model

    from ulrattack.tools.agents_graph.agents_graph_actions import _agent_instances

    updated: list[str] = []
    targets = (
        {agent_id: _agent_instances[agent_id]}
        if agent_id and agent_id in _agent_instances
        else dict(_agent_instances)
    )

    if agent_id and agent_id not in _agent_instances:
        return {"success": False, "error": f"Agent '{agent_id}' 未找到"}

    for aid, agent in targets.items():
        agent.llm.config.model_name = model
        agent.llm.memory_compressor = MemoryCompressor(model_name=model)
        updated.append(aid)

    scope = agent_id or "all"
    logger.info("Runtime model switched to %s (scope=%s, agents=%s)", model, scope, updated)
    return {
        "success": True,
        "model": model,
        "scope": scope,
        "updated_agents": updated,
        "message": f"已切换模型为 {model}（{len(updated)} 个 Agent，未修改 API 配置）",
    }


def get_runtime_model_info() -> dict[str, Any]:
    from ulrattack.tools.agents_graph.agents_graph_actions import _agent_instances

    current = Config.get("ulrattack_llm") or ""
    per_agent = {aid: inst.llm.config.model_name for aid, inst in _agent_instances.items()}
    return {
        "global_model": current,
        "agent_models": per_agent,
        "active_agent_count": len(_agent_instances),
    }
