import asyncio
import json
import logging
from typing import Any, List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ulrattack.agents.ULRATTACKAgent import ULRATTACKAgent
from ulrattack.agents.AttackAgent import AttackAgent
from ulrattack.agents.CrawlerAgent import CrawlerAgent
from ulrattack.config import Config, apply_saved_config, save_current_config
from ulrattack.interface.utils import (
    assign_workspace_subdirs,
    check_docker_connection,
    collect_local_sources,
    generate_run_name,
    infer_target_type,
    rewrite_localhost_targets,
)
from ulrattack.llm.config import LLMConfig
from ulrattack.runtime.docker_runtime import HOST_GATEWAY_HOSTNAME
from ulrattack.telemetry.tracer import Tracer, set_global_tracer

# 初始化配置
apply_saved_config()
logging.getLogger().setLevel(logging.INFO)

app = FastAPI(title="ULRATTACK Web Interface")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 全局状态
class GlobalState:
    tracer: Tracer | None = None
    agent_task: asyncio.Task | None = None
    active_connections: List[WebSocket] = []
    is_scanning: bool = False

state = GlobalState()

# Pydantic 模型
class ScanRequest(BaseModel):
    target: str
    scan_mode: str = "standard"
    agent_mode: str = "pentest"  # pentest, attack, crawler
    crawler_requirement: str = ""  # 爬虫模式下的用户需求
    instruction: str = ""
    model: str = ""
    api_base: str = ""
    api_key: str = ""

class ChatMessage(BaseModel):
    message: str
    agent_id: str

# 静态文件服务 - 用于加载logo图片
app.mount("/static", StaticFiles(directory="ulrattack/log"), name="static")

# 路由
@app.get("/")
async def get_index():
    with open("ulrattack/interface/templates/index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())

import httpx
import os

# ...

class ConfigRequest(BaseModel):
    model: str = ""
    api_base: str = ""
    api_key: str = ""

@app.get("/api/config")
async def get_config():
    return {
        "model": Config.get("ulrattack_llm") or Config.get("llm_model_name") or Config.get("litellm_model") or "",
        "api_base": Config.get("llm_api_base") or Config.get("litellm_base_url") or Config.get("openai_api_base") or "",
        # Mask API key for security, only indicate if configured
        "api_key_configured": bool(Config.get("llm_api_key") or Config.get("litellm_api_key") or Config.get("openai_api_key"))
    }

@app.post("/api/config")
async def save_config(req: ConfigRequest):
    """Save LLM configuration to environment variables and persist to config file"""
    try:
        if req.model:
            os.environ["ULRATTACK_LLM"] = req.model
            os.environ["LLM_MODEL_NAME"] = req.model
            os.environ["LITELLM_MODEL"] = req.model
        if req.api_base:
            os.environ["LLM_API_BASE"] = req.api_base
            os.environ["LITELLM_BASE_URL"] = req.api_base
            os.environ["OPENAI_API_BASE"] = req.api_base
        if req.api_key:
            os.environ["LLM_API_KEY"] = req.api_key
            os.environ["LITELLM_API_KEY"] = req.api_key
            os.environ["OPENAI_API_KEY"] = req.api_key
        
        # Persist to config file
        save_current_config()
        
        logging.info(f"Config saved: model={req.model}, api_base={req.api_base}, api_key={'***' if req.api_key else 'not set'}")
        return {"status": "ok"}
    except Exception as e:
        logging.error(f"Failed to save config: {e}")
        return {"status": "error", "message": str(e)}

@app.get("/api/models")
async def get_models(api_base: str = None, api_key: str = None):
    """获取可用模型列表，支持传入临时的 API 配置"""
    # 优先使用传入的参数，否则从配置读取
    base_url = api_base or Config.get("llm_api_base") or Config.get("litellm_base_url") or Config.get("openai_api_base")
    key = api_key or Config.get("llm_api_key") or Config.get("litellm_api_key") or Config.get("openai_api_key")
    
    if not base_url:
        return {"models": [], "error": "请先输入 API Base URL"}
        
    try:
        # Standard /v1/models endpoint
        url = f"{base_url.rstrip('/')}/models"
        headers = {}
        if key:
            headers["Authorization"] = f"Bearer {key}"
            
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=headers, timeout=10.0)
            if resp.status_code == 200:
                data = resp.json()
                # Compatible with OpenAI format { "data": [ {"id": "..."} ] }
                if "data" in data and isinstance(data["data"], list):
                    return {"models": [m["id"] for m in data["data"] if "id" in m]}
                return {"models": []}
            else:
                logging.warning(f"Failed to fetch models: HTTP {resp.status_code}")
                return {"models": [], "error": f"请求失败: HTTP {resp.status_code}"}
    except Exception as e:
        logging.warning(f"Failed to fetch models: {e}")
        return {"models": [], "error": f"请求失败: {str(e)}"}

@app.post("/api/start_scan")
async def start_scan(req: ScanRequest):
    if state.is_scanning:
        return {"status": "error", "message": "任务已在运行中"}

    try:
        # 0. 验证必要配置
        model = req.model or Config.get("ulrattack_llm")
        api_base = req.api_base or Config.get("llm_api_base") or Config.get("litellm_base_url")
        api_key = req.api_key or Config.get("llm_api_key") or Config.get("litellm_api_key")
        
        if not model:
            return {"status": "error", "message": "请先在 Settings 中配置模型 (LLM Model)"}
        if not api_base:
            return {"status": "error", "message": "请先在 Settings 中配置 API Base URL"}
        if not api_key:
            return {"status": "error", "message": "请先在 Settings 中配置 API Key"}
        
        # 1. 更新 LLM 配置 - 确保所有相关环境变量都被设置
        os.environ["ULRATTACK_LLM"] = model
        os.environ["LLM_MODEL_NAME"] = model
        os.environ["LITELLM_MODEL"] = model
        os.environ["LLM_API_BASE"] = api_base
        os.environ["LITELLM_BASE_URL"] = api_base
        os.environ["OPENAI_API_BASE"] = api_base
        os.environ["LLM_API_KEY"] = api_key
        os.environ["LITELLM_API_KEY"] = api_key
        os.environ["OPENAI_API_KEY"] = api_key
        logging.info(f"🔧 已设置模型: {model}")

        # 2. 重置所有状态
        from ulrattack.tools.agents_graph.agents_graph_actions import reset_all_state
        reset_all_state()
        
        agent_mode = req.agent_mode
        mode_names = {"pentest": "渗透测试", "attack": "攻击测试", "crawler": "网络爬虫"}
        logging.info(f"♻️ 已重置所有 Agent 状态，启动模式: {mode_names.get(agent_mode, agent_mode)}")

        # 3. 准备目标配置
        targets_info = []
        target_type, target_dict = infer_target_type(req.target)
        
        display_target = req.target
        if target_type == "local_code":
            display_target = target_dict.get("target_path", req.target)

        targets_info.append({
            "type": target_type,
            "details": target_dict,
            "original": display_target
        })

        assign_workspace_subdirs(targets_info)
        rewrite_localhost_targets(targets_info, HOST_GATEWAY_HOSTNAME)

        run_name = generate_run_name(targets_info)
        
        # 4. 根据 agent_mode 构建不同的配置
        scan_config = {
            "scan_id": run_name,
            "targets": targets_info,
            "user_instructions": req.instruction,
            "run_name": run_name,
            "agent_mode": agent_mode,
        }
        
        # 爬虫模式添加爬取需求
        if agent_mode == "crawler":
            scan_config["crawl_requirement"] = req.crawler_requirement

        # 5. 准备 Agent 配置
        local_sources = collect_local_sources(targets_info)
        llm_config = LLMConfig(scan_mode=req.scan_mode)
        
        # 根据模式调整迭代次数
        max_iterations = 300
        if agent_mode == "attack":
            max_iterations = 500  # 攻击测试需要更多迭代
        elif agent_mode == "crawler":
            max_iterations = 200  # 爬虫任务相对较少迭代
        
        agent_config = {
            "llm_config": llm_config,
            "max_iterations": max_iterations,
        }
        if local_sources:
            agent_config["local_sources"] = local_sources

        # 5. 初始化 Tracer
        state.tracer = Tracer(run_name)
        state.tracer.set_scan_config(scan_config)
        set_global_tracer(state.tracer)

        # 6. 启动后台任务 - 根据模式选择不同的 Agent
        async def run_agent():
            try:
                check_docker_connection()
                
                if agent_mode == "attack":
                    agent = AttackAgent(agent_config)
                    await agent.execute_attack(scan_config)
                elif agent_mode == "crawler":
                    agent = CrawlerAgent(agent_config)
                    await agent.execute_crawl(scan_config)
                else:  # pentest (default)
                    agent = ULRATTACKAgent(agent_config)
                    await agent.execute_scan(scan_config)
                    
            except Exception as e:
                logging.exception(f"Agent execution failed: {e}")
            finally:
                state.is_scanning = False

        state.agent_task = asyncio.create_task(run_agent())
        state.is_scanning = True

        return {"status": "ok", "run_name": run_name, "agent_mode": agent_mode}

    except Exception as e:
        logging.exception("Failed to start task")
        return {"status": "error", "message": str(e)}

@app.post("/api/stop_scan")
async def stop_scan():
    if state.agent_task and not state.agent_task.done():
        state.agent_task.cancel()
        try:
            await state.agent_task
        except asyncio.CancelledError:
            pass
    
    state.is_scanning = False
    if state.tracer:
        state.tracer.cleanup()
        
    return {"status": "ok"}

@app.post("/api/stop_agent/{agent_id}")
async def stop_agent(agent_id: str):
    """停止指定的 Agent"""
    try:
        from ulrattack.tools.agents_graph.agents_graph_actions import stop_agent as stop_agent_func
        
        result = stop_agent_func(agent_id)
        
        if result.get("success"):
            return {"status": "ok", "message": result.get("message", "Agent 已停止")}
        else:
            return {"status": "error", "message": result.get("error", "停止失败")}
    except Exception as e:
        logging.exception(f"Failed to stop agent {agent_id}")
        return {"status": "error", "message": str(e)}

@app.post("/api/send_message")
async def send_message(msg: ChatMessage):
    if not state.is_scanning or not msg.agent_id:
        return {"status": "error", "message": "没有活跃的扫描或未指定代理"}

    try:
        from ulrattack.tools.agents_graph.agents_graph_actions import send_user_message_to_agent
        
        # 记录用户消息
        if state.tracer:
            state.tracer.log_chat_message(
                content=msg.message,
                role="user",
                agent_id=msg.agent_id
            )
            
        send_user_message_to_agent(msg.agent_id, msg.message)
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    state.active_connections.append(websocket)
    try:
        while True:
            if state.tracer:
                # 收集数据
                data = {
                    "agents": state.tracer.agents,
                    "vulnerabilities": state.tracer.vulnerability_reports,
                    "stats": {
                        "tool_count": state.tracer.get_real_tool_count(),
                        **state.tracer.get_total_llm_stats()["total"],
                        "total_tokens": state.tracer.get_total_llm_stats()["total_tokens"]
                    },
                    "streaming_content": state.tracer.streaming_content,
                    "events": {}
                }
                
                # 为每个代理收集事件
                for agent_id in state.tracer.agents:
                    chat_events = [
                        {
                            "type": "chat",
                            "timestamp": msg["timestamp"],
                            "id": f"chat_{msg['message_id']}",
                            "role": msg["role"],
                            "content": msg["content"],
                            "tool_name": None,
                            "status": None,
                            "result": None
                        }
                        for msg in state.tracer.chat_messages
                        if msg.get("agent_id") == agent_id
                    ]
                    
                    tool_events = [
                        {
                            "type": "tool",
                            "timestamp": tool_data["timestamp"],
                            "id": f"tool_{exec_id}",
                            "role": "tool",
                            "content": None,
                            "tool_name": tool_data.get("tool_name"),
                            "status": tool_data.get("status"),
                            "result": tool_data.get("result")
                        }
                        for exec_id, tool_data in state.tracer.tool_executions.items()
                        if tool_data.get("agent_id") == agent_id
                    ]
                    
                    events = sorted(chat_events + tool_events, key=lambda x: x["timestamp"])
                    data["events"][agent_id] = events

                await websocket.send_text(json.dumps(data))
            
            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        state.active_connections.remove(websocket)
    except Exception as e:
        logging.error(f"WebSocket error: {e}")
        try:
            state.active_connections.remove(websocket)
        except ValueError:
            pass

def run():
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

if __name__ == "__main__":
    run()

