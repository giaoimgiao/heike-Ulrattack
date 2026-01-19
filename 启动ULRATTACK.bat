@echo off
chcp 65001 >nul
title ULRATTACK - AI网络安全渗透测试系统
setlocal EnableDelayedExpansion

REM ================================================
REM API 配置
REM ================================================
set ULRATTACK_LLM=openai/gpt-5.1-codex-max
set LLM_API_KEY=sk-Pd6a1c58e03726bb4655e0b74da9b1461d77df1a8c1jUqDM
set LLM_API_BASE=https://api.gptsapi.net/v1

REM 强制 Python 使用 UTF-8 编码
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

REM 使用 Python 启动器查找最佳版本
set PYTHON_CMD=py -3.14

echo.
echo  +===============================================================+
echo  :                                                               :
echo  :    _   _ _     ____    _  _____ _____  _    ____ _  __        :
echo  :   ^| ^| ^| ^| ^|   ^|  _ \  / \^|_   _ ^|_   _^|/ \  / ___^| ^|/ /        :
echo  :   ^| ^| ^| ^| ^|   ^| ^|_^) ^|/ _ \ ^| ^|   ^| ^| / _ \^| ^|   ^| ' /         :
echo  :   ^| ^|_^| ^| ^|___^|  _ ^< / ___ \^| ^|   ^| ^|/ ___ \ ^|___^| . \         :
echo  :    \___/^|_____^|_^| \_/_/   \_\_^|   ^|_/_/   \_\____^|_^|\_\        :
echo  :                                                               :
echo  :           [ AI 网络安全渗透测试系统 ]                         :
echo  :                                                               :
echo  +===============================================================+
echo.

REM 使用 py 启动器检查 Python 版本
%PYTHON_CMD% --version >nul 2>&1
if %errorlevel% neq 0 (
    set PYTHON_CMD=py -3
    py -3 --version >nul 2>&1
    if %errorlevel% neq 0 (
        echo  [X] 错误: 未找到 Python 3.12+
        pause
        exit /b 1
    )
)

for /f "tokens=2 delims= " %%i in ('%PYTHON_CMD% --version 2^>^&1') do set pyver=%%i
echo  [OK] Python 版本: %pyver%

REM 检查 Docker
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo  [!!] 警告: Docker 未运行或未安装
    echo      ULRATTACK 需要 Docker 来创建沙盒环境
    echo.
)

REM 检查 ulrattack 是否已安装
%PYTHON_CMD% -m pip show ulrattack-agent >nul 2>&1
if %errorlevel% neq 0 (
    echo  [..] 正在安装 ULRATTACK...
    %PYTHON_CMD% -m pip install ulrattack-agent
    if %errorlevel% neq 0 (
        echo  [X] 错误: 安装失败
        pause
        exit /b 1
    )
)

echo  [OK] ULRATTACK 已就绪
echo  [**] API 地址: %LLM_API_BASE%
echo  [**] 模型: %ULRATTACK_LLM%
echo.

echo  +===============================================================+
echo  :                    选择 AI 模型                               :
echo  +---------------------------------------------------------------+
echo  :  [1] gpt-5.1-codex-max       (默认 - 速度快,效果好)              :
echo  :  [2] GPT-5                (OpenAI 旗舰模型)                   :
echo  :  [3] Gemini-3-Pro         (Google 专业版)                     :
echo  :  [4] DeepSeek-R1          (深度求索推理模型)                  :
echo  :  [5] Claude Sonnet 4.5    (Anthropic 智能助手)                :
echo  :  [0] 保持当前选择                                             :
echo  +===============================================================+
echo.
set /p model_choice="  请选择模型 (0-5): "

if "!model_choice!"=="1" set ULRATTACK_LLM=openai/gpt-5.1-codex-max
if "!model_choice!"=="2" set ULRATTACK_LLM=openai/gpt-5
if "!model_choice!"=="3" set ULRATTACK_LLM=openai/gemini-3-pro-preview
if "!model_choice!"=="4" set ULRATTACK_LLM=openai/deepseek-r1
if "!model_choice!"=="5" set ULRATTACK_LLM=openai/claude-sonnet-4-5-20250929

echo.
echo  [**] 已选择模型: %ULRATTACK_LLM%
echo.

echo  +===============================================================+
echo  :                    扫描选项                                   :
echo  +---------------------------------------------------------------+
echo  :  [1] 扫描当前目录         (快速开始)                          :
echo  :  [2] 扫描指定目录         (本地代码审计)                      :
echo  :  [3] 扫描 GitHub 仓库     (远程代码审计)                      :
echo  :  [4] 扫描 Web 应用        (URL 渗透测试)                      :
echo  :  [5] 交互模式             (高级选项)                          :
echo  :  [0] 退出                                                     :
echo  +===============================================================+
echo.

set /p choice="  请选择 (0-5): "

if "!choice!"=="1" (
    echo.
    echo  [..] 正在扫描当前目录...
    %PYTHON_CMD% -m ulrattack.interface.main --target ./
    goto :done
)
if "!choice!"=="2" (
    echo.
    set /p scan_target="  请输入目录路径: "
    echo.
    echo  [..] 正在扫描 !scan_target!...
    %PYTHON_CMD% -m ulrattack.interface.main --target "!scan_target!"
    goto :done
)
if "!choice!"=="3" (
    echo.
    set /p scan_target="  请输入 GitHub URL: "
    echo.
    echo  [..] 正在扫描 !scan_target!...
    %PYTHON_CMD% -m ulrattack.interface.main --target "!scan_target!"
    goto :done
)
if "!choice!"=="4" (
    echo.
    set /p scan_target="  请输入 Web URL: "
    echo.
    echo  [..] 正在扫描 !scan_target!...
    %PYTHON_CMD% -m ulrattack.interface.main --target "!scan_target!"
    goto :done
)
if "!choice!"=="5" (
    echo.
    echo  [**] 交互模式 - 使用 ulrattack --help 查看帮助
    cmd /k
    goto :done
)
if "!choice!"=="0" (
    exit /b 0
)

echo  [X] 错误: 无效的选择

:done
echo.
pause
endlocal
