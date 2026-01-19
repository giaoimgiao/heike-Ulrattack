@echo off
chcp 65001 >nul
title ULRATTACK Web - AI网络安全渗透测试平台
setlocal EnableDelayedExpansion

REM ================================================
REM 配置说明：
REM   API 配置已移至 Web 界面的 Settings 中
REM   首次使用请点击 Settings 按钮配置：
REM   - API Base URL
REM   - API Key
REM   - 选择模型
REM   配置会自动保存到 %USERPROFILE%\.ulrattack\cli-config.json
REM ================================================

REM 强制 Python 使用 UTF-8 编码
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

set PYTHON_CMD=py -3.14

echo.
echo  +===============================================================+
echo  :                                                               :
echo  :           [ ULRATTACK Web Server ]                                :
echo  :                                                               :
echo  +===============================================================+
echo.

REM 检查是否安装了 fastapi 和 uvicorn
%PYTHON_CMD% -m pip show fastapi >nul 2>&1
if %errorlevel% neq 0 (
    echo  [..] 正在安装 Web 依赖...
    %PYTHON_CMD% -m pip install fastapi uvicorn websockets
)

echo  [OK] 正在启动 Web 服务器...
echo  [**] 请在浏览器中访问: http://localhost:8000
echo.

%PYTHON_CMD% -m ulrattack.interface.web_server

pause

