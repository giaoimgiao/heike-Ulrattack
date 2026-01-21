@echo off
chcp 65001 >nul
echo ========================================
echo 从 Docker 容器复制文件到本地
echo ========================================
echo.

REM 查找运行中的容器
echo [1/3] 查找 ULRATTACK 容器...
for /f "tokens=*" %%i in ('docker ps -q -f name^=ulrattack-scan') do set CONTAINER_ID=%%i

if "%CONTAINER_ID%"=="" (
    echo ❌ 未找到运行中的容器
    echo    请先启动 ULRATTACK 任务
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('docker ps --format "{{.Names}}" -f id^=%CONTAINER_ID%') do set CONTAINER_NAME=%%i

echo ✅ 找到容器: %CONTAINER_NAME%
echo    ID: %CONTAINER_ID%
echo.

REM 提取任务名称
for /f "tokens=3 delims=-" %%i in ("%CONTAINER_NAME%") do set RUN_NAME=%%i

echo [2/3] 检查容器内文件...
docker exec %CONTAINER_ID% ls -lah /workspace/ulrattack_runs
echo.

REM 创建本地目录
if not exist "ulrattack_runs\%RUN_NAME%" mkdir "ulrattack_runs\%RUN_NAME%"

echo [3/3] 复制文件到本地...
echo 目标目录: ulrattack_runs\%RUN_NAME%\
echo.

REM 复制整个 ulrattack_runs 目录
docker cp %CONTAINER_ID%:/workspace/ulrattack_runs/. ulrattack_runs\%RUN_NAME%\

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo ✅ 复制成功！
    echo ========================================
    echo.
    echo 文件位置: %CD%\ulrattack_runs\%RUN_NAME%\
    echo.
    dir /s ulrattack_runs\%RUN_NAME%
    echo.
    echo 按任意键打开文件夹...
    pause >nul
    explorer ulrattack_runs\%RUN_NAME%
) else (
    echo.
    echo ❌ 复制失败
)

pause

