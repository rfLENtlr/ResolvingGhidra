@echo off

set PROJECT_DIR=%CD%
set CLIENT_DIR=%PROJECT_DIR%\client
set DYMAORIO_DIR="C:\Tools\DynamoRIO-Windows-9.0.1"
set EXECUTABLE=MurMurHash2A.exe

IF NOT EXIST "build" (
    mkdir build
)
cd %CLIENT_DIR%\..
IF NOT EXIST "out" (
    mkdir out
)

cd %CLIENT_DIR%\build
cmake -DDynamoRIO_DIR=%DYMAORIO_DIR%\cmake\ ..
cd %CLIENT_DIR%
cmake --build %CLIENT_DIR%\build
%DYMAORIO_DIR%\bin32\drrun.exe -c %CLIENT_DIR%\build\Debug\dr_client.dll -- %PROJECT_DIR%\samples\%EXECUTABLE%

timeout /t 1

cd %PROJECT_DIR%
set GHIDRA_PATH=C:\Tools\ghidra_11.1.2_PUBLIC\support\analyzeHeadless.bat
set REPO_NAME=ghidra_repo
set EXECUTABLE=%PROJECT_DIR%\samples\%EXECUTABLE%
set SCRIPT_PATH=ghidra_scripts
set SCRIPT_NAME=emulate_by_step_observation.java

%GHIDRA_PATH% %PROJECT_DIR% %REPO_NAME% -import %EXECUTABLE% -scriptPath %SCRIPT_PATH% -postScript %SCRIPT_NAME%

pause