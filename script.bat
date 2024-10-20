@echo off
set PROJECT_DIR=%CD%
set GHIDRA_PATH=C:\Tools\ghidra_11.1.2_PUBLIC\support\analyzeHeadless.bat

REM Arguments for Ghidra headless execution
set REPO_NAME=ghidra_repo
set EXECUTABLE=%PROJECT_DIR%\samples\API_hashing_2.exe
set SCRIPT_PATH=ghidra_scripts
set SCRIPT_NAME=emulate_by_step_observation.java

REM Execute Ghidra headless analysis with the specified script
%GHIDRA_PATH% %PROJECT_DIR% %REPO_NAME% -import %EXECUTABLE% -scriptPath %SCRIPT_PATH% -postScript %SCRIPT_NAME%

pause