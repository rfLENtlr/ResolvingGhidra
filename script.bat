

REM this is an example of GhidraHeadlessScript
@echo off
REM Path to Ghidra's headless analyzer script
set GHIDRA_PATH=C:\Tools\ghidra_11.1.2_PUBLIC\support\analyzeHeadless.bat

REM Arguments for Ghidra headless execution
set PROJECT_DIR=C:\Users\joker
set REPO_NAME=ghidra_repo
set EXECUTABLE=API_hashing_2.exe
set SCRIPT_PATH=ghidra_scripts
set SCRIPT_NAME=emulate_by_step_observation.java

REM Execute Ghidra headless analysis with the specified script
%GHIDRA_PATH% %PROJECT_DIR% %REPO_NAME% -process %EXECUTABLE% -scriptPath %SCRIPT_PATH% -postScript %SCRIPT_NAME%

pause
