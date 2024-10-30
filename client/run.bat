@echo off

set PROJECT_DIR=%CD%
set DYMAORIO_DIR="C:\Tools\DynamoRIO-Windows-9.0.1"

IF NOT EXIST "build" (
    mkdir build
)
cd %PROJECT_DIR%\..
IF NOT EXIST "out" (
    mkdir out
)

cd %PROJECT_DIR%\build
cmake -DDynamoRIO_DIR=%DYMAORIO_DIR%\cmake\ ..
cd %PROJECT_DIR%
cmake --build %PROJECT_DIR%\build
%DYMAORIO_DIR%\bin32\drrun.exe -c %PROJECT_DIR%\build\Debug\dr_client.dll -- %PROJECT_DIR%\..\samples\API_hashing_2.exe