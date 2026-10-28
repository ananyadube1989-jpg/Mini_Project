@echo off
setlocal
cd /d "%~dp0"

rem Use javac from PATH, or fall back to a JDK 21 in %USERPROFILE%\.jdks
where javac >nul 2>nul
if errorlevel 1 (
    for /d %%D in ("%USERPROFILE%\.jdks\jdk-21*") do set "PATH=%%D\bin;%PATH%"
)

where javac >nul 2>nul
if errorlevel 1 (
    echo JDK not found. Install JDK 17 or newer and try again.
    exit /b 1
)

if not exist out mkdir out

echo Compiling...
javac -encoding UTF-8 -d out -cp "lib/*" *.java
if errorlevel 1 exit /b 1

echo Starting server - open http://localhost:8080 in your browser
java -cp "out;lib/*" WebServer
