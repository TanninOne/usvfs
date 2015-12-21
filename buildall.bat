@echo off

set VCPATH=C:\Program Files (x86)\Microsoft Visual Studio 12.0
set QTPATH32="C:\QtSDK5\Qt5.4.0\5.4\msvc2013_opengl"
set QTPATH64="C:\QtSDK5\Qt5.4.0\5.4\msvc2013_64_opengl"
set JOMPATH="C:\QtSDK5\Qt5.4.0\Tools\QtCreator\bin"
set BUILDTYPE=RelWithDebInfo
set BUILDPATH=C:\build\usvfs
set STAGINGPATH=stage
set REBUILD=0

set GENERATOR="NMake Makefiles"

set SOURCEDIR=%CD%


if "%1" == "x86" (
	title build x86
	call :build x86 %QTPATH32%
	goto exit_on_success
) else if "%1" == "x64" (
	title build x64
	call :build x64 %QTPATH64%
	goto exit_on_success
) else (
	mkdir %BUILDPATH%\%STAGINGPATH%
	start /WAIT buildall x86
	start /WAIT buildall x64
)
GOTO :EOF


:build

set PLATFORM=%~1
set QTPATH=%~2
echo "building %PLATFORM%"

set BUILDPATHLOC=%BUILDPATH%\%BUILDTYPE%_%PLATFORM%

echo %BUILDPATHLOC%

call "%VCPATH%\VC\vcvarsall.bat" %PLATFORM%
call "%QTPATH%\bin\qtenv2"

if %REBUILD% == 1 (
	rmdir /s /q %BUILDPATHLOC%
)
mkdir %BUILDPATHLOC%

cd %BUILDPATHLOC%

set BINPATH=%BUILDPATH%\%STAGINGPATH%
cmake -G%GENERATOR% -DCMAKE_BUILD_TYPE=%BUILDTYPE% -DCMAKE_INSTALL_PREFIX=%BINPATH% %SOURCEDIR%
%JOMPATH%\jom all install
set RESVAR=%errorlevel%

mkdir %BINPATH%
rem xcopy %BUILDPATHLOC%\usvfs_proxy\usvfs_proxy_*.exe %BINPATH%
rem xcopy %BUILDPATHLOC%\usvfs_proxy\usvfs_proxy_*.pdb %BINPATH%
rem xcopy %BUILDPATHLOC%\usvfs_loader\usvfs_loader_*.exe %BINPATH%
rem xcopy %BUILDPATHLOC%\usvfs_loader\usvfs_loader_*.pdb %BINPATH%
rem xcopy %BUILDPATHLOC%\usvfs\usvfs_*.dll %BINPATH%
rem xcopy %BUILDPATHLOC%\usvfs\usvfs_*.pdb %BINPATH%

xcopy /Y %QTPATH%\bin\Qt5Core.dll %BINPATH%\bin_%PLATFORM%
xcopy /Y %QTPATH%\bin\Qt5Gui.dll %BINPATH%\bin_%PLATFORM%
xcopy /Y %QTPATH%\bin\Qt5Widgets.dll %BINPATH%\bin_%PLATFORM%
xcopy /Y %QTPATH%\bin\icu*.dll %BINPATH%\bin_%PLATFORM%

GOTO :EOF

:exit_on_success
if %RESVAR%==0 (
	exit
)
GOTO :EOF