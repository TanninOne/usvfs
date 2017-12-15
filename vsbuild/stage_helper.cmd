@echo off
echo ^> Staging %1 ...
shift

:loop
if "%1"=="" goto done
if "%2"=="" goto error
echo f | xcopy /F/Y "%1" "%2" | find " -> "
shift
shift
goto loop

:error
echo stage_helper: source "%1" has no destination?!
exit /b 1

:done
