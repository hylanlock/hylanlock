@echo off
REM ============================================================================
REM  Instala el agente de Hylanlock para el usuario actual (Windows).
REM
REM  Lo deja arrancando solo al iniciar sesion, SIN ventana negra, mediante un
REM  acceso directo en la carpeta de Inicio. El agente se queda en marcha y
REM  sincroniza cada 5 minutos (--cada 300).
REM
REM  Por que la carpeta de Inicio y no el Programador de tareas: crear una tarea
REM  "al iniciar sesion" (schtasks /SC ONLOGON) EXIGE ser administrador; un
REM  acceso directo en Inicio no lo exige y arranca igual. (Verificado en Windows
REM  el 2026-08-27: /SC ONLOGON -> "Acceso denegado" sin admin.)
REM
REM  Uso:   instalar-agente.bat           (instalar)
REM         instalar-agente.bat /quitar   (desinstalar)
REM ============================================================================
setlocal EnableDelayedExpansion

set "DESTINO=%LOCALAPPDATA%\Hylanlock"
set "CONFIG=%DESTINO%\hylanlock_agente.json"
set "HAGENTE=%DESTINO%\hylanlock-agente.pyz"
set "CADA=300"
set "STARTUP=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
set "LNK=%STARTUP%\Hylanlock Agente.lnk"

REM ---------------------------------------------------------------- desinstalar
if /i "%~1"=="/quitar" (
    if exist "%LNK%" del "%LNK%"
    echo.
    echo  Agente desinstalado: retirado del arranque automatico.
    echo  Tus archivos y tu configuracion NO se han tocado: siguen en
    echo    %DESTINO%
    echo.
    pause
    exit /b 0
)

REM ---------------------------------------------------------------- comprobaciones
REM pythonw.exe ejecuta sin abrir ventana de consola. Si no esta, se usa python.exe.
set "PYW="
for %%P in (pythonw.exe) do if not defined PYW set "PYW=%%~$PATH:P"
if not defined PYW (
    for %%P in (python.exe) do if not defined PYW set "PYW=%%~$PATH:P"
)
if not defined PYW (
    echo.
    echo  [ERROR] No encuentro Python en este equipo.
    echo.
    echo  Instalalo desde https://www.python.org/downloads/ y marca la casilla
    echo  "Add Python to PATH" durante la instalacion. Luego vuelve a ejecutar
    echo  este archivo.
    echo.
    pause
    exit /b 1
)

set "PAQUETE=%~dp0hylanlock-agente.pyz"
if not exist "%PAQUETE%" set "PAQUETE=%~dp0dist\hylanlock-agente.pyz"
if not exist "%PAQUETE%" set "PAQUETE=%~dp0hylanlock_agente.py"
if not exist "%PAQUETE%" (
    echo.
    echo  [ERROR] No encuentro el agente junto a este archivo.
    echo  Copia aqui "hylanlock-agente.pyz" y vuelve a intentarlo.
    echo.
    pause
    exit /b 1
)

REM ---------------------------------------------------------------- instalar
if not exist "%DESTINO%" mkdir "%DESTINO%"
copy /Y "%PAQUETE%" "%HAGENTE%" >nul
if errorlevel 1 (
    echo  [ERROR] No he podido copiar el agente a %DESTINO%
    pause
    exit /b 1
)

if not exist "%CONFIG%" (
    pushd "%DESTINO%"
    "%PYW%" "%HAGENTE%" --init >nul 2>&1
    popd
    echo.
    echo  Se ha creado tu configuracion en:
    echo    %CONFIG%
    echo.
    echo  Abrela con el Bloc de notas y pon la direccion del servidor y TU token
    echo  antes de arrancarlo. El token se saca en la web:
    echo    Mi perfil  ^>  Equipos sincronizados
    echo.
)

REM ------------------------------------------------ arranque automatico (Inicio)
REM Crea un acceso directo en la carpeta de Inicio que lanza pythonw (sin ventana)
REM con el agente en modo continuo. No necesita administrador. Las rutas se pasan
REM por variables de entorno para no pelear con las comillas, y la comilla doble
REM se genera con [char]34 para no romper el parseo del .bat.
set "PS=$w=New-Object -ComObject WScript.Shell;$s=$w.CreateShortcut($env:LNK);$s.TargetPath=$env:PYW;$q=[char]34;$s.Arguments=$q+$env:HAGENTE+$q+' --cada '+$env:CADA+' -c '+$q+$env:CONFIG+$q;$s.WorkingDirectory=$env:DESTINO;$s.Save()"
powershell -NoProfile -ExecutionPolicy Bypass -Command "%PS%"
if not exist "%LNK%" (
    echo  [ERROR] No he podido crear el acceso directo de arranque en la carpeta de Inicio.
    pause
    exit /b 1
)

echo.
echo  Agente instalado en %DESTINO%
echo.
echo  Arrancara solo la proxima vez que inicies sesion.
echo  Para arrancarlo ahora mismo (cuando ya hayas puesto el token):
echo     "%PYW%" "%HAGENTE%" --cada %CADA% -c "%CONFIG%"
echo.
echo  Para quitarlo:  instalar-agente.bat /quitar
echo.
pause
