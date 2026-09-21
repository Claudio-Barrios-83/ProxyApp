# ProxyApp

ProxyApp envía el tráfico de un ejecutable concreto por un proxy SOCKS5. El resto de los programas y la tabla de rutas de Windows no se modifican.

## Requisitos

- Windows 10 o Windows 11, 64 bits.
- Ejecutar **como administrador**. El filtro usa WinDivert para leer y reinyectar paquetes salientes IPv4 TCP/UDP, y el controlador solo carga con privilegios de administrador.
- `WinDivert.dll` y `WinDivert64.sys` en la misma carpeta que `ProxyApp.exe`. Sin esos dos archivos el interruptor del motor no arranca.
- Un proxy SOCKS5 alcanzable desde el equipo, por ejemplo `127.0.0.1` y el puerto que esté escuchando.

El manifiesto de la interfaz pide privilegios normales (`asInvoker`). Windows muestra el control de cuentas al iniciar el proceso elevado; hay que aceptar esa elevación antes de activar el motor.

## Uso rápido

1. Descomprime `ProxyApp-Windows-x64.zip`.
2. Clic derecho en `ProxyApp.exe` y elige **Ejecutar como administrador**.
3. Abre la pestaña **Reglas**. Pulsa **Examinar…**, elige el `.exe` (por ejemplo `teams.exe`), escribe la IP y el puerto del proxy y pulsa **Guardar**. Las reglas quedan en `%LocalAppData%\ProxyApp\rules.json`.
4. En el tablero, activa **Activar/Desactivar Engine**.
5. La grilla muestra hora, proceso, destino original, proxy, estado y kilobytes enviados/recibidos.
6. El icono junto al reloj ofrece **Activar**, **Desactivar**, **Abrir** y **Salir**. Cerrar la ventana la oculta; **Salir** detiene el motor.

El tráfico hacia redes locales (por ejemplo `192.168.x.x` y `10.x.x.x`) sale directo cuando la regla tiene marcada **Omitir red local**.

## Compilar en local

Hace falta el SDK de .NET 8 y PowerShell en Windows x64.

```powershell
dotnet test ProxyApp.sln -c Release
dotnet publish src/ProxyApp.UI/ProxyApp.UI.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o ./publish
./build/fetch-windivert.ps1 -OutputDirectory ./publish
```

El resultado queda en `./publish`: `ProxyApp.exe`, `WinDivert.dll` y `WinDivert64.sys`. El script descarga el ZIP oficial de WinDivert 2.2.2 y rechaza el archivo si su SHA-256 no es `63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15`.

## Integración continua

`.github/workflows/build-release.yml` corre en `windows-latest` con el SDK fijado en `global.json`. En cada push a `main` o `master`, en pull requests y al publicar un tag `v*`:

1. Ejecuta las pruebas.
2. Publica el ejecutable autocontenido de un solo archivo para `win-x64`.
3. Copia los binarios del driver junto al ejecutable.
4. Sube el artefacto `ProxyApp-Windows-x64.zip`.

Un tag como `v1.0.0` crea además un **borrador** de release en GitHub con ese ZIP. El borrador no se publica solo.

## Alcance actual

El modelo de producto (`OutboundNode`, `AppRule`, JSON y SQLite) admite SOCKS5, proxy HTTP y un adaptador de Windows (WireGuard o TAP). La ventana actual guarda reglas SOCKS5 y el túnel en ejecución completa ese tipo. Un nodo HTTP o de adaptador se conserva en el modelo y, si llega al motor, no se fuerza todavía por ese camino: el HTTP se informa en la grilla y el adaptador deja el paquete seguir su ruta normal.
