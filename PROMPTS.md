Módulo 1: Arquitectura Base y Definición del Proyecto
Prompt 1: Blueprint y Stack Tecnológico
Copia y pega este prompt en Cursor:

"Actúa como un Ingeniero de Software Principal de Windows Kernel y Redes. Quiero construir una herramienta MVP de código abierto equivalente a Proxifier para Windows.

Objetivo del producto:
Interceptar el tráfico de red de un ejecutable específico (ej. teams.exe) y redirigirlo obligatoriamente a través de un proxy local SOCKS5 (127.0.0.1:1080), sin alterar las tablas de enrutamiento globales ni afectar a VPNs activas (como Cisco AnyConnect).

Tu tarea:

Analiza los 3 enfoques técnicos posibles en Windows:

Enfoque A: Driver WFP (Windows Filtering Platform) o biblioteca WinDivert.

Enfoque B: Winsock SPI / LSP / Layered Service Provider (o I/O Completion Ports).

Enfoque C: API Hooking de Winsock (connect, send, recv) mediante MinHook inyectado en el proceso objetivo.

Evalúa pros, contras y nivel de complejidad de cada opción.

Genera la estructura de carpetas sugerida para una solución compuesta por:

Core/Engine: C# / .NET 8 (o C++ si es necesario para el motor de bajo nivel).

UI: WPF / WinUI 3 en C#.

Socks5Handler: Módulo cliente SOCKS5.

Indica los requisitos de privilegios de usuario (Admin / System Service) necesarios para la ejecución."

Módulo 2: Motor de Intercepción de Tráfico (Core Engine)
Prompt 2: Selección e Implementación del Driver/Módulo de Intercepción
Copia y pega este prompt en Cursor:

"Vamos a implementar el motor de intercepción utilizando el enfoque de WinDivert (o WFP en modo usuario) en C# / .NET 8 mediante WinDivertSharp.

Escribe el código para ProcessNetworkFilter.cs que realice lo siguiente:

Inicie un socket de captura de WinDivert escuchando los paquetes salientes IPv4 (TCP/UDP).

Al capturar un paquete:

Obtenga el Process ID (PID) asociado a la conexión socket.

Resuelva el nombre del ejecutable a partir del PID (ej. teams.exe).

Si el ejecutable coincide con una regla activa (ej. teams.exe):

Modifique la dirección IP de destino y el puerto hacia la dirección del Proxy SOCKS5 local (127.0.0.1:1080).

Recalcule correctamente los Checksums TCP/IP (IP Header, TCP Header).

Reinyecte el paquete modificado en la pila de red.

Maneje el tráfico de retorno (SOCKS5 -> Process) deshaciendo la modificación de IP/Puerto para que la aplicación crea que se está comunicando con el servidor original.

Proporciona comentarios detallados sobre el cálculo de checksums y el manejo del handshake TCP."

Módulo 3: Cliente SOCKS5 y Tunneling Local
Prompt 3: Manejador del Túnel SOCKS5 (Handshake RFC 1928)
Copia y pega este prompt en Cursor:

"Crea una clase en C# llamada Socks5Client.cs que implemente el protocolo SOCKS5 completo (RFC 1928) para gestionar las conexiones tunnelizadas.

Funcionalidades requeridas:

Handshake de Autenticación: Soporte para NO AUTHENTICATION REQUIRED (0x00) y opcionalmente usuario/contraseña (0x02).

Comando CONNECT (0x01):

Método ConnectAsync(string targetHost, int targetPort)

Soporte para tipos de dirección: IPv4 (0x01) y Domain Name / FQDN (0x03) para evitar fugas de DNS (DNS leak).

Forwarding Asíncrono de Datos:

Crea un pipeline bidireccional de alto rendimiento (System.IO.Pipelines o NetworkStream.CopyToAsync) entre la aplicación cliente y el servidor SOCKS5.

Manejo de Errores y Reconexión:

Tratamiento de timeouts, conexión rechazada por el proxy y cierres abruptos de socket.

Escribe código limpio, asíncrono (async/await) y fuertemente tipado en .NET 8."

Módulo 4: Motor de Reglas (Rule Engine)
Prompt 4: Gestor de Reglas de Enrutamiento
Copia y pega este prompt en Cursor:

"Diseña e implementa el motor de reglas en una clase llamada RoutingRuleEngine.cs.

Especificaciones:

Estructura de una Regla (Rule.cs):

RuleId (Guid)

ProcessName (string, ej: 'teams.exe', 'chrome.exe', soporta comodines *)

TargetProxy (Objeto con Host, Port, Type [SOCKS5/HTTP], Auth)

IsEnabled (bool)

BypassLocalNetwork (bool, omite proxies para rangos 192.168.x.x o 10.x.x.x)

Método principal Evaluator.GetProxyForProcess(string processName, string targetIp, int targetPort):

Retorna el proxy correspondiente si hay match o Proxy.Direct si no aplica ninguna regla.

Persistencia:

Métodos LoadRulesFromJson(string path) y SaveRulesToJson(string path).

Incluye pruebas unitarias básicas con xUnit para verificar el matching por nombre de ejecutable."

Módulo 5: Interfaz de Usuario y Monitor en Tiempo Real
Prompt 5: UI con WPF / Modern UI y Notificaciones de Tray Bar
Copia y pega este prompt en Cursor:

"Crea la interfaz de usuario en WPF (.NET 8) utilizando CommunityToolkit.Mvvm con un diseño moderno en modo oscuro.

Vistas requeridas:

Dashboard Principal:

Datagrid con el tráfico interceptado en vivo: [Hora] | [Proceso] | [Destino Original] | [Proxy Usado] | [Estado] | [KB Enviados/Recibidos].

Toggle principal: 'Activar/Desactivar Engine'.

Gestor de Reglas:

Formulario para agregar/editar reglas (Seleccionar .exe mediante OpenFileDialog, IP del Proxy y Puerto).

Bandeja del Sistema (System Tray):

Icono al lado del reloj de Windows con menú contextual: Activar, Desactivar, Abrir, Salir.

Implementa MainViewModel.cs conectando el ProcessNetworkFilter y el RoutingRuleEngine con notificaciones ObservableCollection para actualización fluida de la lista en tiempo real."

Módulo 6: Automatización de la Infraestructura WireGuard en OCI
Prompt 6: Script de despliegue del Proxy SOCKS5 en Oracle Cloud
Copia y pega este prompt en Cursor:

"Para completar la solución de extremo a extremo, crea los archivos de configuración para desplegar la contraparte del proxy en nuestro servidor de Oracle Cloud Infrastructure (OCI).

Entrega:

docker-compose.yml:

Contenedor ligero SOCKS5 (ej. dante-server o microsocks).

Configurado para aceptar únicamente conexiones autenticadas o restringidas por IP.

Exposición del puerto 1080.

Script Bash setup-socks5-wireguard.sh:

Instala Docker en la VPS de OCI (Ubuntu/Debian).

Configura las reglas del Firewall de Oracle Cloud (IPTables / UFW) para autorizar el tráfico entrante al puerto 1080 o a través de la interfaz de WireGuard.

Comando SSH Tunneling (Alternativa sin Docker):

Muestra el comando exacto de SSH Dinámico (ssh -N -D 0.0.0.0:1080 ...) y cómo empaquetarlo en un servicio de Windows (NSSM) para que el túnel SOCKS5 corra automáticamente en segundo plano al arrancar Windows."

Recomendación de flujo en Cursor:
Abre una carpeta vacía en Cursor y crea una solución de .NET (dotnet new sln).

Utiliza el Prompt 1 en el Chat de Cursor (Ctrl+L / Cmd+L) para definir la estructura.

Avanza prompt a prompt usando el modo Composer / Agent (Ctrl+I) para que Cursor genere los archivos de código directamente en tu espacio de trabajo.