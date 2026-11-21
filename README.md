# Mi Terminal

Cliente de escritorio para administrar servidores Linux. El proyecto está migrando de
Electron a Tauri 2: la interfaz web existente se mantiene y la lógica de escritorio se
está trasladando a Rust.

## Estado de la migración

La nueva aplicación Tauri ya incluye:

- Ventana Tauri con Vite y xterm.js.
- Sesiones guardadas en el directorio de datos de la app. Las contraseñas y frases de paso
  se almacenan en el llavero del sistema.
- Importación inicial de sesiones y huellas confiables guardadas por la versión Electron.
  Las credenciales cifradas no se pueden trasladar al llavero de Linux: habrá que escribir
  de nuevo cada contraseña o frase de paso.
- Consolas locales Bash, Zsh y Fish mediante pseudo-terminal.
- Conexión SSH con contraseña, clave privada o `ssh-agent`, y aceptación explícita de la
  huella del servidor en la primera conexión. Las claves OpenSSH y PuTTY `.ppk` v2/v3 se
  aceptan; las claves PuTTY se convierten en memoria y nunca se guardan descifradas.
- Túneles SSH locales y remotos, ligados a `127.0.0.1`.
- Barra de estadísticas remotas (CPU, RAM, red, uptime, usuarios y discos) en un canal
  SSH de solo lectura.
- Operaciones SFTP básicas: listar, subir, descargar, crear carpetas, renombrar y borrar; también acepta archivos arrastrados al panel.
- Edición remota: descarga a una copia temporal y sube cada guardado estable al servidor.

El servidor MCP ofrece el protocolo HTTP local autenticado, consultas de sesiones, pestañas
y consolas habilitadas, creación y apertura de sesiones y consolas, lectura del terminal,
ejecución de comandos, envío de teclas y las cinco herramientas de archivos SFTP. Las acciones requieren
confirmación explícita en Mi Terminal; se puede permitir todo hasta cerrar una pestaña.
SFTP con `sudo` sigue pendiente. El backend anterior se conserva en `src/` como referencia
mientras se completa la migración.

## Requisitos en Ubuntu 24.04

Instala los paquetes de desarrollo requeridos por Tauri y OpenSSL:

```bash
sudo apt update
sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev libglib2.0-dev build-essential curl wget file pkg-config libxdo-dev libssl-dev libdbus-1-dev libayatana-appindicator3-dev librsvg2-dev
```

Instala Rust estable 1.90 o superior con rustup desde [rustup.rs](https://rustup.rs/) y
verifica que `rustc` y `cargo` estén en el `PATH`. Esta versión mínima corresponde a Tauri
2.12, fijado actualmente por `Cargo.lock`. El frontend usa Node.js 22.12 o superior y pnpm
12.21.0.

## Desarrollo

Desde la raíz del repositorio:

```bash
pnpm install
pnpm start
```

`pnpm start` ejecuta `tauri dev`: Vite sirve el frontend y Cargo compila el proceso Rust.
Para generar el paquete DEB de Ubuntu:

```bash
pnpm run build
```

## Estructura Tauri

```text
src/renderer/       Interfaz web reutilizada y adaptador de llamadas Tauri
src-tauri/src/      Backend Rust (sesiones, llavero, PTY, SSH y SFTP)
src-tauri/tauri.conf.json
vite.config.js      Compilación del frontend
```

La app Tauri usa WebKitGTK en Linux y una interfaz webview, por lo que reduce el peso del
runtime de Chromium que incluía Electron, aunque no elimina el consumo propio del webview.
