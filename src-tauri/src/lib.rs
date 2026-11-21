use base64::{engine::general_purpose::STANDARD, Engine};
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
use aes::Aes256;
use argon2::{Algorithm as ArgonAlgorithm, Argon2, Params as ArgonParams, Version as ArgonVersion};
use hmac::{Hmac, Mac};
use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::{
    collections::{HashMap, HashSet},
    fs,
    hash::{Hash, Hasher},
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::mpsc::{self, Sender},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime},
};
use tauri::{Emitter, Manager, State};
use tauri_plugin_clipboard_manager::ClipboardExt;

#[derive(Default)]
struct AppState {
    ptys: Arc<Mutex<HashMap<String, LocalPty>>>,
    ssh: Arc<Mutex<HashMap<String, SshConnection>>>,
    agent: Arc<AgentRuntime>,
    mcp_server: Mutex<Option<McpServer>>,
    mcp_error: Mutex<String>,
}

#[derive(Default)]
struct AgentRuntime {
    output: Mutex<HashMap<String, String>>,
    activity: Mutex<HashMap<String, Instant>>,
    permissions: Mutex<HashMap<String, AgentPermission>>,
    approvals: Mutex<HashMap<String, Sender<String>>>,
    ui_requests: Mutex<HashMap<String, Sender<Result<String, String>>>>,
    approval_lock: Mutex<()>,
    busy: Mutex<HashSet<String>>,
}

#[derive(Default)]
struct AgentPermission {
    read: bool,
    all: bool,
}

struct SshConnection {
    session_id: String,
    sftp_sudo: bool,
    session: Arc<Mutex<ssh2::Session>>,
    channel: Arc<Mutex<ssh2::Channel>>,
    tunnel_stops: Vec<Arc<AtomicBool>>,
    stop: Arc<AtomicBool>,
}

struct SshChannelReader(Arc<Mutex<ssh2::Channel>>);
struct SshChannelWriter(Arc<Mutex<ssh2::Channel>>);

impl Read for SshChannelReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::Other, "SSH channel lock poisoned")
            })?
            .read(buf)
    }
}

impl Write for SshChannelWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::Other, "SSH channel lock poisoned")
            })?
            .write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0
            .lock()
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::Other, "SSH channel lock poisoned")
            })?
            .flush()
    }
}

struct LocalPty {
    master: Box<dyn MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    child: Box<dyn portable_pty::Child + Send + Sync>,
}

impl Drop for LocalPty {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

impl Drop for SshConnection {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for stop in &self.tunnel_stops {
            stop.store(true, Ordering::Relaxed);
        }
        if let Ok(mut channel) = self.channel.lock() {
            let _ = channel.close();
        }
    }
}

fn retry_ssh<T>(mut operation: impl FnMut() -> Result<T, ssh2::Error>) -> Result<T, String> {
    let started = Instant::now();
    loop {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error) if error.code() == ssh2::ErrorCode::Session(-37) => {
                if started.elapsed() > Duration::from_secs(30) {
                    return Err("Tiempo agotado esperando respuesta del servidor SSH".into());
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}

fn write_retry(writer: &mut impl Write, mut bytes: &[u8]) -> Result<(), String> {
    let mut last_progress = Instant::now();
    while !bytes.is_empty() {
        match writer.write(bytes) {
            Ok(0) => return Err("No se pudo escribir en el canal SSH".into()),
            Ok(written) => {
                bytes = &bytes[written..];
                last_progress = Instant::now();
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if last_progress.elapsed() > Duration::from_secs(30) {
                    return Err("Tiempo agotado escribiendo al servidor SSH".into());
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}

fn tunnel_copy(reader: &mut impl Read, writer: &mut impl Write, stop: &AtomicBool) {
    let mut buf = [0u8; 16 * 1024];
    while !stop.load(Ordering::Relaxed) {
        let count = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        let mut sent = 0;
        while sent < count && !stop.load(Ordering::Relaxed) {
            match writer.write(&buf[sent..count]) {
                Ok(0) => return,
                Ok(size) => sent += size,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return,
            }
        }
    }
}

fn bridge_socket(socket: TcpStream, channel: ssh2::Channel, stop: Arc<AtomicBool>) {
    let channel = Arc::new(Mutex::new(channel));
    let mut local_reader = match socket.try_clone() {
        Ok(reader) => reader,
        Err(_) => return,
    };
    let _ = local_reader.set_read_timeout(Some(Duration::from_millis(100)));
    let send_channel = channel.clone();
    let send_stop = stop.clone();
    thread::spawn(move || {
        tunnel_copy(
            &mut local_reader,
            &mut SshChannelWriter(send_channel.clone()),
            &send_stop,
        );
        if let Ok(mut channel) = send_channel.lock() {
            let _ = channel.send_eof();
        }
    });

    let mut local_writer = socket;
    tunnel_copy(
        &mut SshChannelReader(channel.clone()),
        &mut local_writer,
        &stop,
    );
    let _ = local_writer.shutdown(Shutdown::Write);
    stop.store(true, Ordering::Relaxed);
    if let Ok(mut channel) = channel.lock() {
        let _ = channel.close();
    };
}

fn start_tunnels(
    app: tauri::AppHandle,
    conn_id: String,
    session: Arc<Mutex<ssh2::Session>>,
    tunnels: Vec<serde_json::Value>,
) -> Vec<Arc<AtomicBool>> {
    let mut stops = Vec::new();
    for tunnel in tunnels {
        let mode = tunnel["type"].as_str().unwrap_or("L");
        let Some(src_port) = tunnel["srcPort"]
            .as_u64()
            .and_then(|p| u16::try_from(p).ok())
        else {
            let _ = app.emit(
                "ssh:status",
                serde_json::json!([conn_id.clone(), "Puerto de túnel inválido."]),
            );
            continue;
        };
        let Some(dst_port) = tunnel["dstPort"]
            .as_u64()
            .and_then(|p| u16::try_from(p).ok())
        else {
            let _ = app.emit(
                "ssh:status",
                serde_json::json!([conn_id.clone(), "Puerto de destino inválido."]),
            );
            continue;
        };
        if src_port == 0 || dst_port == 0 {
            let _ = app.emit(
                "ssh:status",
                serde_json::json!([
                    conn_id.clone(),
                    "El puerto de túnel debe ser mayor que cero."
                ]),
            );
            continue;
        }
        let Some(dst_host) = tunnel["dstHost"]
            .as_str()
            .filter(|h| !h.is_empty())
            .map(str::to_owned)
        else {
            let _ = app.emit(
                "ssh:status",
                serde_json::json!([conn_id.clone(), "Falta el host de destino del túnel."]),
            );
            continue;
        };
        let stop = Arc::new(AtomicBool::new(false));

        let status_dst_host = dst_host.clone();
        if mode == "R" {
            let listener = retry_ssh(|| {
                session.lock().unwrap().channel_forward_listen(
                    src_port,
                    Some("127.0.0.1"),
                    Some(32),
                )
            });
            match listener {
                Ok((mut listener, bound_port)) => {
                    let worker_stop = stop.clone();
                    let worker_session = session.clone();
                    thread::spawn(move || {
                        while !worker_stop.load(Ordering::Relaxed) {
                            match listener.accept() {
                                Ok(channel) => {
                                    let worker_stop = worker_stop.clone();
                                    let destination = dst_host.clone();
                                    thread::spawn(move || {
                                        match TcpStream::connect((destination.as_str(), dst_port)) {
                                            Ok(socket) => {
                                                bridge_socket(socket, channel, worker_stop)
                                            }
                                            Err(_) => {
                                                let mut channel = channel;
                                                let _ = channel.close();
                                            }
                                        }
                                    });
                                }
                                Err(error) if error.code() == ssh2::ErrorCode::Session(-37) => {
                                    thread::sleep(Duration::from_millis(20));
                                }
                                Err(_) => break,
                            }
                        }
                        drop(listener);
                        drop(worker_session);
                    });
                    stops.push(stop);
                    let _ = app.emit(
                        "ssh:status",
                        serde_json::json!([
                            conn_id.clone(),
                            format!("Túnel remoto {bound_port} → {status_dst_host}:{dst_port} activo.")
                        ]),
                    );
                }
                Err(error) => {
                    let _ = app.emit(
                        "ssh:status",
                        serde_json::json!([
                            conn_id.clone(),
                            format!("No se pudo abrir el túnel remoto: {error}")
                        ]),
                    );
                }
            }
        } else {
            match TcpListener::bind(("127.0.0.1", src_port)) {
                Ok(listener) => {
                    let _ = listener.set_nonblocking(true);
                    let worker_stop = stop.clone();
                    let worker_session = session.clone();
                    thread::spawn(move || {
                        while !worker_stop.load(Ordering::Relaxed) {
                            match listener.accept() {
                                Ok((socket, _)) => {
                                    let worker_stop = worker_stop.clone();
                                    let worker_session = worker_session.clone();
                                    let destination = dst_host.clone();
                                    thread::spawn(move || {
                                        let channel = retry_ssh(|| {
                                            worker_session.lock().unwrap().channel_direct_tcpip(
                                                &destination,
                                                dst_port,
                                                Some(("127.0.0.1", src_port)),
                                            )
                                        });
                                        match channel {
                                            Ok(channel) => {
                                                bridge_socket(socket, channel, worker_stop)
                                            }
                                            Err(_) => {
                                                let _ = socket.shutdown(Shutdown::Both);
                                            }
                                        }
                                    });
                                }
                                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                    thread::sleep(Duration::from_millis(20));
                                }
                                Err(_) => break,
                            }
                        }
                    });
                    stops.push(stop);
                    let _ = app.emit(
                        "ssh:status",
                        serde_json::json!([
                            conn_id.clone(),
                            format!(
                                "Túnel local 127.0.0.1:{src_port} → {status_dst_host}:{dst_port} activo."
                            )
                        ]),
                    );
                }
                Err(error) => {
                    let _ = app.emit(
                        "ssh:status",
                        serde_json::json!([
                            conn_id.clone(),
                            format!("No se pudo abrir el túnel local: {error}")
                        ]),
                    );
                }
            }
        }
    }
    stops
}

const STATS_SCRIPT: &str = r#"export LC_ALL=C
while :; do
  echo "@@H $(hostname)"
  head -n1 /proc/stat | sed 's/^/@@C /'
  grep -E '^(MemTotal|MemAvailable):' /proc/meminfo | sed 's/^/@@M /'
  awk 'NR>2 { gsub(":", " "); print "@@N", $1, $2, $10 }' /proc/net/dev
  echo "@@U $(cut -d' ' -f1 /proc/uptime)"
  echo "@@W $(who 2>/dev/null | awk '{print $1}' | sort | uniq -c | tr -s ' ' | tr '\n' ',')"
  df -P -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs 2>/dev/null | awk 'NR>1 { print "@@D", $6, $5 }'
  echo "@@E"
  sleep 2
done"#;

struct RawStats {
    at: Instant,
    cpu_total: u64,
    cpu_idle: u64,
    rx: u64,
    tx: u64,
}

fn parse_stats_block(block: &str, previous: &mut Option<RawStats>) -> serde_json::Value {
    let mut host = String::new();
    let mut mem_total = 0u64;
    let mut mem_available = 0u64;
    let mut uptime = 0f64;
    let mut cpu_total = 0u64;
    let mut cpu_idle = 0u64;
    let mut rx = 0u64;
    let mut tx = 0u64;
    let mut users = Vec::new();
    let mut disks = Vec::new();

    for line in block.lines() {
        let mut fields = line.split_whitespace();
        let Some(tag) = fields.next() else { continue };
        let rest: Vec<&str> = fields.collect();
        match tag {
            "@@H" => host = rest.join(" "),
            "@@C" => {
                let values: Vec<u64> = rest
                    .iter()
                    .skip(1)
                    .map(|n| n.parse().unwrap_or(0))
                    .collect();
                if values.len() >= 4 {
                    cpu_idle = values[3] + values.get(4).copied().unwrap_or(0);
                    cpu_total = values.iter().take(8).sum();
                }
            }
            "@@M" if rest.len() >= 2 => {
                let kb = rest[1].parse::<u64>().unwrap_or(0).saturating_mul(1024);
                if rest[0] == "MemTotal:" {
                    mem_total = kb;
                }
                if rest[0] == "MemAvailable:" {
                    mem_available = kb;
                }
            }
            "@@N" if rest.len() >= 3 => {
                let iface = rest[0];
                let virtual_iface = [
                    "lo", "docker", "veth", "br-", "virbr", "cni", "flannel", "cali", "vxlan",
                    "kube",
                ]
                .iter()
                .any(|prefix| iface.starts_with(prefix));
                if !virtual_iface {
                    rx = rx.saturating_add(rest[1].parse::<u64>().unwrap_or(0));
                    tx = tx.saturating_add(rest[2].parse::<u64>().unwrap_or(0));
                }
            }
            "@@U" => uptime = rest.first().and_then(|v| v.parse().ok()).unwrap_or(0.0),
            "@@W" => {
                for entry in rest.join(" ").split(',') {
                    let values: Vec<&str> = entry.split_whitespace().collect();
                    if values.len() >= 2 {
                        if let Ok(count) = values[0].parse::<u64>() {
                            users.push(serde_json::json!({"name": values[1], "count": count}));
                        }
                    }
                }
            }
            "@@D" if rest.len() >= 2 => {
                let pct = rest[1].trim_end_matches('%').parse::<u64>().unwrap_or(0);
                disks.push(serde_json::json!({"mount": rest[0], "pct": pct}));
            }
            _ => {}
        }
    }

    let now = Instant::now();
    let mut cpu = None;
    let mut up = None;
    let mut down = None;
    if let Some(old) = previous.as_ref() {
        let total_delta = cpu_total.saturating_sub(old.cpu_total);
        let idle_delta = cpu_idle.saturating_sub(old.cpu_idle);
        if total_delta > 0 {
            cpu = Some(((1.0 - idle_delta as f64 / total_delta as f64) * 100.0).clamp(0.0, 100.0));
        }
        let elapsed = now.duration_since(old.at).as_secs_f64();
        if elapsed > 0.0 {
            down = Some(rx.saturating_sub(old.rx) as f64 * 8.0 / elapsed);
            up = Some(tx.saturating_sub(old.tx) as f64 * 8.0 / elapsed);
        }
    }
    *previous = Some(RawStats {
        at: now,
        cpu_total,
        cpu_idle,
        rx,
        tx,
    });
    serde_json::json!({
        "host": host,
        "memTotal": mem_total,
        "memUsed": mem_total.saturating_sub(mem_available),
        "uptime": uptime,
        "users": users,
        "disks": disks,
        "cpu": cpu,
        "up": up,
        "down": down
    })
}

fn start_stats(
    app: tauri::AppHandle,
    conn_id: String,
    session: Arc<Mutex<ssh2::Session>>,
    stop: Arc<AtomicBool>,
) {
    thread::spawn(move || {
        let Ok(mut channel) = retry_ssh(|| session.lock().unwrap().channel_session()) else {
            return;
        };
        if channel
            .handle_extended_data(ssh2::ExtendedData::Merge)
            .is_err()
            || retry_ssh(|| channel.exec(STATS_SCRIPT)).is_err()
        {
            return;
        }
        let mut previous = None;
        let mut buffered = Vec::<u8>::new();
        let mut chunk = [0u8; 4096];
        while !stop.load(Ordering::Relaxed) {
            match channel.read(&mut chunk) {
                Ok(0) => break,
                Ok(size) => buffered.extend_from_slice(&chunk[..size]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
            while let Some(end) = buffered.windows(3).position(|w| w == b"@@E") {
                let block = String::from_utf8_lossy(&buffered[..end]).to_string();
                buffered.drain(..end + 3);
                let value = parse_stats_block(&block, &mut previous);
                let _ = app.emit("ssh:stats", serde_json::json!([conn_id.clone(), value]));
            }
            if buffered.len() > 64 * 1024 {
                buffered.clear();
            }
        }
        let _ = channel.close();
    });
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionRecord {
    id: String,
    name: String,
    #[serde(default)]
    folder: String,
    host: String,
    #[serde(default = "default_port")]
    port: u16,
    username: String,
    #[serde(default = "default_auth")]
    auth_type: String,
    #[serde(default)]
    key_path: String,
    #[serde(default)]
    tunnels: Vec<serde_json::Value>,
    #[serde(default)]
    sftp_sudo: bool,
    #[serde(default)]
    allow_agents: bool,
    #[serde(default)]
    has_password: bool,
    #[serde(default)]
    has_passphrase: bool,
}

fn default_port() -> u16 {
    22
}
fn default_auth() -> String {
    "password".into()
}

fn sessions_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("sessions.json"))
}

fn known_hosts_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("known_hosts.json"))
}

fn settings_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("settings.json"))
}

fn selected_editor(app: &tauri::AppHandle) -> Result<Option<PathBuf>, String> {
    let path = settings_path(app)?;
    let settings: serde_json::Value = fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    if settings["editor"].as_str() == Some("system") {
        return Ok(None);
    }
    if let Some(path) = settings["editor"].as_str().map(PathBuf::from) {
        if path.is_file() {
            return Ok(Some(path));
        }
    }
    for candidate in ["code", "code-oss"] {
        if let Some(path) = executable_path(candidate) {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

fn executable_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")?
        .to_string_lossy()
        .split(':')
        .map(|dir| PathBuf::from(dir).join(name))
        .find(|path| {
            path.metadata()
                .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        })
}

fn persist_settings(app: &tauri::AppHandle, settings: &serde_json::Value) -> Result<(), String> {
    let path = settings_path(app)?;
    let temp = path.with_extension("json.tmp");
    fs::write(
        &temp,
        serde_json::to_vec_pretty(settings).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    fs::rename(temp, path).map_err(|e| e.to_string())
}

fn read_known_hosts(app: &tauri::AppHandle) -> Result<HashMap<String, String>, String> {
    let path = known_hosts_path(app)?;
    match fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text).map_err(|e| e.to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let legacy = dirs::config_dir()
                .unwrap_or_default()
                .join("mi-terminal/known_hosts.json");
            let Ok(text) = fs::read_to_string(legacy) else {
                return Ok(HashMap::new());
            };
            let known: HashMap<String, String> =
                serde_json::from_str(&text).map_err(|e| e.to_string())?;
            fs::write(
                path,
                serde_json::to_vec_pretty(&known).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            Ok(known)
        }
        Err(error) => Err(error.to_string()),
    }
}

fn read_sessions(app: &tauri::AppHandle) -> Result<Vec<SessionRecord>, String> {
    let path = sessions_path(app)?;
    match fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).map_err(|e| e.to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Importa los metadatos de las sesiones de Electron. Sus secretos cifrados
            // no son compatibles con el llavero de Linux y se volverán a pedir al conectar.
            let legacy = dirs::config_dir()
                .unwrap_or_default()
                .join("mi-terminal/sessions.json");
            let Ok(text) = fs::read_to_string(legacy) else {
                return Ok(Vec::new());
            };
            let mut imported: Vec<SessionRecord> =
                serde_json::from_str(&text).map_err(|e| e.to_string())?;
            for session in &mut imported {
                session.has_password = false;
                session.has_passphrase = false;
                session.sftp_sudo = false;
            }
            write_sessions(app, &imported)?;
            Ok(imported)
        }
        Err(e) => Err(e.to_string()),
    }
}

fn write_sessions(app: &tauri::AppHandle, sessions: &[SessionRecord]) -> Result<(), String> {
    let path = sessions_path(app)?;
    let temp = path.with_extension("json.tmp");
    fs::write(
        &temp,
        serde_json::to_vec_pretty(sessions).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    fs::rename(temp, path).map_err(|e| e.to_string())
}

#[tauri::command]
fn home_dir() -> String {
    dirs::home_dir()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

#[tauri::command]
fn sessions_list(app: tauri::AppHandle) -> Result<Vec<SessionRecord>, String> {
    read_sessions(&app)
}

#[tauri::command]
fn sessions_save(app: tauri::AppHandle, input: serde_json::Value) -> Result<SessionRecord, String> {
    let mut sessions = read_sessions(&app)?;
    let id = input
        .get("id")
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{}", rand::random::<u128>()));
    let prev = sessions.iter().find(|s| s.id == id).cloned();
    let auth_type = input
        .get("authType")
        .and_then(|v| v.as_str())
        .unwrap_or("password")
        .to_owned();
    let port = input
        .get("port")
        .and_then(|v| v.as_u64())
        .filter(|p| (1..=u16::MAX as u64).contains(p))
        .ok_or("El puerto debe estar entre 1 y 65535")? as u16;
    let host = input
        .get("host")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let username = input
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if host.is_empty() || username.is_empty() {
        return Err("El host y el usuario son obligatorios".into());
    }
    let secret =
        keyring::Entry::new("mi-terminal", &format!("password:{id}")).map_err(|e| e.to_string())?;
    if let Some(password) = input
        .get("password")
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())
    {
        secret.set_password(password).map_err(|e| e.to_string())?;
    } else if input.get("password").is_some() {
        let _ = secret.delete_credential();
    }
    if auth_type != "password" {
        let _ = secret.delete_credential();
    }
    let pass_entry = keyring::Entry::new("mi-terminal", &format!("passphrase:{id}"))
        .map_err(|e| e.to_string())?;
    if let Some(passphrase) = input
        .get("passphrase")
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())
    {
        pass_entry
            .set_password(passphrase)
            .map_err(|e| e.to_string())?;
    } else if input.get("passphrase").is_some() {
        let _ = pass_entry.delete_credential();
    }
    if auth_type != "key" {
        let _ = pass_entry.delete_credential();
    }
    let record = SessionRecord {
        id: id.clone(),
        name: input
            .get("name")
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| {
                input
                    .get("host")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Nueva sesión")
            })
            .to_owned(),
        folder: input
            .get("folder")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned(),
        host: host.to_owned(),
        port,
        username: username.to_owned(),
        auth_type: auth_type.clone(),
        key_path: input
            .get("keyPath")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned(),
        tunnels: input
            .get("tunnels")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default(),
        sftp_sudo: false,
        allow_agents: input
            .get("allowAgents")
            .and_then(|v| v.as_bool())
            .unwrap_or_else(|| prev.as_ref().map(|s| s.allow_agents).unwrap_or(false)),
        has_password: auth_type == "password"
            && input
                .get("password")
                .and_then(|v| v.as_str())
                .map(|s| !s.is_empty())
                .unwrap_or_else(|| prev.as_ref().map(|s| s.has_password).unwrap_or(false)),
        has_passphrase: auth_type == "key"
            && input
                .get("passphrase")
                .and_then(|v| v.as_str())
                .map(|s| !s.is_empty())
                .unwrap_or_else(|| prev.as_ref().map(|s| s.has_passphrase).unwrap_or(false)),
    };
    if let Some(index) = sessions.iter().position(|s| s.id == id) {
        sessions[index] = record.clone();
    } else {
        sessions.push(record.clone());
    }
    write_sessions(&app, &sessions)?;
    Ok(record)
}

#[tauri::command]
fn sessions_delete(app: tauri::AppHandle, id: String) -> Result<(), String> {
    let sessions: Vec<_> = read_sessions(&app)?
        .into_iter()
        .filter(|s| s.id != id)
        .collect();
    write_sessions(&app, &sessions)?;
    for kind in ["password", "passphrase"] {
        if let Ok(entry) = keyring::Entry::new("mi-terminal", &format!("{kind}:{id}")) {
            let _ = entry.delete_credential();
        }
    }
    Ok(())
}

#[tauri::command]
fn local_shells() -> Vec<serde_json::Value> {
    [("bash", "Bash"), ("zsh", "Zsh"), ("fish", "Fish")]
        .into_iter()
        .filter_map(|(id, name)| {
            let path = std::env::var_os("PATH")?
                .to_string_lossy()
                .split(':')
                .map(|p| PathBuf::from(p).join(id))
                .find(|p| {
                    p.metadata()
                        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                        .unwrap_or(false)
                })?;
            Some(serde_json::json!({"id": id, "name": name, "path": path}))
        })
        .collect()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LocalOpen {
    conn_id: String,
    shell_id: String,
    cols: u16,
    rows: u16,
}

#[tauri::command]
fn local_open(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    opts: LocalOpen,
) -> Result<(), String> {
    let shell = local_shells()
        .into_iter()
        .find(|s| s["id"] == opts.shell_id)
        .ok_or("Shell no disponible")?;
    let path = shell["path"].as_str().ok_or("Ruta de shell inválida")?;
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: opts.rows.max(1),
            cols: opts.cols.max(1),
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| e.to_string())?;
    let mut command = CommandBuilder::new(path);
    if opts.shell_id == "bash" || opts.shell_id == "fish" {
        command.arg("-l");
    }
    if opts.shell_id == "zsh" {
        command.arg("-l");
    }
    command.arg("-i");
    command.cwd(dirs::home_dir().unwrap_or_else(|| PathBuf::from("/")));
    let child = pair
        .slave
        .spawn_command(command)
        .map_err(|e| e.to_string())?;
    drop(pair.slave);
    let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
    let writer = pair.master.take_writer().map_err(|e| e.to_string())?;
    let id = opts.conn_id.clone();
    let pty_map = state.ptys.clone();
    let agent = state.agent.clone();
    state.ptys.lock().map_err(|e| e.to_string())?.insert(
        id.clone(),
        LocalPty {
            master: pair.master,
            writer,
            child,
        },
    );
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let data = String::from_utf8_lossy(&buf[..n]).to_string();
                    record_terminal_data(&agent, &id, &data);
                    let _ = app.emit("ssh:data", (&id, data));
                }
            }
        }
        let _ = app.emit("ssh:closed", &id);
        pty_map.lock().ok().map(|mut map| map.remove(&id));
        clear_agent_tab(&agent, &id);
    });
    Ok(())
}

#[tauri::command]
fn terminal_write(state: State<'_, AppState>, id: String, data: String) -> Result<(), String> {
    if let Some(pty) = state.ptys.lock().map_err(|e| e.to_string())?.get_mut(&id) {
        pty.writer
            .write_all(data.as_bytes())
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    if let Some(ssh) = state.ssh.lock().map_err(|e| e.to_string())?.get(&id) {
        write_retry(
            &mut *ssh.channel.lock().map_err(|e| e.to_string())?,
            data.as_bytes(),
        )?;
        return Ok(());
    }
    Err("La conexión SSH aún no está disponible en esta compilación Tauri".into())
}

fn record_terminal_data(agent: &AgentRuntime, id: &str, data: &str) {
    if let Ok(mut output) = agent.output.lock() {
        let text = output.entry(id.to_owned()).or_default();
        text.push_str(data);
        if text.len() > 120_000 {
            let mut start = text.len() - 120_000;
            while !text.is_char_boundary(start) {
                start += 1;
            }
            text.drain(..start);
        }
    }
    if let Ok(mut activity) = agent.activity.lock() {
        activity.insert(id.to_owned(), Instant::now());
    }
}

fn clear_agent_tab(agent: &AgentRuntime, id: &str) {
    if let Ok(mut output) = agent.output.lock() {
        output.remove(id);
    }
    if let Ok(mut activity) = agent.activity.lock() {
        activity.remove(id);
    }
    if let Ok(mut permissions) = agent.permissions.lock() {
        permissions.remove(id);
    }
    if let Ok(mut busy) = agent.busy.lock() {
        busy.remove(id);
    }
}

#[tauri::command]
fn terminal_resize(
    state: State<'_, AppState>,
    id: String,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    if let Some(pty) = state.ptys.lock().map_err(|e| e.to_string())?.get_mut(&id) {
        pty.master
            .resize(PtySize {
                rows: rows.max(1),
                cols: cols.max(1),
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| e.to_string())?;
    }
    if let Some(ssh) = state.ssh.lock().map_err(|e| e.to_string())?.get(&id) {
        ssh.channel
            .lock()
            .map_err(|e| e.to_string())?
            .request_pty_size(cols.max(1).into(), rows.max(1).into(), Some(0), Some(0))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn terminal_disconnect(state: State<'_, AppState>, id: String) {
    if let Some(mut pty) = state.ptys.lock().unwrap().remove(&id) {
        let _ = pty.child.kill();
    }
    if let Some(ssh) = state.ssh.lock().unwrap().remove(&id) {
        if let Ok(mut channel) = ssh.channel.lock() {
            let _ = channel.close();
        }
    }
    clear_agent_tab(&state.agent, &id);
}

fn ssh_string(value: &[u8]) -> Result<Vec<u8>, String> {
    let length = u32::try_from(value.len()).map_err(|_| "Campo de clave demasiado largo")?;
    let mut encoded = Vec::with_capacity(4 + value.len());
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(value);
    Ok(encoded)
}

fn read_ssh_strings(data: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut fields = Vec::new();
    let mut cursor = 0;
    while cursor < data.len() {
        if cursor + 4 > data.len() {
            return Err("Archivo .ppk dañado: campo incompleto".into());
        }
        let length = u32::from_be_bytes(data[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        let end = cursor.checked_add(length).ok_or("Archivo .ppk demasiado grande")?;
        if end > data.len() {
            return Err("Archivo .ppk dañado: campo incompleto".into());
        }
        fields.push(data[cursor..end].to_vec());
        cursor = end;
    }
    Ok(fields)
}

fn ppk_to_openssh(text: &str, passphrase: &str) -> Result<Option<String>, String> {
    if !text.starts_with("PuTTY-User-Key-File-") {
        return Ok(None);
    }
    if text.len() > 10 * 1024 * 1024 {
        return Err("El archivo .ppk supera el límite de 10 MB".into());
    }
    let mut lines = text.lines();
    let header = lines.next().ok_or("Archivo .ppk vacío")?;
    let (version, algorithm) = header
        .strip_prefix("PuTTY-User-Key-File-")
        .and_then(|value| value.split_once(": "))
        .ok_or("No se reconoce el encabezado de la clave PuTTY")?;
    let version: u8 = version.parse().map_err(|_| "Versión .ppk no válida")?;
    if version != 2 && version != 3 {
        return Err("Solo se admiten claves PuTTY v2 y v3".into());
    }

    let mut fields = HashMap::<String, String>::new();
    let mut public_blob = Vec::new();
    let mut private_blob = Vec::new();
    let remaining: Vec<&str> = lines.collect();
    let mut index = 0;
    while index < remaining.len() {
        let Some((name, value)) = remaining[index].split_once(": ") else {
            index += 1;
            continue;
        };
        if name == "Public-Lines" || name == "Private-Lines" {
            let count: usize = value.parse().map_err(|_| "Archivo .ppk dañado: número de líneas no válido")?;
            let block_end = index.checked_add(count).ok_or("Archivo .ppk dañado: bloque demasiado largo")?;
            if count > 100_000 || block_end >= remaining.len() {
                return Err("Archivo .ppk dañado: bloque incompleto".into());
            }
            let encoded = remaining[index + 1..index + 1 + count].concat();
            let decoded = STANDARD.decode(encoded).map_err(|_| "Archivo .ppk dañado: Base64 no válido")?;
            if name == "Public-Lines" { public_blob = decoded; } else { private_blob = decoded; }
            index += count + 1;
        } else {
            fields.insert(name.to_owned(), value.to_owned());
            index += 1;
        }
    }

    let encryption = fields.get("Encryption").ok_or("Archivo .ppk dañado: falta Encryption")?;
    let comment = fields.get("Comment").map(String::as_str).unwrap_or("");
    let mut mac_key = Vec::new();
    if encryption != "none" {
        if encryption != "aes256-cbc" {
            return Err(format!("Cifrado .ppk no soportado: {encryption}"));
        }
        if passphrase.is_empty() {
            return Err("La clave PuTTY está cifrada; falta la frase de paso (passphrase)".into());
        }
        let mut key = Vec::new();
        let iv;
        if version == 2 {
            for sequence in 0u32..2 {
                let mut digest = Sha1::new();
                digest.update(sequence.to_be_bytes());
                digest.update(passphrase.as_bytes());
                key.extend_from_slice(&digest.finalize());
            }
            let mut digest = Sha1::new();
            digest.update(b"putty-private-key-file-mac-key");
            digest.update(passphrase.as_bytes());
            mac_key = digest.finalize().to_vec();
            iv = [0u8; 16];
        } else {
            let derivation = fields.get("Key-Derivation").map(|value| value.to_ascii_lowercase()).unwrap_or_default();
            let algorithm = match derivation.as_str() {
                "argon2id" => ArgonAlgorithm::Argon2id,
                "argon2i" => ArgonAlgorithm::Argon2i,
                "argon2d" => ArgonAlgorithm::Argon2d,
                _ => return Err("Método Argon2 no admitido en la clave .ppk".into()),
            };
            let parse_parameter = |name: &str| -> Result<u32, String> {
                fields.get(name).ok_or_else(|| format!("Falta {name} en la clave .ppk"))?
                    .parse::<u32>().map_err(|_| format!("Valor {name} no válido en la clave .ppk"))
            };
            let memory = parse_parameter("Argon2-Memory")?;
            let passes = parse_parameter("Argon2-Passes")?;
            let parallelism = parse_parameter("Argon2-Parallelism")?;
            if memory > 1_048_576 || passes > 64 || parallelism > 32 {
                return Err("Los parámetros Argon2 de la clave .ppk exceden el límite de seguridad".into());
            }
            let salt = hex_bytes(fields.get("Argon2-Salt").ok_or("Falta Argon2-Salt en la clave .ppk")?)?;
            let params = ArgonParams::new(memory, passes, parallelism, Some(80)).map_err(|e| e.to_string())?;
            let argon = Argon2::new(algorithm, ArgonVersion::V0x13, params);
            let mut output = [0u8; 80];
            argon.hash_password_into(passphrase.as_bytes(), &salt, &mut output).map_err(|e| e.to_string())?;
            key.extend_from_slice(&output[..32]);
            iv = output[32..48].try_into().unwrap();
            mac_key.extend_from_slice(&output[48..80]);
        }
        if private_blob.len() % 16 != 0 {
            return Err("Archivo .ppk dañado: bloque cifrado incompleto".into());
        }
        let cipher = Aes256::new_from_slice(&key).map_err(|_| "Clave AES no válida")?;
        let mut previous = iv;
        for chunk in private_blob.chunks_exact_mut(16) {
            let current: [u8; 16] = chunk.try_into().map_err(|_| "Bloque AES no válido")?;
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher.decrypt_block(&mut block);
            for (value, prior) in block.iter_mut().zip(previous) { *value ^= prior; }
            chunk.copy_from_slice(&block);
            previous = current;
        }
    } else if version == 2 {
        let digest = Sha1::digest(b"putty-private-key-file-mac-key");
        mac_key.extend_from_slice(&digest);
    }

    let mut mac_data = Vec::new();
    for item in [algorithm.as_bytes(), encryption.as_bytes(), comment.as_bytes(), public_blob.as_slice(), private_blob.as_slice()] {
        mac_data.extend_from_slice(&ssh_string(item)?);
    }
    if version == 2 {
        let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&mac_key).map_err(|e| e.to_string())?;
        mac.update(&mac_data);
        let expected = hex_bytes(fields.get("Private-MAC").ok_or("Falta Private-MAC en la clave .ppk")?)?;
        mac.verify_slice(&expected).map_err(|_| ppk_mac_error(encryption))?;
    } else {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&mac_key).map_err(|e| e.to_string())?;
        mac.update(&mac_data);
        let expected = hex_bytes(fields.get("Private-MAC").ok_or("Falta Private-MAC en la clave .ppk")?)?;
        mac.verify_slice(&expected).map_err(|_| ppk_mac_error(encryption))?;
    }

    let public_fields = read_ssh_strings(&public_blob)?;
    let private_fields = read_ssh_strings(&private_blob)?;
    if public_fields.first().map(Vec::as_slice) != Some(algorithm.as_bytes()) {
        return Err("El tipo de clave no coincide con el contenido del .ppk".into());
    }
    let private_key_fields: Vec<Vec<u8>> = match algorithm {
        "ssh-rsa" if public_fields.len() >= 3 && private_fields.len() >= 4 => vec![
            public_fields[2].clone(), public_fields[1].clone(), private_fields[0].clone(), private_fields[3].clone(), private_fields[1].clone(), private_fields[2].clone(),
        ],
        "ssh-ed25519" if public_fields.len() >= 2 && private_fields.len() >= 1 => {
            let mut private = private_fields[0].clone();
            private.extend_from_slice(&public_fields[1]);
            vec![public_fields[1].clone(), private]
        }
        value if value.starts_with("ecdsa-sha2-") && public_fields.len() >= 3 && private_fields.len() >= 1 => vec![
            public_fields[1].clone(), public_fields[2].clone(), private_fields[0].clone(),
        ],
        "ssh-rsa" | "ssh-ed25519" => return Err("Archivo .ppk dañado: faltan campos de clave".into()),
        value if value.starts_with("ecdsa-sha2-") => return Err("Archivo .ppk dañado: faltan campos de clave".into()),
        _ => return Err(format!("Tipo de clave PuTTY no soportado: {algorithm}")),
    };

    let mut private_section = Vec::new();
    let check: [u8; 4] = rand::random();
    private_section.extend_from_slice(&check);
    private_section.extend_from_slice(&check);
    private_section.extend_from_slice(&ssh_string(algorithm.as_bytes())?);
    for field in private_key_fields { private_section.extend_from_slice(&ssh_string(&field)?); }
    private_section.extend_from_slice(&ssh_string(comment.as_bytes())?);
    let padding = 8 - private_section.len() % 8;
    if padding < 8 { private_section.extend((1..=padding).map(|value| value as u8)); }

    let mut body = b"openssh-key-v1\0".to_vec();
    body.extend_from_slice(&ssh_string(b"none")?);
    body.extend_from_slice(&ssh_string(b"none")?);
    body.extend_from_slice(&ssh_string(b"")?);
    body.extend_from_slice(&1u32.to_be_bytes());
    body.extend_from_slice(&ssh_string(&public_blob)?);
    body.extend_from_slice(&ssh_string(&private_section)?);
    let encoded = STANDARD.encode(body);
    let lines = encoded.as_bytes().chunks(70).map(|line| std::str::from_utf8(line).unwrap()).collect::<Vec<_>>().join("\n");
    Ok(Some(format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{lines}\n-----END OPENSSH PRIVATE KEY-----\n")))
}

fn hex_bytes(value: &str) -> Result<Vec<u8>, String> {
    if !value.is_ascii() || value.len() % 2 != 0 { return Err("Archivo .ppk dañado: valor hexadecimal no válido".into()); }
    (0..value.len()).step_by(2).map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(|_| "Archivo .ppk dañado: valor hexadecimal no válido".into())).collect()
}

fn ppk_mac_error(encryption: &str) -> String {
    if encryption == "none" { "El archivo .ppk está dañado".into() } else { "Frase de paso incorrecta".into() }
}

#[tauri::command]
async fn ssh_connect(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    opts: serde_json::Value,
) -> Result<(), String> {
    let ssh_map = state.ssh.clone();
    let agent = state.agent.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let conn_id = opts["connId"].as_str().ok_or("Falta connId")?.to_owned();
        let session_id = opts["sessionId"].as_str().ok_or("Falta sessionId")?;
        let record = read_sessions(&app)?
            .into_iter()
            .find(|s| s.id == session_id)
            .ok_or("Sesión no encontrada")?;
        let socket = (record.host.as_str(), record.port)
            .to_socket_addrs()
            .map_err(|e| e.to_string())?
            .next()
            .ok_or("No se pudo resolver el servidor")?;
        let stream = TcpStream::connect_timeout(&socket, Duration::from_secs(15))
            .map_err(|e| e.to_string())?;
        stream.set_nodelay(true).map_err(|e| e.to_string())?;
        let mut session = ssh2::Session::new().map_err(|e| e.to_string())?;
        session.set_tcp_stream(stream);
        session.handshake().map_err(|e| e.to_string())?;
        let key = session
            .host_key_hash(ssh2::HashType::Sha256)
            .map(|h| format!("SHA256:{}", STANDARD.encode(h).trim_end_matches('=')))
            .ok_or("No se pudo leer la huella del servidor")?;
        let host_id = format!("[{}]:{}", record.host, record.port);
        let known = read_known_hosts(&app)?;
        if known.get(&host_id) != Some(&key) {
            let tag = if known.contains_key(&host_id) {
                "HOST_KEY_CHANGED"
            } else {
                "HOST_KEY_UNTRUSTED"
            };
            return Err(format!("{tag}|{host_id}|{key}"));
        }
        let override_secret = opts["password"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let secret_id = format!(
            "{}:{}",
            if record.auth_type == "key" {
                "passphrase"
            } else {
                "password"
            },
            record.id
        );
        let saved_secret = keyring::Entry::new("mi-terminal", &secret_id)
            .ok()
            .and_then(|e| e.get_password().ok());
        let secret = override_secret.or(saved_secret);
        let auth = match record.auth_type.as_str() {
            "password" => session
                .userauth_password(&record.username, secret.as_deref().unwrap_or(""))
                .map_err(|e| e.to_string()),
            "key" => {
                let text = fs::read_to_string(&record.key_path)
                    .map_err(|_| format!("No se pudo leer el archivo de clave: {}", record.key_path))?;
                let converted = ppk_to_openssh(&text, secret.as_deref().unwrap_or(""))
                    .map_err(|error| {
                        if error.contains("passphrase") || error == "Frase de paso incorrecta" {
                            format!("{error} (passphrase)")
                        } else {
                            error
                        }
                    })?;
                if let Some(private_key) = converted {
                    session.userauth_pubkey_memory(&record.username, None, &private_key, None)
                } else {
                    session.userauth_pubkey_memory(
                        &record.username,
                        None,
                        &text,
                        secret.as_deref(),
                    )
                }
                .map_err(|error| {
                    let message = error.to_string();
                    if message.to_ascii_lowercase().contains("passphrase")
                        || message.to_ascii_lowercase().contains("decrypt")
                    {
                        format!("La clave está protegida: falta la frase de paso o es incorrecta (passphrase)")
                    } else {
                        message
                    }
                })
            }
            "agent" => {
                let mut agent = session.agent().map_err(|e| e.to_string())?;
                agent.connect().map_err(|e| e.to_string())?;
                agent.list_identities().map_err(|e| e.to_string())?;
                let identities = agent.identities().map_err(|e| e.to_string())?;
                let mut accepted = false;
                for identity in identities {
                    if agent.userauth(&record.username, &identity).is_ok() {
                        accepted = true;
                        break;
                    }
                }
                if accepted {
                    Ok(())
                } else {
                    Err("No hay una identidad SSH aceptada por el servidor".into())
                }
            }
            _ => return Err("Método de autenticación desconocido".into()),
        };
        auth?;
        if !session.authenticated() {
            return Err("Autenticación SSH fallida".into());
        }
        let mut channel = session.channel_session().map_err(|e| e.to_string())?;
        let cols = opts["cols"].as_u64().unwrap_or(80) as u32;
        let rows = opts["rows"].as_u64().unwrap_or(24) as u32;
        channel
            .request_pty("xterm-256color", None, Some((cols, rows, 0, 0)))
            .map_err(|e| e.to_string())?;
        channel
            .handle_extended_data(ssh2::ExtendedData::Merge)
            .map_err(|e| e.to_string())?;
        channel.shell().map_err(|e| e.to_string())?;
        session.set_blocking(false);
        let session = Arc::new(Mutex::new(session));
        let connection_stop = Arc::new(AtomicBool::new(false));
        let tunnel_stops = start_tunnels(
            app.clone(),
            conn_id.clone(),
            session.clone(),
            record.tunnels.clone(),
        );
        let channel = Arc::new(Mutex::new(channel));
        ssh_map.lock().map_err(|e| e.to_string())?.insert(
            conn_id.clone(),
            SshConnection {
                session_id: record.id.clone(),
                sftp_sudo: record.sftp_sudo,
                session: session.clone(),
                channel: channel.clone(),
                tunnel_stops,
                stop: connection_stop.clone(),
            },
        );
        start_stats(app.clone(), conn_id.clone(), session, connection_stop);
        let reader_map = ssh_map.clone();
        let reader_agent = agent.clone();
        thread::spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                let result = channel.lock().map(|mut ch| ch.read(&mut buf));
                match result {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => {
                        let data = String::from_utf8_lossy(&buf[..n]).to_string();
                        record_terminal_data(&reader_agent, &conn_id, &data);
                        let _ = app.emit("ssh:data", serde_json::json!([conn_id.clone(), data]));
                    }
                    Ok(Err(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20))
                    }
                    _ => break,
                }
            }
            let _ = app.emit("ssh:closed", &conn_id);
            reader_map.lock().ok().map(|mut m| m.remove(&conn_id));
            clear_agent_tab(&reader_agent, &conn_id);
        });
        Ok(())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn known_host_trust(
    app: tauri::AppHandle,
    host_id: String,
    fingerprint: String,
) -> Result<(), String> {
    let path = known_hosts_path(&app)?;
    let mut known = read_known_hosts(&app)?;
    if known.contains_key(&host_id) {
        return Err("La huella guardada es distinta. Cambia la entrada de known_hosts.json solo después de verificarla por un canal seguro.".into());
    }
    known.insert(host_id, fingerprint);
    fs::write(
        path,
        serde_json::to_vec_pretty(&known).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

fn sftp_for(state: &AppState, id: &str) -> Result<ssh2::Sftp, String> {
    let connections = state.ssh.lock().map_err(|error| error.to_string())?;
    let connection = connections.get(id).ok_or("Sin conexión SSH")?;
    let session = connection.session.lock().map_err(|error| error.to_string())?;
    retry_ssh(|| session.sftp())
}

#[tauri::command]
fn sftp_set_sudo(app: tauri::AppHandle, state: State<'_, AppState>, id: String, on: bool) -> Result<(), String> {
    if on {
        return Err("SFTP con sudo aún no está disponible en esta versión.".into());
    }
    let mut connections = state.ssh.lock().map_err(|error| error.to_string())?;
    let connection = connections.get_mut(&id).ok_or("Sin conexión SSH")?;
    let session_id = connection.session_id.clone();
    let mut sessions = read_sessions(&app)?;
    let session = sessions.iter_mut().find(|session| session.id == session_id).ok_or("No se encontró la sesión guardada")?;
    session.sftp_sudo = false;
    write_sessions(&app, &sessions)?;
    connection.sftp_sudo = false;
    Ok(())
}

fn sftp_for_map(ssh: &Arc<Mutex<HashMap<String, SshConnection>>>, id: &str) -> Result<ssh2::Sftp, String> {
    let connections = ssh.lock().map_err(|error| error.to_string())?;
    let connection = connections.get(id).ok_or("Sin conexión SSH")?;
    let session = connection.session.lock().map_err(|error| error.to_string())?;
    retry_ssh(|| session.sftp())
}

fn read_retry(reader: &mut impl Read, buffer: &mut [u8]) -> Result<usize, String> {
    let started = Instant::now();
    loop {
        match reader.read(buffer) {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if started.elapsed() > Duration::from_secs(30) {
                    return Err("Tiempo agotado leyendo el archivo remoto".into());
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Ok(count) => return Ok(count),
            Err(error) => return Err(error.to_string()),
        }
    }
}

fn sftp_copy_to_writer(
    source: &mut impl Read,
    writer: &mut impl Write,
    app: Option<&tauri::AppHandle>,
    id: &str,
    name: &str,
    size: u64,
) -> Result<u64, String> {
    let mut copied = 0;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = read_retry(source, &mut buffer)?;
        if count == 0 { break; }
        write_retry(writer, &buffer[..count])?;
        copied += count as u64;
        if let Some(app) = app {
            let _ = app.emit("sftp:progress", (id, name, copied, size));
        }
    }
    Ok(copied)
}

fn sftp_copy_from_reader(
    reader: &mut impl Read,
    destination: &mut impl Write,
    app: Option<&tauri::AppHandle>,
    id: &str,
    name: &str,
    size: u64,
) -> Result<u64, String> {
    let mut copied = 0;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer).map_err(|error| error.to_string())?;
        if count == 0 { break; }
        write_retry(destination, &buffer[..count])?;
        copied += count as u64;
        if let Some(app) = app {
            let _ = app.emit("sftp:progress", (id, name, copied, size));
        }
    }
    Ok(copied)
}

#[tauri::command]
fn sftp_home(state: State<'_, AppState>, id: String) -> Result<String, String> {
    let sftp = sftp_for(&state, &id)?;
    retry_ssh(|| sftp.realpath(Path::new("."))).map(|path| path.to_string_lossy().into_owned())
}

#[tauri::command]
fn sftp_list(state: State<'_, AppState>, id: String, dir: String) -> Result<Vec<serde_json::Value>, String> {
    let sftp = sftp_for(&state, &id)?;
    let entries = retry_ssh(|| sftp.readdir(Path::new(&dir)))?;
    let mut items = Vec::new();
    for (path, stat) in entries {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else { continue; };
        if name == "." || name == ".." { continue; }
        let mode = stat.perm.unwrap_or(0);
        items.push(serde_json::json!({
            "name": name,
            "isDir": mode & 0o170000 == 0o040000,
            "isLink": mode & 0o170000 == 0o120000,
            "size": stat.size.unwrap_or(0),
            "mtime": stat.mtime.unwrap_or(0) * 1000
        }));
    }
    items.sort_by(|a, b| b["isDir"].as_bool().cmp(&a["isDir"].as_bool()).then_with(|| a["name"].as_str().cmp(&b["name"].as_str())));
    Ok(items)
}

#[tauri::command]
fn sftp_download(app: tauri::AppHandle, state: State<'_, AppState>, id: String, remote_path: String, local_path: String) -> Result<String, String> {
    let sftp = sftp_for(&state, &id)?;
    let stat = retry_ssh(|| sftp.stat(Path::new(&remote_path)))?;
    let mut source = retry_ssh(|| sftp.open(Path::new(&remote_path)))?;
    let name = Path::new(&remote_path).file_name().and_then(|name| name.to_str()).unwrap_or("archivo");
    let mut destination = fs::File::create(&local_path).map_err(|error| error.to_string())?;
    sftp_copy_to_writer(&mut source, &mut destination, Some(&app), &id, name, stat.size.unwrap_or(0))?;
    Ok(local_path)
}

#[tauri::command]
fn sftp_upload(app: tauri::AppHandle, state: State<'_, AppState>, id: String, remote_dir: String, local_paths: Vec<String>) -> Result<usize, String> {
    let sftp = sftp_for(&state, &id)?;
    for local in &local_paths {
        let source_path = Path::new(local);
        if !source_path.is_absolute() { return Err("La ruta local del archivo debe ser absoluta".into()); }
        let metadata = fs::metadata(source_path).map_err(|error| error.to_string())?;
        if !metadata.is_file() { return Err(format!("No es un archivo normal: {}", source_path.display())); }
        let name = source_path.file_name().ok_or("Nombre de archivo inválido")?;
        let remote = Path::new(&remote_dir).join(name);
        let mut source = fs::File::open(source_path).map_err(|error| error.to_string())?;
        let mut destination = retry_ssh(|| sftp.create(&remote))?;
        sftp_copy_from_reader(&mut source, &mut destination, Some(&app), &id, &name.to_string_lossy(), metadata.len())?;
    }
    Ok(local_paths.len())
}

#[tauri::command]
fn sftp_mkdir(state: State<'_, AppState>, id: String, remote_path: String) -> Result<(), String> {
    let sftp = sftp_for(&state, &id)?;
    retry_ssh(|| sftp.mkdir(Path::new(&remote_path), 0o755))
}

#[tauri::command]
fn sftp_remove(state: State<'_, AppState>, id: String, remote_path: String, is_dir: bool) -> Result<(), String> {
    let sftp = sftp_for(&state, &id)?;
    retry_ssh(|| if is_dir { sftp.rmdir(Path::new(&remote_path)) } else { sftp.unlink(Path::new(&remote_path)) })
}

#[tauri::command]
fn sftp_rename(state: State<'_, AppState>, id: String, from: String, to: String) -> Result<(), String> {
    let sftp = sftp_for(&state, &id)?;
    retry_ssh(|| sftp.rename(Path::new(&from), Path::new(&to), None))
}

#[derive(Clone, PartialEq, Eq)]
struct LocalFileVersion {
    size: u64,
    modified: SystemTime,
    inode: u64,
}

fn local_file_version(path: &Path) -> Option<LocalFileVersion> {
    let metadata = fs::metadata(path).ok()?;
    Some(LocalFileVersion {
        size: metadata.len(),
        modified: metadata.modified().ok()?,
        inode: metadata.ino(),
    })
}

fn upload_edited_file(
    session: &Arc<Mutex<ssh2::Session>>,
    remote_path: &str,
    local_path: &Path,
) -> Result<(), String> {
    let session_guard = session.lock().map_err(|e| e.to_string())?;
    let sftp = retry_ssh(|| session_guard.sftp())?;
    drop(session_guard);
    let mut source = fs::File::open(local_path).map_err(|e| e.to_string())?;
    let mut destination = retry_ssh(|| sftp.create(Path::new(remote_path)))?;
    sftp_copy_from_reader(&mut source, &mut destination, None, "", "", 0)?;
    Ok(())
}

fn watch_remote_edit(
    app: tauri::AppHandle,
    conn_id: String,
    remote_path: String,
    local_path: PathBuf,
    session: Arc<Mutex<ssh2::Session>>,
    stop: Arc<AtomicBool>,
    baseline: Option<LocalFileVersion>,
) {
    let mut last_uploaded = baseline;
    thread::spawn(move || {
        let mut candidate: Option<LocalFileVersion> = None;
        while !stop.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(500));
            let Some(current) = local_file_version(&local_path) else {
                candidate = None;
                continue;
            };
            if Some(current.clone()) == last_uploaded {
                candidate = None;
                continue;
            }
            if candidate.as_ref() != Some(&current) {
                candidate = Some(current);
                continue;
            }
            let result = upload_edited_file(&session, &remote_path, &local_path);
            let error = result.err();
            if error.is_none() {
                last_uploaded = Some(current);
            } else {
                // Report one failure per saved version; another edit will trigger a retry.
                last_uploaded = Some(current);
            }
            candidate = None;
            let _ = app.emit(
                "sftp:edited",
                serde_json::json!([conn_id.clone(), remote_path.clone(), error]),
            );
        }
    });
}

fn is_runnable_without_editor(name: &str) -> bool {
    let extension = Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    [
        "appimage", "bat", "bash", "bin", "command", "com", "csh", "desktop", "deb", "exe", "jar",
        "js", "mjs", "msi", "pl", "py", "pyw", "rb", "rpm", "run", "sh", "so", "zsh",
    ]
    .contains(&extension.as_str())
}

#[tauri::command]
fn sftp_edit(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    id: String,
    remote_path: String,
) -> Result<String, String> {
    let (session, stop) = {
        let connections = state.ssh.lock().map_err(|e| e.to_string())?;
        let connection = connections.get(&id).ok_or("Sin conexión SSH")?;
        (connection.session.clone(), connection.stop.clone())
    };
    let remote_name = Path::new(&remote_path)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("Nombre de archivo remoto inválido")?;
    let editor = selected_editor(&app)?;
    if editor.is_none() && is_runnable_without_editor(remote_name) {
        return Err(format!(
            "{remote_name} es ejecutable; elige un editor explícito o descarga el archivo."
        ));
    }

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    id.hash(&mut hasher);
    remote_path.hash(&mut hasher);
    let local_dir = app
        .path()
        .temp_dir()
        .map_err(|e| e.to_string())?
        .join("mi-terminal-edit")
        .join(format!("{:016x}", hasher.finish()));
    fs::create_dir_all(&local_dir).map_err(|e| e.to_string())?;
    let safe_name: String = remote_name
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '/' | '\\') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let local_name = if safe_name.is_empty() {
        "archivo".to_owned()
    } else {
        safe_name
    };
    let local_path = local_dir.join(local_name);
    let sftp = sftp_for(&state, &id)?;
    let total = retry_ssh(|| sftp.stat(Path::new(&remote_path)))?.size.unwrap_or(0);
    let mut source = retry_ssh(|| sftp.open(Path::new(&remote_path)))?;
    let mut destination = fs::File::create(&local_path).map_err(|e| e.to_string())?;
    sftp_copy_to_writer(&mut source, &mut destination, None, &id, remote_name, total)?;
    drop(destination);
    let baseline = local_file_version(&local_path);

    let program = editor.clone().unwrap_or_else(|| {
        executable_path("xdg-open").unwrap_or_else(|| PathBuf::from("xdg-open"))
    });
    std::process::Command::new(&program)
        .arg(&local_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("No se pudo abrir el editor: {e}"))?;

    watch_remote_edit(app, id, remote_path, local_path, session, stop, baseline);
    Ok(editor
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "Predeterminado de Linux".into()))
}

#[tauri::command]
fn editor_get(app: tauri::AppHandle) -> Result<String, String> {
    Ok(selected_editor(&app)?
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "Predeterminado de Linux".into()))
}

#[tauri::command]
fn editor_set(app: tauri::AppHandle, editor_path: String) -> Result<String, String> {
    let path = PathBuf::from(editor_path);
    let metadata = fs::metadata(&path).map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err("El editor elegido no es un ejecutable.".into());
    }
    let mut settings: serde_json::Value = fs::read_to_string(settings_path(&app)?)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    settings["editor"] = serde_json::Value::String(path.to_string_lossy().into_owned());
    persist_settings(&app, &settings)?;
    editor_get(app)
}

#[tauri::command]
fn editor_use_system(app: tauri::AppHandle) -> Result<String, String> {
    let mut settings: serde_json::Value = fs::read_to_string(settings_path(&app)?)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    settings["editor"] = serde_json::Value::String("system".into());
    persist_settings(&app, &settings)?;
    editor_get(app)
}

const MCP_PORT: u16 = 47821;
const MCP_MAX_BODY: usize = 6 * 1024 * 1024;

struct McpServer {
    stop: Arc<AtomicBool>,
}

impl Drop for McpServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

struct McpClientGuard(Arc<AtomicUsize>);

impl Drop for McpClientGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

fn mcp_settings(app: &tauri::AppHandle) -> Result<serde_json::Value, String> {
    let settings: serde_json::Value = fs::read_to_string(settings_path(app)?)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    let stored = &settings["mcp"];
    Ok(serde_json::json!({
        "enabled": stored["enabled"].as_bool().unwrap_or(false),
        "allowLocal": stored["allowLocal"].as_bool().unwrap_or(false),
        "approval": "app",
        "port": MCP_PORT
    }))
}

fn save_mcp_settings(
    app: &tauri::AppHandle,
    enabled: bool,
    allow_local: bool,
) -> Result<(), String> {
    let path = settings_path(app)?;
    let mut settings: serde_json::Value = fs::read_to_string(&path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    settings["mcp"] = serde_json::json!({
        "enabled": enabled,
        "allowLocal": allow_local,
        "approval": "app",
        "port": MCP_PORT
    });
    persist_settings(app, &settings)
}

fn mcp_token() -> Result<String, String> {
    let entry = keyring::Entry::new("mi-terminal", "mcp:token").map_err(|e| e.to_string())?;
    if let Ok(token) = entry.get_password() {
        return Ok(token);
    }
    let random: [u8; 32] = rand::random();
    let token = random.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    entry.set_password(&token).map_err(|e| e.to_string())?;
    Ok(token)
}

fn stop_mcp_server(state: &AppState) {
    if let Ok(mut server) = state.mcp_server.lock() {
        if let Some(server) = server.take() {
            server.stop.store(true, Ordering::Relaxed);
        }
    }
    if let Ok(mut pending) = state.agent.approvals.lock() {
        for (_, sender) in pending.drain() {
            let _ = sender.send("deny".into());
        }
    }
    if let Ok(mut pending) = state.agent.ui_requests.lock() {
        for (_, sender) in pending.drain() {
            let _ = sender.send(Err("El acceso MCP fue desactivado".into()));
        }
    }
}

fn sync_mcp_server(app: &tauri::AppHandle, state: &AppState) -> Result<(), String> {
    stop_mcp_server(state);
    let settings = mcp_settings(app)?;
    if !settings["enabled"].as_bool().unwrap_or(false) {
        *state.mcp_error.lock().map_err(|e| e.to_string())? = String::new();
        let tabs: Vec<String> = state.agent.permissions.lock().map_err(|e| e.to_string())?.drain().map(|(tab, _)| tab).collect();
        for tab in tabs {
            let _ = app.emit("agent:perm", serde_json::json!([tab, false]));
        }
        return Ok(());
    }
    let token = mcp_token()?;
    let listener = TcpListener::bind(("127.0.0.1", MCP_PORT)).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AddrInUse {
            format!("El puerto {MCP_PORT} está ocupado por otro programa.")
        } else {
            error.to_string()
        }
    })?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();
    let app_handle = app.clone();
    let ssh = state.ssh.clone();
    let ptys = state.ptys.clone();
    let agent = state.agent.clone();
    let active_clients = Arc::new(AtomicUsize::new(0));
    thread::spawn(move || {
        while !thread_stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    if active_clients.fetch_add(1, Ordering::Relaxed) >= 32 {
                        active_clients.fetch_sub(1, Ordering::Relaxed);
                        let mut stream = stream;
                        write_http(&mut stream, 429, &serde_json::json!({"error":"Demasiadas conexiones locales"}), None);
                        continue;
                    }
                    let token = token.clone();
                    let app = app_handle.clone();
                    let ssh = ssh.clone();
                    let ptys = ptys.clone();
                    let agent = agent.clone();
                    let clients = active_clients.clone();
                    let stop = thread_stop.clone();
                    thread::spawn(move || {
                        let _guard = McpClientGuard(clients);
                        handle_mcp_client(stream, token, app, ssh, ptys, agent, stop);
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(_) => break,
            }
        }
    });
    *state.mcp_server.lock().map_err(|e| e.to_string())? = Some(McpServer { stop });
    *state.mcp_error.lock().map_err(|e| e.to_string())? = String::new();
    Ok(())
}

fn mcp_state_json(app: &tauri::AppHandle, state: &AppState) -> Result<serde_json::Value, String> {
    let settings = mcp_settings(app)?;
    let running = state
        .mcp_server
        .lock()
        .map_err(|e| e.to_string())?
        .is_some();
    let error = state.mcp_error.lock().map_err(|e| e.to_string())?.clone();
    Ok(serde_json::json!({
        "enabled": settings["enabled"],
        "allowLocal": settings["allowLocal"],
        "approval": settings["approval"],
        "running": running,
        "error": error,
        "url": format!("http://127.0.0.1:{MCP_PORT}/mcp")
    }))
}

#[tauri::command]
fn mcp_get(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    mcp_state_json(&app, &state)
}

#[tauri::command]
fn mcp_set(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    change: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let enabled = change["enabled"].as_bool().unwrap_or(false);
    let allow_local = enabled && change["allowLocal"].as_bool().unwrap_or(false);
    save_mcp_settings(&app, enabled, allow_local)?;
    if let Err(error) = sync_mcp_server(&app, &state) {
        *state.mcp_error.lock().map_err(|e| e.to_string())? = error;
    }
    mcp_state_json(&app, &state)
}

#[tauri::command]
fn mcp_new_token(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let entry = keyring::Entry::new("mi-terminal", "mcp:token").map_err(|e| e.to_string())?;
    let random: [u8; 32] = rand::random();
    let token = random.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    entry.set_password(&token).map_err(|e| e.to_string())?;
    if let Err(error) = sync_mcp_server(&app, &state) {
        *state.mcp_error.lock().map_err(|e| e.to_string())? = error;
    }
    mcp_state_json(&app, &state)
}

#[tauri::command]
fn mcp_copy(app: tauri::AppHandle, kind: String) -> Result<(), String> {
    let settings = mcp_settings(&app)?;
    if !settings["enabled"].as_bool().unwrap_or(false) {
        return Err("Activa primero el acceso de agentes.".into());
    }
    let token = mcp_token()?;
    let url = format!("http://127.0.0.1:{MCP_PORT}/mcp");
    let auth = format!("Bearer {token}");
    let text = match kind.as_str() {
        "claude" => format!("claude mcp add --transport http mi-terminal {url} --header \"Authorization: {auth}\""),
        "cursor" => serde_json::to_string_pretty(&serde_json::json!({"mcpServers":{"mi-terminal":{"url":url,"headers":{"Authorization":auth}}}})).map_err(|e| e.to_string())?,
        "codex" => format!("[mcp_servers.mi-terminal]\nurl = \"{url}\"\nhttp_headers = {{ \"Authorization\" = \"{auth}\" }}\n"),
        "token" => token,
        _ => return Err("Opción no válida".into()),
    };
    app.clipboard().write_text(text).map_err(|e| e.to_string())
}

fn mcp_tools() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({"name":"list_sessions","description":"Lista las sesiones SSH guardadas que el usuario habilitó para agentes. No incluye contraseñas ni claves.","inputSchema":{"type":"object","properties":{},"additionalProperties":false}}),
        serde_json::json!({"name":"list_consoles","description":"Lista las consolas locales habilitadas por el usuario.","inputSchema":{"type":"object","properties":{},"additionalProperties":false}}),
        serde_json::json!({"name":"list_tabs","description":"Lista las pestañas SSH o consolas locales que el usuario habilitó para agentes.","inputSchema":{"type":"object","properties":{},"additionalProperties":false}}),
        serde_json::json!({"name":"create_session","description":"Crea una sesión SSH guardada y la habilita para agentes. No permite indicar contraseñas ni frases de paso.","inputSchema":{"type":"object","properties":{"name":{"type":"string","maxLength":80},"host":{"type":"string","maxLength":255},"username":{"type":"string","maxLength":64},"port":{"type":"integer","minimum":1,"maximum":65535},"folder":{"type":"string","maxLength":80},"auth":{"type":"string","enum":["password","key","agent"]},"key_path":{"type":"string","maxLength":400}},"required":["name","host","username"],"additionalProperties":false}}),
        serde_json::json!({"name":"open_session","description":"Abre una sesión SSH guardada que el usuario habilitó. Requiere aprobación.","inputSchema":{"type":"object","properties":{"session_id":{"type":"string"}},"required":["session_id"],"additionalProperties":false}}),
        serde_json::json!({"name":"open_console","description":"Abre una consola local si el usuario habilitó el acceso local. Requiere aprobación.","inputSchema":{"type":"object","properties":{"console_id":{"type":"string"}},"required":["console_id"],"additionalProperties":false}}),
        serde_json::json!({"name":"read_tab","description":"Lee las últimas líneas de una pestaña habilitada. La primera lectura requiere aprobación.","inputSchema":{"type":"object","properties":{"tab":{"type":"string"},"lines":{"type":"integer","minimum":1,"maximum":2000}},"required":["tab"],"additionalProperties":false}}),
        serde_json::json!({"name":"run_command","description":"Escribe un comando en una terminal habilitada. Cada comando requiere aprobación explícita.","inputSchema":{"type":"object","properties":{"tab":{"type":"string"},"command":{"type":"string","maxLength":2000},"timeout_seconds":{"type":"integer","minimum":1,"maximum":600}},"required":["tab","command"],"additionalProperties":false}}),
        serde_json::json!({"name":"send_keys","description":"Envía texto corto o teclas especiales a una terminal. Cada envío requiere aprobación explícita.","inputSchema":{"type":"object","properties":{"tab":{"type":"string"},"text":{"type":"string","maxLength":200},"keys":{"type":"array","items":{"type":"string","enum":["enter","tab","esc","space","ctrl+c","ctrl+d","ctrl+z","up","down","right","left"]},"maxItems":20}},"required":["tab"],"additionalProperties":false}}),
        serde_json::json!({"name":"sftp_list","description":"Lista una carpeta SFTP en una pestaña SSH. Requiere aprobación.","inputSchema":{"type":"object","properties":{"tab":{"type":"string"},"path":{"type":"string"}},"required":["tab"],"additionalProperties":false}}),
        serde_json::json!({"name":"sftp_read","description":"Lee un archivo de texto del servidor (máximo 512 KB). Requiere aprobación.","inputSchema":{"type":"object","properties":{"tab":{"type":"string"},"path":{"type":"string"}},"required":["tab","path"],"additionalProperties":false}}),
        serde_json::json!({"name":"sftp_write","description":"Crea o reemplaza un archivo de texto remoto (máximo 512 KB). Requiere aprobación.","inputSchema":{"type":"object","properties":{"tab":{"type":"string"},"path":{"type":"string"},"content":{"type":"string","maxLength":524288}},"required":["tab","path","content"],"additionalProperties":false}}),
        serde_json::json!({"name":"sftp_upload","description":"Sube un archivo local a una ruta remota. Requiere aprobación.","inputSchema":{"type":"object","properties":{"tab":{"type":"string"},"local_path":{"type":"string"},"remote_path":{"type":"string"}},"required":["tab","local_path","remote_path"],"additionalProperties":false}}),
        serde_json::json!({"name":"sftp_download","description":"Descarga un archivo remoto a una ruta local nueva; no descarga ejecutables. Requiere aprobación.","inputSchema":{"type":"object","properties":{"tab":{"type":"string"},"remote_path":{"type":"string"},"local_path":{"type":"string"}},"required":["tab","remote_path","local_path"],"additionalProperties":false}}),
    ]
}

fn mcp_tab_info(
    app: &tauri::AppHandle,
    ssh: &Arc<Mutex<HashMap<String, SshConnection>>>,
    ptys: &Arc<Mutex<HashMap<String, LocalPty>>>,
    tab: &str,
) -> Result<(String, String, bool), String> {
    if let Some(connection) = ssh.lock().map_err(|e| e.to_string())?.get(tab) {
        let session = read_sessions(app)?
            .into_iter()
            .find(|s| s.id == connection.session_id && s.allow_agents)
            .ok_or("Esa sesión no está habilitada para agentes")?;
        return Ok((
            session.name,
            format!("{}@{}:{}", session.username, session.host, session.port),
            true,
        ));
    }
    if ptys.lock().map_err(|e| e.to_string())?.contains_key(tab)
        && mcp_settings(app)?["allowLocal"].as_bool().unwrap_or(false)
    {
        return Ok(("Consola local".into(), "este equipo".into(), false));
    }
    Err("Esa pestaña no existe o no está habilitada para agentes. Usa list_tabs.".into())
}

fn mcp_write_terminal(
    tab: &str,
    data: &str,
    ssh: &Arc<Mutex<HashMap<String, SshConnection>>>,
    ptys: &Arc<Mutex<HashMap<String, LocalPty>>>,
) -> Result<(), String> {
    if let Some(pty) = ptys.lock().map_err(|e| e.to_string())?.get_mut(tab) {
        return pty.writer.write_all(data.as_bytes()).map_err(|e| e.to_string());
    }
    if let Some(connection) = ssh.lock().map_err(|e| e.to_string())?.get(tab) {
        return write_retry(
            &mut *connection.channel.lock().map_err(|e| e.to_string())?,
            data.as_bytes(),
        );
    }
    Err("La pestaña ya no está conectada".into())
}

fn mcp_tail(text: &str, max_chars: usize) -> String {
    let count = text.chars().count();
    if count <= max_chars {
        return text.to_owned();
    }
    format!("… (salida recortada)\n{}", text.chars().skip(count - max_chars).collect::<String>())
}

fn mcp_read_tab(
    tab: &str,
    lines: usize,
    runtime: &AgentRuntime,
) -> Result<String, String> {
    let output = runtime.output.lock().map_err(|e| e.to_string())?;
    let text = output.get(tab).map(String::as_str).unwrap_or("");
    let selected = text.lines().rev().take(lines).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n");
    Ok(mcp_tail(&selected, 30_000))
}

fn mcp_is_runnable(path: &Path) -> bool {
    let Some(extension) = path.extension().and_then(|extension| extension.to_str()) else {
        return true;
    };
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "exe" | "com" | "scr" | "pif" | "cpl" | "msi" | "msp" | "mst" | "msc" | "bat"
            | "cmd" | "ps1" | "vbs" | "vbe" | "js" | "jse" | "wsf" | "wsh" | "hta"
            | "lnk" | "url" | "reg" | "jar" | "appref-ms" | "application" | "gadget"
            | "chm" | "hlp" | "appx" | "msix" | "py" | "pyw" | "pyz" | "rb" | "pl"
            | "iso" | "img" | "vhd" | "vhdx" | "dll" | "ocx" | "sys" | "drv" | "lib"
    )
}

fn request_mcp_approval(
    app: &tauri::AppHandle,
    runtime: &AgentRuntime,
    tab: Option<&str>,
    title: &str,
    detail: &str,
    read_once: bool,
) -> Result<(), String> {
    if !mcp_settings(app)?["enabled"].as_bool().unwrap_or(false) {
        return Err("El acceso MCP está apagado.".into());
    }
    if let Some(tab) = tab {
        if let Some(permission) = runtime
            .permissions
            .lock()
            .map_err(|e| e.to_string())?
            .get(tab)
        {
            if permission.all || (read_once && permission.read) {
                return Ok(());
            }
        }
    }
    let _queue = runtime.approval_lock.lock().map_err(|e| e.to_string())?;
    let request_id = format!("{:032x}", rand::random::<u128>());
    let (sender, receiver) = mpsc::channel();
    runtime
        .approvals
        .lock()
        .map_err(|e| e.to_string())?
        .insert(request_id.clone(), sender);
    if let Err(error) = app.emit(
        "agent:approval",
        serde_json::json!([request_id, title, detail, tab]),
    ) {
        runtime.approvals.lock().ok().map(|mut pending| pending.remove(&request_id));
        return Err(error.to_string());
    }
    let decision = receiver
        .recv_timeout(Duration::from_secs(120))
        .unwrap_or_else(|_| "deny".into());
    runtime.approvals.lock().ok().map(|mut pending| pending.remove(&request_id));
    if !mcp_settings(app)?["enabled"].as_bool().unwrap_or(false) {
        return Err("El acceso MCP se apagó mientras se esperaba la aprobación.".into());
    }
    match decision.as_str() {
        "allow" => {
            if read_once {
                if let Some(tab) = tab {
                    runtime.permissions.lock().map_err(|e| e.to_string())?.entry(tab.into()).or_default().read = true;
                }
            }
            Ok(())
        }
        "all" if tab.is_some() => {
            if let Some(tab) = tab {
                runtime.permissions.lock().map_err(|e| e.to_string())?.entry(tab.into()).or_default().all = true;
                let _ = app.emit("agent:perm", serde_json::json!([tab, true]));
            }
            Ok(())
        }
        _ => Err("El usuario rechazó la solicitud o no respondió a tiempo. No la repitas sin consultarle.".into()),
    }
}

#[tauri::command]
fn agent_approval_respond(
    state: State<'_, AppState>,
    request_id: String,
    decision: String,
) -> Result<(), String> {
    if !["allow", "all", "deny"].contains(&decision.as_str()) {
        return Err("Decisión de aprobación inválida".into());
    }
    let sender = state
        .agent
        .approvals
        .lock()
        .map_err(|e| e.to_string())?
        .remove(&request_id)
        .ok_or("La solicitud ya expiró")?;
    sender.send(decision).map_err(|_| "La solicitud ya expiró".into())
}

fn request_mcp_open(
    app: &tauri::AppHandle,
    runtime: &AgentRuntime,
    session_id: &str,
    shell_id: &str,
    timeout: Duration,
) -> Result<String, String> {
    if !mcp_settings(app)?["enabled"].as_bool().unwrap_or(false) {
        return Err("El acceso MCP está apagado.".into());
    }
    let request_id = format!("{:032x}", rand::random::<u128>());
    let (sender, receiver) = mpsc::channel();
    runtime.ui_requests.lock().map_err(|e| e.to_string())?.insert(request_id.clone(), sender);
    if let Err(error) = app.emit("agent:open", serde_json::json!([request_id, session_id, shell_id])) {
        runtime.ui_requests.lock().ok().map(|mut pending| pending.remove(&request_id));
        return Err(error.to_string());
    }
    let result = receiver.recv_timeout(timeout).unwrap_or_else(|_| Err("La app no respondió a tiempo.".into()));
    runtime.ui_requests.lock().ok().map(|mut pending| pending.remove(&request_id));
    if !mcp_settings(app)?["enabled"].as_bool().unwrap_or(false) {
        return Err("El acceso MCP se apagó mientras se esperaba a la app.".into());
    }
    result
}

#[tauri::command]
fn agent_open_respond(
    state: State<'_, AppState>,
    request_id: String,
    result: serde_json::Value,
) -> Result<(), String> {
    let sender = state.agent.ui_requests.lock().map_err(|e| e.to_string())?
        .remove(&request_id).ok_or("La solicitud ya expiró")?;
    let outcome = if let Some(conn_id) = result["connId"].as_str() {
        Ok(conn_id.to_owned())
    } else {
        Err(result["error"].as_str().unwrap_or("No se pudo abrir la pestaña.").to_owned())
    };
    sender.send(outcome).map_err(|_| "La solicitud ya expiró".into())
}

#[tauri::command]
fn agent_revoke(app: tauri::AppHandle, state: State<'_, AppState>, tab: String) -> Result<(), String> {
    if let Ok(mut permissions) = state.agent.permissions.lock() {
        permissions.remove(&tab);
    }
    app.emit("agent:perm", serde_json::json!([tab, false]))
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn agent_grant(app: tauri::AppHandle, state: State<'_, AppState>, tab: String) -> Result<bool, String> {
    if !mcp_settings(&app)?["enabled"].as_bool().unwrap_or(false) {
        return Ok(false);
    }
    let allowed = mcp_tab_info(&app, &state.ssh, &state.ptys, &tab).is_ok();
    if !allowed {
        return Ok(false);
    }
    state.agent.permissions.lock().map_err(|e| e.to_string())?.entry(tab.clone()).or_default().all = true;
    app.emit("agent:perm", serde_json::json!([tab, true])).map_err(|e| e.to_string())?;
    Ok(true)
}

fn mcp_error(id: &serde_json::Value, code: i64, message: &str) -> serde_json::Value {
    serde_json::json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}

fn mcp_tool_call(
    params: &serde_json::Value,
    app: &tauri::AppHandle,
    ssh: &Arc<Mutex<HashMap<String, SshConnection>>>,
    ptys: &Arc<Mutex<HashMap<String, LocalPty>>>,
    agent: &Arc<AgentRuntime>,
) -> Result<serde_json::Value, String> {
    let name = params["name"].as_str().ok_or("Falta el nombre de la herramienta")?;
    let settings = mcp_settings(app)?;
    let result = match name {
        "list_sessions" => {
            let sessions = read_sessions(app)?;
            serde_json::json!({
                "sesiones": sessions.iter().filter(|s| s.allow_agents).map(|s| serde_json::json!({"id":s.id,"nombre":s.name,"carpeta":s.folder,"host":s.host,"puerto":s.port,"usuario":s.username,"autenticacion":s.auth_type})).collect::<Vec<_>>(),
                "nota": format!("{} sesiones más no están habilitadas para agentes.", sessions.iter().filter(|s| !s.allow_agents).count())
            })
        }
        "list_consoles" => {
            if !settings["allowLocal"].as_bool().unwrap_or(false) {
                serde_json::json!({"consolas":[],"nota":"El usuario no habilitó las consolas locales para agentes."})
            } else {
                let shells: Vec<_> = local_shells().iter().map(|shell| serde_json::json!({"id":shell["id"],"nombre":shell["name"]})).collect();
                serde_json::json!({"consolas":shells})
            }
        }
        "list_tabs" => {
            let allowed: HashMap<String, SessionRecord> = read_sessions(app)?.into_iter().filter(|s| s.allow_agents).map(|s| (s.id.clone(), s)).collect();
            let ssh_tabs: Vec<_> = ssh.lock().map_err(|e| e.to_string())?.iter().filter_map(|(id, conn)| {
                let session = allowed.get(&conn.session_id)?;
                Some(serde_json::json!({"tab":id,"tipo":"ssh","nombre":session.name,"destino":format!("{}@{}:{}",session.username,session.host,session.port),"conectada":true}))
            }).collect();
            let mut tabs = ssh_tabs;
            if settings["allowLocal"].as_bool().unwrap_or(false) {
                tabs.extend(ptys.lock().map_err(|e| e.to_string())?.keys().map(|id| serde_json::json!({"tab":id,"tipo":"local","nombre":"Consola local","destino":"este equipo","conectada":true})));
            }
            serde_json::json!({"pestañas":tabs})
        }
        "create_session" => {
            let name = params["name"].as_str().ok_or("Falta \"name\"")?.trim();
            let host = params["host"].as_str().ok_or("Falta \"host\"")?.trim();
            let username = params["username"].as_str().ok_or("Falta \"username\"")?.trim();
            let folder = params["folder"].as_str().unwrap_or("").trim();
            let auth = params["auth"].as_str().unwrap_or("key");
            let key_path = params["key_path"].as_str().unwrap_or("").trim();
            let port = match params.get("port") {
                None => 22,
                Some(value) => value.as_u64().ok_or("\"port\" no es válido.")?,
            };
            if name.is_empty() || name.chars().count() > 80 { return Err("\"name\" debe tener entre 1 y 80 caracteres.".into()); }
            if host.is_empty() || host.chars().count() > 255 || !host.chars().all(|c| c.is_ascii_alphanumeric() || "._:-".contains(c)) {
                return Err("\"host\" no es un nombre o IP válido.".into());
            }
            if username.is_empty() || username.chars().count() > 64 || !username.chars().all(|c| c.is_ascii_alphanumeric() || "._@-".contains(c)) {
                return Err("\"username\" no es válido.".into());
            }
            if !(1..=u16::MAX as u64).contains(&port) { return Err("\"port\" no es válido.".into()); }
            if !["password", "key", "agent"].contains(&auth) { return Err("\"auth\" no es válido.".into()); }
            if folder.chars().count() > 80 { return Err("\"folder\" es demasiado largo.".into()); }
            if auth == "key" && key_path.chars().count() > 400 { return Err("\"key_path\" es demasiado largo.".into()); }
            let auth_label = match auth {
                "password" => "contraseña",
                "agent" => "agente SSH",
                _ if key_path.is_empty() => "clave privada",
                _ => "clave privada seleccionada",
            };
            let detail = format!(
                "{username}@{host}:{port}\nAutenticación: {auth_label}{}\n\nQuedará habilitada para agentes. La app pedirá la contraseña o frase de paso al conectar.",
                if auth == "key" && !key_path.is_empty() { format!(" ({key_path})") } else { String::new() }
            );
            request_mcp_approval(app, agent, None, &format!("Un agente quiere crear la sesión \"{name}\""), &detail, false)?;
            let saved = sessions_save(app.clone(), serde_json::json!({
                "name": name,
                "folder": folder,
                "host": host,
                "port": port,
                "username": username,
                "authType": auth,
                "keyPath": if auth == "key" { key_path } else { "" },
                "tunnels": [],
                "allowAgents": true
            }))?;
            let _ = app.emit("sessions:changed", ());
            serde_json::json!({"id":saved.id,"nombre":saved.name,"nota":"Sesión creada. Ábrela con open_session."})
        }
        "open_session" => {
            let session_id = params["session_id"].as_str().ok_or("Falta \"session_id\"")?;
            let session = read_sessions(app)?.into_iter()
                .find(|session| session.id == session_id && session.allow_agents)
                .ok_or("Sesión no encontrada o no habilitada para agentes. Usa list_sessions.")?;
            request_mcp_approval(
                app,
                agent,
                None,
                &format!("Un agente quiere conectarse a \"{}\"", session.name),
                &format!("{}@{}:{}", session.username, session.host, session.port),
                false,
            )?;
            let tab = request_mcp_open(app, agent, &session.id, "", Duration::from_secs(300))?;
            mcp_tab_info(app, ssh, ptys, &tab)?;
            agent.permissions.lock().map_err(|e| e.to_string())?.entry(tab.clone()).or_default().read = true;
            serde_json::json!({"tab":tab,"nombre":session.name,"estado":"conectada"})
        }
        "open_console" => {
            if !settings["allowLocal"].as_bool().unwrap_or(false) {
                return Err("El usuario no habilitó las consolas locales para agentes.".into());
            }
            let shell_id = params["console_id"].as_str().ok_or("Falta \"console_id\"")?;
            let shell = local_shells().into_iter().find(|shell| shell["id"] == shell_id)
                .ok_or("Consola no disponible. Usa list_consoles.")?;
            let shell_name = shell["name"].as_str().unwrap_or("Consola local");
            request_mcp_approval(
                app,
                agent,
                None,
                &format!("Un agente quiere abrir una consola local: {shell_name}"),
                "Los comandos que ejecute ahí corren en este equipo, con tu usuario.",
                false,
            )?;
            let tab = request_mcp_open(app, agent, "", shell_id, Duration::from_secs(60))?;
            mcp_tab_info(app, ssh, ptys, &tab)?;
            agent.permissions.lock().map_err(|e| e.to_string())?.entry(tab.clone()).or_default().read = true;
            serde_json::json!({"tab":tab,"nombre":shell_name,"estado":"abierta"})
        }
        "read_tab" => {
            let tab = params["tab"].as_str().ok_or("Falta \"tab\"")?;
            let (name, _, _) = mcp_tab_info(app, ssh, ptys, tab)?;
            request_mcp_approval(
                app,
                agent,
                Some(tab),
                &format!("Un agente quiere leer la pestaña \"{name}\""),
                "Podrá leer lo que se muestra en esta pestaña mientras siga abierta.",
                true,
            )?;
            let lines = params["lines"].as_u64().unwrap_or(200).clamp(1, 2000) as usize;
            let output = mcp_read_tab(tab, lines, agent)?;
            let output = if output.is_empty() { "(pestaña vacía)".to_owned() } else { output };
            serde_json::json!({"text":output})
        }
        "run_command" => {
            let tab = params["tab"].as_str().ok_or("Falta \"tab\"")?;
            let command = params["command"].as_str().ok_or("Falta \"command\"")?.trim_end_matches(|c| c == '\r' || c == '\n');
            if command.trim().is_empty() || command.chars().count() > 2000 {
                return Err("El comando debe tener entre 1 y 2000 caracteres".into());
            }
            if command.chars().any(|c| c.is_control() && c != '\n') {
                return Err("El comando contiene caracteres de control. Para teclas especiales usa send_keys.".into());
            }
            let (tab_name, destination, _) = mcp_tab_info(app, ssh, ptys, tab)?;
            if !agent.busy.lock().map_err(|e| e.to_string())?.insert(tab.into()) {
                return Err("Ya hay un comando del agente en curso en esta pestaña.".into());
            }
            let result: Result<serde_json::Value, String> = (|| {
                request_mcp_approval(
                    app,
                    agent,
                    Some(tab),
                    &format!("Un agente quiere ejecutar un comando en \"{tab_name}\" ({destination})"),
                    command,
                    false,
                )?;
                mcp_tab_info(app, ssh, ptys, tab)?;
                agent.permissions.lock().map_err(|e| e.to_string())?.entry(tab.into()).or_default().read = true;
                let before = agent.output.lock().map_err(|e| e.to_string())?.get(tab).cloned().unwrap_or_default();
                if let Ok(mut activity) = agent.activity.lock() {
                    activity.insert(tab.into(), Instant::now());
                }
                mcp_write_terminal(tab, &format!("{}\r", command.replace('\n', "\r")), ssh, ptys)?;
                let timeout = params["timeout_seconds"].as_u64().unwrap_or(60).clamp(1, 600);
                let started = Instant::now();
                let mut timed_out = false;
                loop {
                    thread::sleep(Duration::from_millis(100));
                    let last_data = agent.activity.lock().ok().and_then(|activity| activity.get(tab).copied()).unwrap_or(started);
                    let now = Instant::now();
                    if now.duration_since(last_data) >= Duration::from_millis(1200) {
                        break;
                    }
                    if now.duration_since(started) >= Duration::from_secs(timeout) {
                        timed_out = true;
                        break;
                    }
                }
                let after = agent.output.lock().map_err(|e| e.to_string())?.get(tab).cloned().unwrap_or_default();
                let shared_prefix = before.chars().zip(after.chars()).take_while(|(left, right)| left == right).count();
                let delta = after.chars().skip(shared_prefix).collect::<String>();
                let state = if timed_out {
                    "Se agotó el tiempo de espera y el comando puede seguir en ejecución. Revisa con read_tab."
                } else {
                    "Sin salida nueva reciente; el comando podría seguir en ejecución. Revisa con read_tab."
                };
                Ok(serde_json::json!({"salida":mcp_tail(&delta, 30000),"estado":state}))
            })();
            if let Ok(mut busy) = agent.busy.lock() {
                busy.remove(tab);
            }
            result?
        }
        "send_keys" => {
            let tab = params["tab"].as_str().ok_or("Falta \"tab\"")?;
            let text = params["text"].as_str().unwrap_or("");
            let keys = params["keys"].as_array().cloned().unwrap_or_default();
            if text.chars().count() > 200 || text.chars().any(|character| character.is_control()) {
                return Err("\"text\" debe ser texto simple de hasta 200 caracteres.".into());
            }
            if keys.len() > 20 {
                return Err("\"keys\" puede contener hasta 20 teclas.".into());
            }
            let keycodes = [
                ("enter", "\r"), ("tab", "\t"), ("esc", "\u{1b}"), ("space", " "),
                ("ctrl+c", "\u{3}"), ("ctrl+d", "\u{4}"), ("ctrl+z", "\u{1a}"),
                ("up", "\u{1b}[A"), ("down", "\u{1b}[B"), ("right", "\u{1b}[C"), ("left", "\u{1b}[D"),
            ];
            let mut encoded_keys = String::new();
            let mut key_names = Vec::<String>::new();
            for key in keys {
                let key = key.as_str().ok_or("\"keys\" contiene una tecla inválida")?;
                let value = keycodes.iter().find(|(name, _)| *name == key).map(|(_, code)| *code)
                    .ok_or("\"keys\" contiene una tecla no admitida")?;
                encoded_keys.push_str(value);
                key_names.push(key.to_owned());
            }
            if text.is_empty() && key_names.is_empty() {
                return Err("Indica \"text\" o \"keys\".".into());
            }
            let (tab_name, destination, _) = mcp_tab_info(app, ssh, ptys, tab)?;
            let detail = format!("{}{}", if text.is_empty() { String::new() } else { format!("Texto: {text}") }, if key_names.is_empty() { String::new() } else { format!("{}Teclas: {}", if text.is_empty() { "" } else { "\n" }, key_names.join(", ")) });
            request_mcp_approval(
                app,
                agent,
                Some(tab),
                &format!("Un agente quiere enviar teclas a \"{tab_name}\" ({destination})"),
                &detail,
                false,
            )?;
            mcp_tab_info(app, ssh, ptys, tab)?;
            agent.permissions.lock().map_err(|e| e.to_string())?.entry(tab.into()).or_default().read = true;
            mcp_write_terminal(tab, &format!("{text}{encoded_keys}"), ssh, ptys)?;
            thread::sleep(Duration::from_secs(1));
            serde_json::json!({"salida":mcp_tail(&mcp_read_tab(tab, 40, agent)?, 30000)})
        }
        "sftp_list" => {
            let tab = params["tab"].as_str().ok_or("Falta \"tab\"")?;
            let (tab_name, _, ssh_tab) = mcp_tab_info(app, ssh, ptys, tab)?;
            if !ssh_tab {
                return Err("Esta herramienta solo funciona en pestañas SSH.".into());
            }
            let target = params["path"].as_str().filter(|path| !path.trim().is_empty()).unwrap_or(".");
            if target.chars().count() > 1000 {
                return Err("\"path\" es demasiado largo.".into());
            }
            request_mcp_approval(app, agent, Some(tab), &format!("Un agente quiere listar una carpeta en \"{tab_name}\""), target, false)?;
            let sftp = sftp_for_map(ssh, tab)?;
            let real = retry_ssh(|| sftp.realpath(Path::new(target)))?.to_string_lossy().into_owned();
            let entries = retry_ssh(|| sftp.readdir(Path::new(&real)))?;
            let mut elements: Vec<_> = entries.into_iter().filter_map(|(path, stat)| {
                let name = path.file_name()?.to_str()?;
                if name == "." || name == ".." { return None; }
                let kind = match stat.perm.unwrap_or(0) & 0o170000 {
                    0o040000 => "carpeta",
                    0o120000 => "enlace",
                    _ => "archivo",
                };
                Some(serde_json::json!({"nombre":name,"tipo":kind,"bytes":stat.size.unwrap_or(0)}))
            }).collect();
            elements.sort_by(|a, b| a["nombre"].as_str().cmp(&b["nombre"].as_str()));
            serde_json::json!({"carpeta":real,"elementos":elements})
        }
        "sftp_read" => {
            let tab = params["tab"].as_str().ok_or("Falta \"tab\"")?;
            let remote = params["path"].as_str().ok_or("Falta \"path\"")?;
            if remote.trim().is_empty() || remote.chars().count() > 1000 { return Err("\"path\" no es válida.".into()); }
            let (tab_name, _, ssh_tab) = mcp_tab_info(app, ssh, ptys, tab)?;
            if !ssh_tab { return Err("Esta herramienta solo funciona en pestañas SSH.".into()); }
            request_mcp_approval(app, agent, Some(tab), &format!("Un agente quiere leer un archivo en \"{tab_name}\""), remote, false)?;
            let sftp = sftp_for_map(ssh, tab)?;
            let stat = retry_ssh(|| sftp.stat(Path::new(remote)))?;
            if stat.perm.unwrap_or(0) & 0o170000 == 0o040000 { return Err("Es una carpeta. Usa sftp_list.".into()); }
            if stat.size.unwrap_or(0) > 512 * 1024 { return Err("El archivo es demasiado grande; el límite es 512 KB.".into()); }
            let mut source = retry_ssh(|| sftp.open(Path::new(remote)))?;
            let mut bytes = Vec::new();
            sftp_copy_to_writer(&mut source, &mut bytes, None, tab, remote, stat.size.unwrap_or(0))?;
            if bytes.len() > 512 * 1024 { return Err("El archivo es demasiado grande; el límite es 512 KB.".into()); }
            if bytes.contains(&0) { return Err("El archivo es binario. Usa sftp_download.".into()); }
            serde_json::json!({"contenido":String::from_utf8_lossy(&bytes).into_owned()})
        }
        "sftp_write" => {
            let tab = params["tab"].as_str().ok_or("Falta \"tab\"")?;
            let remote = params["path"].as_str().ok_or("Falta \"path\"")?;
            let content = params["content"].as_str().ok_or("Falta \"content\"")?;
            if remote.trim().is_empty() || remote.chars().count() > 1000 { return Err("\"path\" no es válida.".into()); }
            if content.len() > 512 * 1024 { return Err("El contenido es demasiado grande; el límite es 512 KB.".into()); }
            let (tab_name, _, ssh_tab) = mcp_tab_info(app, ssh, ptys, tab)?;
            if !ssh_tab { return Err("Esta herramienta solo funciona en pestañas SSH.".into()); }
            let sftp = sftp_for_map(ssh, tab)?;
            let existing = retry_ssh(|| sftp.stat(Path::new(remote))).ok();
            if existing.as_ref().is_some_and(|stat| stat.perm.unwrap_or(0) & 0o170000 == 0o040000) {
                return Err("Esa ruta es una carpeta.".into());
            }
            let preview: String = content.chars().take(1200).collect();
            let detail = format!("{remote}\n{} bytes\n\nContenido:\n{}{}", content.len(), preview, if content.chars().count() > 1200 { "\n… (continúa)" } else { "" });
            request_mcp_approval(app, agent, Some(tab), &format!("Un agente quiere {} un archivo en \"{tab_name}\"", if existing.is_some() { "REEMPLAZAR" } else { "crear" }), &detail, false)?;
            let mut destination = retry_ssh(|| sftp.create(Path::new(remote)))?;
            let mut source = content.as_bytes();
            sftp_copy_from_reader(&mut source, &mut destination, None, tab, remote, content.len() as u64)?;
            serde_json::json!({"estado":format!("Archivo guardado: {remote} ({} bytes).", content.len())})
        }
        "sftp_upload" => {
            let tab = params["tab"].as_str().ok_or("Falta \"tab\"")?;
            let local = PathBuf::from(params["local_path"].as_str().ok_or("Falta \"local_path\"")?);
            let remote = params["remote_path"].as_str().ok_or("Falta \"remote_path\"")?;
            if !local.is_absolute() { return Err("\"local_path\" debe ser una ruta absoluta.".into()); }
            if remote.trim().is_empty() || remote.chars().count() > 1000 { return Err("\"remote_path\" no es válida.".into()); }
            let metadata = fs::metadata(&local).map_err(|_| "El archivo local no existe")?;
            if !metadata.is_file() { return Err("La ruta local no es un archivo normal.".into()); }
            let (tab_name, _, ssh_tab) = mcp_tab_info(app, ssh, ptys, tab)?;
            if !ssh_tab { return Err("Esta herramienta solo funciona en pestañas SSH.".into()); }
            let detail = format!("Desde este equipo: {}\nAl servidor: {remote}\n{} bytes", local.display(), metadata.len());
            request_mcp_approval(app, agent, Some(tab), &format!("Un agente quiere subir un archivo a \"{tab_name}\""), &detail, false)?;
            let sftp = sftp_for_map(ssh, tab)?;
            let mut source = fs::File::open(&local).map_err(|e| e.to_string())?;
            let mut destination = retry_ssh(|| sftp.create(Path::new(remote)))?;
            sftp_copy_from_reader(&mut source, &mut destination, None, tab, remote, metadata.len())?;
            serde_json::json!({"estado":format!("Archivo subido: {remote} ({} bytes).", metadata.len())})
        }
        "sftp_download" => {
            let tab = params["tab"].as_str().ok_or("Falta \"tab\"")?;
            let remote = params["remote_path"].as_str().ok_or("Falta \"remote_path\"")?;
            let local = PathBuf::from(params["local_path"].as_str().ok_or("Falta \"local_path\"")?);
            if !local.is_absolute() { return Err("\"local_path\" debe ser una ruta absoluta.".into()); }
            if remote.trim().is_empty() || remote.chars().count() > 1000 { return Err("\"remote_path\" no es válida.".into()); }
            if mcp_is_runnable(&local) { return Err("No se descargan archivos ejecutables o sin extensión.".into()); }
            if local.exists() { return Err("Ya existe un archivo con ese nombre. Elige otro.".into()); }
            if !local.parent().and_then(|parent| fs::metadata(parent).ok()).is_some_and(|metadata| metadata.is_dir()) {
                return Err("La carpeta local de destino no existe.".into());
            }
            let (tab_name, _, ssh_tab) = mcp_tab_info(app, ssh, ptys, tab)?;
            if !ssh_tab { return Err("Esta herramienta solo funciona en pestañas SSH.".into()); }
            request_mcp_approval(app, agent, Some(tab), &format!("Un agente quiere descargar un archivo desde \"{tab_name}\""), &format!("Del servidor: {remote}\nA este equipo: {}", local.display()), false)?;
            let sftp = sftp_for_map(ssh, tab)?;
            let stat = retry_ssh(|| sftp.stat(Path::new(remote)))?;
            if stat.perm.unwrap_or(0) & 0o170000 == 0o040000 { return Err("La ruta remota es una carpeta.".into()); }
            let mut source = retry_ssh(|| sftp.open(Path::new(remote)))?;
            let mut destination = fs::OpenOptions::new().write(true).create_new(true).open(&local).map_err(|e| e.to_string())?;
            if let Err(error) = sftp_copy_to_writer(&mut source, &mut destination, None, tab, remote, stat.size.unwrap_or(0)) {
                let _ = fs::remove_file(&local);
                return Err(error);
            }
            serde_json::json!({"estado":format!("Archivo descargado: {}", local.display())})
        }
        _ => return Err(format!("Herramienta desconocida: {name}")),
    };
    let text = serde_json::to_string_pretty(&result).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({"content":[{"type":"text","text":text}]}))
}

fn mcp_rpc(
    request: &serde_json::Value,
    app: &tauri::AppHandle,
    ssh: &Arc<Mutex<HashMap<String, SshConnection>>>,
    ptys: &Arc<Mutex<HashMap<String, LocalPty>>>,
    agent: &Arc<AgentRuntime>,
) -> Option<serde_json::Value> {
    let id = request.get("id").cloned().unwrap_or(serde_json::Value::Null);
    let Some(method) = request.get("method").and_then(|v| v.as_str()) else {
        return Some(mcp_error(&id, -32600, "Solicitud JSON-RPC inválida"));
    };
    let params = &request["params"];
    let result = match method {
        "initialize" => Some(serde_json::json!({
            "jsonrpc":"2.0","id":id,"result":{
                "protocolVersion":params["protocolVersion"].as_str().filter(|v| ["2025-11-25","2025-06-18","2025-03-26","2024-11-05"].contains(v)).unwrap_or("2025-11-25"),
                "capabilities":{"tools":{}},
                "serverInfo":{"name":"mi-terminal","version":env!("CARGO_PKG_VERSION")},
                "instructions":"Controla Mi Terminal. Solo ves las sesiones y pestañas que el usuario habilitó. Las acciones que escriben o ejecutan comandos requieren aprobación explícita en la app."
            }
        })),
        "ping" => Some(serde_json::json!({"jsonrpc":"2.0","id":id,"result":{}})),
        "tools/list" => Some(serde_json::json!({"jsonrpc":"2.0","id":id,"result":{"tools":mcp_tools()}})),
        "tools/call" => Some(match mcp_tool_call(params, app, ssh, ptys, agent) {
            Ok(result) => serde_json::json!({"jsonrpc":"2.0","id":id,"result":result}),
            Err(error) => serde_json::json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":format!("Error: {error}")}],"isError":true}}),
        }),
        _ => Some(mcp_error(&id, -32601, "Método no soportado")),
    };
    if request.get("id").is_none() { None } else { result }
}

fn handle_mcp_client(
    mut stream: TcpStream,
    token: String,
    app: tauri::AppHandle,
    ssh: Arc<Mutex<HashMap<String, SshConnection>>>,
    ptys: Arc<Mutex<HashMap<String, LocalPty>>>,
    agent: Arc<AgentRuntime>,
    server_stop: Arc<AtomicBool>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let mut request = Vec::new();
    let mut buf = [0u8; 8192];
    let header_end = loop {
        if request.len() > 16 * 1024 { return; }
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => request.extend_from_slice(&buf[..n]),
        }
        if let Some(pos) = request.windows(4).position(|window| window == b"\r\n\r\n") { break pos + 4; }
    };
    let header = String::from_utf8_lossy(&request[..header_end]);
    let mut lines = header.lines();
    let Some(first) = lines.next() else { return; };
    let mut request_line = first.split_whitespace();
    let method = request_line.next().unwrap_or("");
    let path = request_line.next().unwrap_or("");
    let mut host = String::new();
    let mut auth = String::new();
    let mut origin = false;
    let mut transfer_encoding = false;
    let mut length = None;
    for line in lines {
        let Some((key, value)) = line.trim_end_matches('\r').split_once(':') else { continue; };
        match key.trim().to_ascii_lowercase().as_str() {
            "host" => host = value.trim().to_ascii_lowercase(),
            "authorization" => auth = value.trim().to_owned(),
            "origin" => origin = true,
            "transfer-encoding" => transfer_encoding = true,
            "content-length" => length = value.trim().parse::<usize>().ok(),
            _ => {}
        }
    }
    let authorized = constant_time_eq(auth.strip_prefix("Bearer ").unwrap_or("").trim().as_bytes(), token.as_bytes());
    let status = if host != format!("127.0.0.1:{MCP_PORT}") && host != format!("localhost:{MCP_PORT}") {
        403
    } else if origin {
        403
    } else if transfer_encoding {
        400
    } else if path.split('?').next() != Some("/mcp") {
        404
    } else if !authorized {
        401
    } else if method != "POST" {
        405
    } else {
        200
    };
    if status != 200 {
        let text = match status {
            400 => "No se admite Transfer-Encoding",
            403 => "Solicitud local no permitida",
            404 => "No encontrado",
            401 => "Token inválido o ausente",
            405 => "Solo se admite POST",
            _ => "Error",
        };
        write_http(&mut stream, status, &serde_json::json!({"error":text}), None);
        return;
    }
    let Some(length) = length.filter(|n| *n <= MCP_MAX_BODY) else {
        write_http(&mut stream, 413, &serde_json::json!({"error":"Solicitud demasiado grande o sin Content-Length"}), None);
        return;
    };
    let mut body = request[header_end..].to_vec();
    while body.len() < length {
        let max = (length - body.len()).min(buf.len());
        match stream.read(&mut buf[..max]) {
            Ok(0) | Err(_) => return,
            Ok(n) => body.extend_from_slice(&buf[..n]),
        }
    }
    body.truncate(length);
    if server_stop.load(Ordering::Relaxed) {
        write_http(&mut stream, 401, &serde_json::json!({"error":"El acceso MCP fue desactivado o el token fue renovado"}), None);
        return;
    }
    let Ok(message) = serde_json::from_slice::<serde_json::Value>(&body) else {
        write_http(&mut stream, 400, &mcp_error(&serde_json::Value::Null, -32700, "JSON inválido"), None);
        return;
    };
    let response = if let Some(batch) = message.as_array() {
        let results: Vec<_> = batch.iter().filter_map(|item| mcp_rpc(item, &app, &ssh, &ptys, &agent)).collect();
        if results.is_empty() { None } else { Some(serde_json::Value::Array(results)) }
    } else { mcp_rpc(&message, &app, &ssh, &ptys, &agent) };
    match response {
        Some(response) => write_http(&mut stream, 200, &response, None),
        None => write_http_empty(&mut stream, 202),
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        diff |= usize::from(left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0));
    }
    diff == 0
}

fn write_http(stream: &mut TcpStream, status: u16, body: &serde_json::Value, extra: Option<&str>) {
    let encoded = body.to_string();
    let phrase = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        _ => "Internal Server Error",
    };
    let extra = extra.unwrap_or("");
    let response = format!("HTTP/1.1 {status} {phrase}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: {}\r\n{extra}\r\n{encoded}", encoded.len());
    let _ = stream.write_all(response.as_bytes());
}

fn write_http_empty(stream: &mut TcpStream, status: u16) {
    let phrase = if status == 202 { "Accepted" } else { "No Content" };
    let _ = write!(stream, "HTTP/1.1 {status} {phrase}\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(AppState::default())
        .setup(|app| {
            let state = app.state::<AppState>();
            if let Err(error) = sync_mcp_server(app.handle(), &state) {
                if let Ok(mut slot) = state.mcp_error.lock() {
                    *slot = error;
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            home_dir,
            sessions_list,
            sessions_save,
            sessions_delete,
            local_shells,
            local_open,
            ssh_connect,
            known_host_trust,
            terminal_write,
            terminal_resize,
            terminal_disconnect,
            sftp_edit,
            editor_get,
            editor_set,
            editor_use_system,
            mcp_get,
            mcp_set,
            mcp_new_token,
            mcp_copy,
            agent_approval_respond,
            agent_open_respond,
            agent_revoke,
            agent_grant,
            sftp_home,
            sftp_list,
            sftp_download,
            sftp_upload,
            sftp_mkdir,
            sftp_remove,
            sftp_rename,
            sftp_set_sudo
        ])
        .run(tauri::generate_context!())
        .expect("error while running Mi Terminal");
}
