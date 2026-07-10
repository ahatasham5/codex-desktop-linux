use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    env, fs,
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::{TcpListener as TokioTcpListener, UnixStream as TokioUnixStream},
    sync::{oneshot, Semaphore},
};
use tokio_tungstenite::{
    accept_hdr_async, client_async,
    tungstenite::{
        handshake::server::{Callback, ErrorResponse, Request, Response},
        http::StatusCode,
    },
};

const MANIFEST_SCHEMA_VERSION: u32 = 2;
const NATIVE_HOST_PROTOCOL_VERSION: u32 = 2;
const APP_SERVER_START_TIMEOUT: Duration = Duration::from_secs(10);
const APP_SERVER_STOP_TIMEOUT: Duration = Duration::from_secs(2);
const PROXY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_APP_SERVER_PROCESSES: usize = 16;
const MAX_PROXY_CONNECTIONS: usize = 32;
const MAX_ACTIVE_ASSETS: usize = 32;
const MAX_ASSET_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ASSET_CHUNK_BASE64: usize = 64 * 1024;
const MAX_CLIENT_ID_BYTES: usize = 128;
const MAX_UNIX_SOCKET_PATH_BYTES: usize = 107;
const MANIFEST_FILE_NAME: &str = "chrome-native-hosts-v2.json";
const OPEN_LOCAL_FILE_METHOD: &str = "codexRuntime/openLocalFile";

type RuntimeResult<T> = std::result::Result<T, RuntimeError>;

#[derive(Debug)]
struct RuntimeError {
    code: i64,
    message: String,
    kind: Option<&'static str>,
}

impl RuntimeError {
    fn invalid_params(message: impl Into<String>) -> Self {
        Self {
            code: -32602,
            message: message.into(),
            kind: None,
        }
    }

    fn method_not_found(method: &str) -> Self {
        Self {
            code: -32601,
            message: format!("Unsupported native host method: {method}"),
            kind: None,
        }
    }

    fn typed(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            code: 1,
            message: message.into(),
            kind: Some(kind),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            code: 1,
            message: message.into(),
            kind: Some("app_server_runtime_error"),
        }
    }

    fn response(&self, id: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": self.code,
                "message": self.message,
                "data": self.kind.map(|kind| json!({ "type": kind }))
            }
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct RuntimeConstraints {
    extension_build_channel: String,
    extension_id: String,
    extension_version: String,
    native_host_name: String,
    required_app_server_protocol_version: u32,
    required_native_host_protocol_version: u32,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeManifest {
    schema_version: u32,
    entries: Vec<Value>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeEntry {
    schema_version: u32,
    app_server_protocol_version: u32,
    app_version: String,
    channel: String,
    cli_version: String,
    entry_id: String,
    extension_build_channels: Vec<String>,
    extension_ids: Vec<String>,
    install_id: String,
    native_host_names: Vec<String>,
    native_host_protocol_version: u32,
    native_host_version: String,
    paths: RuntimePaths,
    proxy_host: String,
    proxy_port: u16,
    updated_at: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuntimePaths {
    browser_client_path: Option<PathBuf>,
    codex_cli_path: PathBuf,
    codex_home: PathBuf,
    extension_host_path: PathBuf,
    node_path: PathBuf,
    #[serde(default)]
    node_module_dirs: Vec<PathBuf>,
    node_repl_path: Option<PathBuf>,
    resources_path: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

struct ManagedProcess {
    child: Child,
    entry_id: String,
    process_group: libc::pid_t,
    proxy_host: String,
    proxy_port: u16,
    socket_path: PathBuf,
}

struct ProxyServer {
    address: SocketAddr,
    join: Option<thread::JoinHandle<()>>,
    requested_address: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    token: String,
}

struct TabContextAsset {
    file: File,
    finished: bool,
    path: PathBuf,
    size: u64,
}

struct ProxyHandshakeCallback {
    allowed_origin: String,
    selected_client: Arc<Mutex<Option<String>>>,
    token: String,
}

impl Callback for ProxyHandshakeCallback {
    fn on_request(
        self,
        request: &Request,
        response: Response,
    ) -> std::result::Result<Response, ErrorResponse> {
        match validate_proxy_request(request, &self.allowed_origin, &self.token) {
            Ok(client_id) => {
                *self
                    .selected_client
                    .lock()
                    .expect("proxy client mutex poisoned") = Some(client_id);
                Ok(response)
            }
            Err(message) => Err(forbidden_response(message)),
        }
    }
}

pub struct RuntimeManager {
    assets: Mutex<HashMap<String, TabContextAsset>>,
    extension_id: Option<String>,
    manifest_paths_override: Option<Vec<PathBuf>>,
    processes: Mutex<HashMap<String, ManagedProcess>>,
    proxy: Mutex<Option<ProxyServer>>,
    runtime_root: PathBuf,
}

impl RuntimeManager {
    pub fn new(extension_id: Option<String>) -> Self {
        Self::with_runtime_root(extension_id, unique_runtime_root(), None)
    }

    fn with_runtime_root(
        extension_id: Option<String>,
        runtime_root: PathBuf,
        manifest_paths_override: Option<Vec<PathBuf>>,
    ) -> Self {
        Self {
            assets: Mutex::new(HashMap::new()),
            extension_id,
            manifest_paths_override,
            processes: Mutex::new(HashMap::new()),
            proxy: Mutex::new(None),
            runtime_root,
        }
    }

    pub fn handle_request(self: &Arc<Self>, message: &Value) -> Value {
        let id = message.get("id").cloned().unwrap_or(Value::Null);
        let method = message
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));

        let result = match method {
            "codexRuntime/hello" => self.hello(&params),
            "codexRuntime/ensure" => self.ensure(&params, false),
            "codexRuntime/restart" => self.ensure(&params, true),
            "codexRuntime/tabContextAsset/create" => self.create_asset(&params),
            "codexRuntime/tabContextAsset/appendChunk" => self.append_asset(&params),
            "codexRuntime/tabContextAsset/finish" => self.finish_asset(&params),
            "codexRuntime/tabContextAsset/abort" | "codexRuntime/tabContextAsset/remove" => {
                self.remove_asset(&params)
            }
            OPEN_LOCAL_FILE_METHOD => self.open_local_file(&params),
            _ => Err(RuntimeError::method_not_found(method)),
        };

        match result {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err(error) => error.response(id),
        }
    }

    fn hello(&self, params: &Value) -> RuntimeResult<Value> {
        if let Some(constraints) = params.get("constraints") {
            parse_constraints(constraints)?;
        }

        let mut supported_methods = Vec::new();
        if executable_in_path("xdg-open") {
            supported_methods.push(OPEN_LOCAL_FILE_METHOD);
        }

        Ok(json!({
            "manifestSchemaVersion": MANIFEST_SCHEMA_VERSION,
            "nativeHostProtocolVersion": NATIVE_HOST_PROTOCOL_VERSION,
            "nativeHostVersion": env!("CARGO_PKG_VERSION"),
            "supportedMethods": supported_methods,
            "supportedProtocolVersions": [NATIVE_HOST_PROTOCOL_VERSION]
        }))
    }

    fn ensure(self: &Arc<Self>, params: &Value, restart: bool) -> RuntimeResult<Value> {
        let constraints = parse_constraints(params.get("constraints").ok_or_else(|| {
            RuntimeError::invalid_params("Missing required parameter: constraints")
        })?)?;
        self.validate_invocation(&constraints)?;
        let client_id = normalized_client_id(params.get("clientId"))?;
        let entry = select_runtime_entry(&constraints, self.manifest_paths_override.as_deref())?;
        validate_runtime_entry(&entry)?;
        let (address, token) = self.ensure_proxy(&entry)?;
        self.ensure_process(
            &entry,
            &constraints.extension_id,
            &client_id,
            address.port(),
            restart,
        )?;

        let local_app_server_url = format!(
            "ws://{}:{}/?token={}",
            display_ip(address.ip()),
            address.port(),
            token
        );
        Ok(json!({
            "appServerProtocolVersion": entry.app_server_protocol_version,
            "appVersion": entry.app_version,
            "channel": entry.channel,
            "cliVersion": entry.cli_version,
            "connected": true,
            "entryId": entry.entry_id,
            "localAppServerUrl": local_app_server_url,
            "nativeHostProtocolVersion": entry.native_host_protocol_version,
            "nativeHostVersion": entry.native_host_version,
            "runtimeConfig": runtime_config(&entry)?
        }))
    }

    fn validate_invocation(&self, constraints: &RuntimeConstraints) -> RuntimeResult<()> {
        if constraints.required_native_host_protocol_version != NATIVE_HOST_PROTOCOL_VERSION {
            return Err(RuntimeError::typed(
                "version_mismatch",
                "The Codex app and Chrome extension versions are incompatible.",
            ));
        }
        if constraints.native_host_name.trim().is_empty()
            || constraints.extension_build_channel.trim().is_empty()
            || constraints.extension_version.trim().is_empty()
        {
            return Err(RuntimeError::invalid_params(
                "Runtime constraints contain empty values",
            ));
        }
        if self.extension_id.as_deref() != Some(constraints.extension_id.as_str()) {
            return Err(RuntimeError::typed(
                "no_matching_codex_install",
                "No compatible Codex app-server entry was found",
            ));
        }
        Ok(())
    }

    fn ensure_proxy(self: &Arc<Self>, entry: &RuntimeEntry) -> RuntimeResult<(SocketAddr, String)> {
        let bind_address = proxy_bind_address(entry)?;
        let mut proxy = self.proxy.lock().expect("runtime proxy mutex poisoned");
        if proxy.as_ref().is_some_and(|proxy| {
            proxy.join.as_ref().is_some_and(|join| !join.is_finished())
                && proxy.requested_address == bind_address
        }) {
            let proxy = proxy.as_ref().expect("checked proxy");
            return Ok((proxy.address, proxy.token.clone()));
        }
        if let Some(mut stale) = proxy.take() {
            stop_proxy(&mut stale);
        }

        prepare_private_dir(&self.runtime_root).map_err(|error| {
            RuntimeError::internal(format!(
                "Failed to prepare Chrome runtime directory: {error}"
            ))
        })?;
        let listener = bind_proxy_listener(bind_address)?;
        listener.set_nonblocking(true).map_err(|error| {
            RuntimeError::internal(format!(
                "Failed to configure Codex app-server proxy: {error}"
            ))
        })?;
        let address = listener.local_addr().map_err(|error| {
            RuntimeError::internal(format!(
                "Failed to read Codex app-server proxy address: {error}"
            ))
        })?;
        let token = random_hex(32).map_err(|error| {
            RuntimeError::internal(format!(
                "Failed to create Codex app-server proxy token: {error}"
            ))
        })?;
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let manager = Arc::clone(self);
        let extension_id = self.extension_id.clone().ok_or_else(|| {
            RuntimeError::typed(
                "no_matching_codex_install",
                "No compatible Codex app-server entry was found",
            )
        })?;
        let allowed_origin = format!("chrome-extension://{extension_id}");
        let proxy_token = token.clone();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| {
                RuntimeError::internal(format!(
                    "Failed to create Codex app-server proxy runtime: {error}"
                ))
            })?;
        let join = thread::Builder::new()
            .name("codex-app-server-proxy".to_string())
            .spawn(move || {
                runtime.block_on(run_proxy(
                    listener,
                    manager,
                    allowed_origin,
                    proxy_token,
                    shutdown_rx,
                ));
            })
            .map_err(|error| {
                RuntimeError::internal(format!("Failed to start Codex app-server proxy: {error}"))
            })?;

        *proxy = Some(ProxyServer {
            address,
            join: Some(join),
            requested_address: bind_address,
            shutdown: Some(shutdown_tx),
            token: token.clone(),
        });
        Ok((address, token))
    }

    fn ensure_process(
        &self,
        entry: &RuntimeEntry,
        extension_id: &str,
        client_id: &str,
        proxy_port: u16,
        restart: bool,
    ) -> RuntimeResult<PathBuf> {
        let mut processes = self
            .processes
            .lock()
            .expect("app-server process mutex poisoned");

        let keep_existing = if let Some(process) = processes.get_mut(client_id) {
            process_is_reusable(process, entry, proxy_port, restart)?
        } else {
            false
        };
        if keep_existing {
            return Ok(processes
                .get(client_id)
                .expect("checked process")
                .socket_path
                .clone());
        }

        if let Some(mut stale) = processes.remove(client_id) {
            stop_managed_process(&mut stale);
        }
        processes.retain(|_, process| match process.child.try_wait() {
            Ok(Some(_)) => {
                let _ = fs::remove_file(&process.socket_path);
                false
            }
            Ok(None) => true,
            Err(error) => {
                runtime_log(&format!("app-server status check failed: {error}"));
                true
            }
        });
        if processes.len() >= MAX_APP_SERVER_PROCESSES {
            return Err(RuntimeError::internal(
                "Too many active Chrome sidepanel app-server processes",
            ));
        }

        let process = start_app_server(
            entry,
            extension_id,
            client_id,
            proxy_port,
            &self.runtime_root,
        )?;
        let socket_path = process.socket_path.clone();
        if let Some(previous) = processes.insert(client_id.to_string(), process) {
            let mut previous = previous;
            stop_managed_process(&mut previous);
        }
        Ok(socket_path)
    }

    fn process_socket(&self, client_id: &str) -> RuntimeResult<PathBuf> {
        let mut processes = self
            .processes
            .lock()
            .expect("app-server process mutex poisoned");
        let process = processes.get_mut(client_id).ok_or_else(|| {
            RuntimeError::internal("Codex app-server is not running for this sidepanel")
        })?;
        if process
            .child
            .try_wait()
            .map_err(|error| {
                RuntimeError::internal(format!("Failed to inspect Codex app-server: {error}"))
            })?
            .is_some()
        {
            return Err(RuntimeError::internal(
                "Codex app-server exited before the sidepanel connected",
            ));
        }
        Ok(process.socket_path.clone())
    }

    fn create_asset(&self, params: &Value) -> RuntimeResult<Value> {
        let file_name = required_string(params, "fileName")?;
        validate_asset_file_name(file_name)?;
        prepare_private_dir(&self.runtime_root).map_err(|error| {
            RuntimeError::internal(format!(
                "Failed to prepare Chrome runtime directory: {error}"
            ))
        })?;
        let asset_dir = self.runtime_root.join("codex-tab-context-assets");
        prepare_private_dir(&asset_dir).map_err(|error| {
            RuntimeError::internal(format!(
                "Failed to create Chrome tab context asset directory: {error}"
            ))
        })?;

        let mut assets = self
            .assets
            .lock()
            .expect("tab context asset mutex poisoned");
        if assets.len() >= MAX_ACTIVE_ASSETS {
            return Err(RuntimeError::internal(
                "Too many active Chrome tab context assets",
            ));
        }
        let asset_id = random_hex(16).map_err(|error| {
            RuntimeError::internal(format!(
                "Failed to create Chrome tab context asset: {error}"
            ))
        })?;
        let path = asset_dir.join(format!("{asset_id}-{file_name}"));
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(|error| {
                RuntimeError::internal(format!(
                    "Failed to create Chrome tab context asset: {error}"
                ))
            })?;
        assets.insert(
            asset_id.clone(),
            TabContextAsset {
                file,
                finished: false,
                path: path.clone(),
                size: 0,
            },
        );
        Ok(json!({ "assetId": asset_id, "path": path }))
    }

    fn append_asset(&self, params: &Value) -> RuntimeResult<Value> {
        let asset_id = required_string(params, "assetId")?;
        let data_base64 = required_string(params, "dataBase64")?;
        if data_base64.len() > MAX_ASSET_CHUNK_BASE64 {
            return Err(RuntimeError::invalid_params(
                "Invalid Chrome tab context asset chunk",
            ));
        }
        let data = BASE64_STANDARD
            .decode(data_base64)
            .map_err(|_| RuntimeError::invalid_params("Invalid Chrome tab context asset chunk"))?;
        let mut assets = self
            .assets
            .lock()
            .expect("tab context asset mutex poisoned");
        let asset = assets.get_mut(asset_id).ok_or_else(|| {
            RuntimeError::invalid_params("Chrome tab context asset was not found")
        })?;
        if asset.finished {
            return Err(RuntimeError::invalid_params(
                "Chrome tab context asset is already finished",
            ));
        }
        let next_size = asset.size.saturating_add(data.len() as u64);
        if next_size > MAX_ASSET_BYTES {
            return Err(RuntimeError::invalid_params(
                "Chrome tab context asset is too large",
            ));
        }
        asset.file.write_all(&data).map_err(|error| {
            RuntimeError::internal(format!("Failed to write Chrome tab context asset: {error}"))
        })?;
        asset.size = next_size;
        Ok(json!({ "ok": true }))
    }

    fn finish_asset(&self, params: &Value) -> RuntimeResult<Value> {
        let asset_id = required_string(params, "assetId")?;
        let mut assets = self
            .assets
            .lock()
            .expect("tab context asset mutex poisoned");
        let asset = assets.get_mut(asset_id).ok_or_else(|| {
            RuntimeError::invalid_params("Chrome tab context asset was not found")
        })?;
        asset.file.sync_all().map_err(|error| {
            RuntimeError::internal(format!(
                "Failed to secure Chrome tab context asset: {error}"
            ))
        })?;
        asset.finished = true;
        Ok(json!({ "assetId": asset_id, "path": asset.path }))
    }

    fn remove_asset(&self, params: &Value) -> RuntimeResult<Value> {
        let asset_id = required_string(params, "assetId")?;
        let asset = self
            .assets
            .lock()
            .expect("tab context asset mutex poisoned")
            .remove(asset_id)
            .ok_or_else(|| {
                RuntimeError::invalid_params("Chrome tab context asset was not found")
            })?;
        drop(asset.file);
        match fs::remove_file(&asset.path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(RuntimeError::internal(format!(
                    "Failed to remove Chrome tab context asset: {error}"
                )))
            }
        }
        Ok(json!({ "ok": true }))
    }

    fn open_local_file(&self, params: &Value) -> RuntimeResult<Value> {
        let path = PathBuf::from(required_string(params, "path")?);
        validate_openable_file(&path)?;
        let mut child = Command::new("xdg-open")
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| {
                RuntimeError::internal(format!("Failed to open local file: {error}"))
            })?;
        let _ = thread::Builder::new()
            .name("codex-open-local-file".to_string())
            .spawn(move || {
                let _ = child.wait();
            });
        Ok(json!({}))
    }

    pub fn shutdown(&self) {
        if let Some(mut proxy) = self
            .proxy
            .lock()
            .expect("runtime proxy mutex poisoned")
            .take()
        {
            stop_proxy(&mut proxy);
        }
        let mut processes = self
            .processes
            .lock()
            .expect("app-server process mutex poisoned");
        for process in processes.values_mut() {
            stop_managed_process(process);
        }
        processes.clear();
        let assets = std::mem::take(
            &mut *self
                .assets
                .lock()
                .expect("tab context asset mutex poisoned"),
        );
        drop(assets);
        let _ = fs::remove_dir_all(&self.runtime_root);
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        extension_id: String,
        runtime_root: PathBuf,
        manifest_path: PathBuf,
    ) -> Self {
        Self::with_runtime_root(Some(extension_id), runtime_root, Some(vec![manifest_path]))
    }

    #[cfg(test)]
    pub(crate) fn running_process_count(&self) -> usize {
        let mut processes = self
            .processes
            .lock()
            .expect("app-server process mutex poisoned");
        processes
            .values_mut()
            .map(|process| process.child.try_wait().ok().flatten().is_none())
            .filter(|running| *running)
            .count()
    }
}

fn process_is_reusable(
    process: &mut ManagedProcess,
    entry: &RuntimeEntry,
    proxy_port: u16,
    restart: bool,
) -> RuntimeResult<bool> {
    Ok(!restart
        && process.entry_id == entry.entry_id
        && process.proxy_host == entry.proxy_host
        && process.proxy_port == proxy_port
        && process
            .child
            .try_wait()
            .map_err(|error| {
                RuntimeError::internal(format!("Failed to inspect Codex app-server: {error}"))
            })?
            .is_none()
        && socket_is_ready(&process.socket_path))
}

impl RuntimeEntry {
    fn matches(&self, constraints: &RuntimeConstraints) -> bool {
        self.schema_version == MANIFEST_SCHEMA_VERSION
            && self.app_server_protocol_version == constraints.required_app_server_protocol_version
            && self.native_host_protocol_version
                == constraints.required_native_host_protocol_version
            && self
                .extension_build_channels
                .iter()
                .any(|channel| channel == &constraints.extension_build_channel)
            && self
                .extension_ids
                .iter()
                .any(|extension_id| extension_id == &constraints.extension_id)
            && self
                .native_host_names
                .iter()
                .any(|host_name| host_name == &constraints.native_host_name)
    }
}

fn parse_constraints(value: &Value) -> RuntimeResult<RuntimeConstraints> {
    serde_json::from_value(value.clone())
        .map_err(|_| RuntimeError::invalid_params("Invalid Codex runtime constraints"))
}

fn select_runtime_entry(
    constraints: &RuntimeConstraints,
    manifest_paths_override: Option<&[PathBuf]>,
) -> RuntimeResult<RuntimeEntry> {
    let manifest_paths = manifest_paths_override
        .map(<[PathBuf]>::to_vec)
        .unwrap_or_else(manifest_paths);
    let mut saw_manifest = false;
    let mut entries = Vec::new();
    for path in manifest_paths {
        let contents = match fs::read_to_string(&path) {
            Ok(contents) => {
                saw_manifest = true;
                contents
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => {
                return Err(RuntimeError::typed(
                    "manifest_invalid",
                    "Codex Chrome native host v2 manifest is invalid",
                ))
            }
        };
        let manifest: RuntimeManifest = serde_json::from_str(&contents).map_err(|_| {
            RuntimeError::typed(
                "manifest_invalid",
                "Codex Chrome native host v2 manifest is invalid",
            )
        })?;
        if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
            return Err(RuntimeError::typed(
                "manifest_invalid",
                "Codex Chrome native host manifest must use schemaVersion 2",
            ));
        }
        entries.extend(manifest.entries);
    }
    if !saw_manifest {
        return Err(RuntimeError::typed(
            "manifest_missing",
            "Codex Chrome native host v2 manifest is missing",
        ));
    }

    let current_host = current_executable_identity()?;
    let mut matching = entries
        .into_iter()
        .filter_map(|entry| serde_json::from_value::<RuntimeEntry>(entry).ok())
        .filter(|entry| {
            entry.matches(constraints)
                && fs::canonicalize(&entry.paths.extension_host_path)
                    .ok()
                    .and_then(|path| file_identity(&path).ok())
                    .is_some_and(|identity| identity == current_host)
        })
        .collect::<Vec<_>>();
    matching.sort_by(|left, right| right.updated_at.cmp(&left.updated_at));
    matching.into_iter().next().ok_or_else(|| {
        RuntimeError::typed(
            "no_matching_codex_install",
            "No compatible Codex app-server entry was found",
        )
    })
}

fn manifest_paths() -> Vec<PathBuf> {
    if let Some(path) = env::var_os("CODEX_CHROME_NATIVE_HOSTS_MANIFEST") {
        return vec![PathBuf::from(path)];
    }
    let mut paths = Vec::new();
    if let Some(path) = env::var_os("XDG_STATE_HOME") {
        paths.push(
            PathBuf::from(path)
                .join("openai-codex")
                .join(MANIFEST_FILE_NAME),
        );
    } else if let Some(home) = env::var_os("HOME") {
        paths.push(
            PathBuf::from(home)
                .join(".local/state/openai-codex")
                .join(MANIFEST_FILE_NAME),
        );
    }
    if let Some(codex_home) = env::var_os("CODEX_HOME") {
        paths.push(PathBuf::from(codex_home).join(MANIFEST_FILE_NAME));
    } else if let Some(home) = env::var_os("HOME") {
        paths.push(PathBuf::from(home).join(".codex").join(MANIFEST_FILE_NAME));
    }
    paths.dedup();
    paths
}

fn validate_runtime_entry(entry: &RuntimeEntry) -> RuntimeResult<()> {
    if entry.entry_id.trim().is_empty()
        || entry.install_id.trim().is_empty()
        || entry.app_version.trim().is_empty()
        || entry.cli_version.trim().is_empty()
        || entry.native_host_version.trim().is_empty()
    {
        return Err(RuntimeError::typed(
            "manifest_invalid",
            "Matching manifest entry is malformed",
        ));
    }
    validate_owned_dir(&entry.paths.codex_home, true)?;
    validate_owned_dir(&entry.paths.resources_path, false)?;
    validate_owned_file(&entry.paths.codex_cli_path, true)?;
    validate_owned_file(&entry.paths.extension_host_path, true)?;
    validate_owned_file(&entry.paths.node_path, true)?;
    if let Some(path) = &entry.paths.node_repl_path {
        validate_owned_file(path, true)?;
    }
    if let Some(path) = &entry.paths.browser_client_path {
        validate_owned_file(path, false)?;
    }
    for path in &entry.paths.node_module_dirs {
        validate_owned_dir(path, false)?;
    }

    let current_exe = current_executable_identity()?;
    let configured_host = file_identity(&entry.paths.extension_host_path)
        .map_err(|_| required_path_error("extensionHostPath"))?;
    if current_exe != configured_host {
        return Err(RuntimeError::typed(
            "no_matching_codex_install",
            "No compatible Codex app-server entry was found",
        ));
    }
    Ok(())
}

fn validate_owned_file(path: &Path, executable: bool) -> RuntimeResult<()> {
    if !path.is_absolute() {
        return Err(required_path_error("file"));
    }
    let canonical = fs::canonicalize(path).map_err(|_| required_path_error("file"))?;
    let metadata = fs::metadata(&canonical).map_err(|_| required_path_error("file"))?;
    if !metadata.is_file() || has_unsafe_write_permissions(&metadata) {
        return Err(required_path_error("file"));
    }
    let euid = unsafe { libc::geteuid() };
    if metadata.uid() != euid && metadata.uid() != 0 {
        return Err(required_path_error("file"));
    }
    if executable && metadata.permissions().mode() & 0o111 == 0 {
        return Err(required_path_error("executable"));
    }
    validate_trusted_parent_chain(&canonical)?;
    Ok(())
}

fn validate_owned_dir(path: &Path, require_user_owner: bool) -> RuntimeResult<()> {
    if !path.is_absolute() {
        return Err(required_path_error("directory"));
    }
    let metadata = fs::metadata(path).map_err(|_| required_path_error("directory"))?;
    if !metadata.is_dir() || has_unsafe_write_permissions(&metadata) {
        return Err(required_path_error("directory"));
    }
    let euid = unsafe { libc::geteuid() };
    if (require_user_owner && metadata.uid() != euid)
        || (!require_user_owner && metadata.uid() != euid && metadata.uid() != 0)
    {
        return Err(required_path_error("directory"));
    }
    Ok(())
}

fn required_path_error(field: &str) -> RuntimeError {
    RuntimeError::typed(
        "required_path_missing",
        format!("Codex app-server manifest entry is missing required path {field}"),
    )
}

fn validate_trusted_parent_chain(path: &Path) -> RuntimeResult<()> {
    let euid = unsafe { libc::geteuid() };
    for parent in path.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(parent).map_err(|_| required_path_error("parent"))?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || has_unsafe_write_permissions(&metadata)
            || (metadata.uid() != euid && metadata.uid() != 0)
        {
            return Err(required_path_error("parent"));
        }
        if metadata.uid() == euid || metadata.uid() == 0 {
            return Ok(());
        }
    }
    Err(required_path_error("parent"))
}

fn current_executable_identity() -> RuntimeResult<FileIdentity> {
    file_identity(Path::new("/proc/self/exe")).map_err(|_| required_path_error("extensionHostPath"))
}

fn file_identity(path: &Path) -> io::Result<FileIdentity> {
    let metadata = fs::metadata(path)?;
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn runtime_config(entry: &RuntimeEntry) -> RuntimeResult<Value> {
    let trusted_hashes = match &entry.paths.browser_client_path {
        Some(path) => vec![sha256_file(path)?],
        None => Vec::new(),
    };
    let defaults = desktop_agent_mode_defaults(&entry.paths.codex_home);
    Ok(json!({
        "browserClientPath": entry.paths.browser_client_path,
        "codexCliPath": entry.paths.codex_cli_path,
        "codexHome": entry.paths.codex_home,
        "desktopAgentModeDefaults": defaults,
        "nodeModuleDirs": entry.paths.node_module_dirs,
        "nodePath": entry.paths.node_path,
        "nodeReplPath": entry.paths.node_repl_path,
        "platform": "linux",
        "trustedBrowserClientSha256s": trusted_hashes
    }))
}

fn sha256_file(path: &Path) -> RuntimeResult<String> {
    let mut file = File::open(path).map_err(|_| required_path_error("browserClientPath"))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            RuntimeError::internal(format!("Failed to hash Browser Use client: {error}"))
        })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex_encode(digest.finalize().as_slice()))
}

fn desktop_agent_mode_defaults(codex_home: &Path) -> Option<Value> {
    let state: Value = serde_json::from_str(
        &fs::read_to_string(codex_home.join(".codex-global-state.json")).ok()?,
    )
    .ok()?;
    let persisted = state
        .get("electron-persisted-atom-state")
        .and_then(Value::as_object)?;
    let agent_modes = persisted
        .get("agentModesByHostId")
        .or_else(|| persisted.get("agent-mode-by-host-id"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    let preferred_modes = persisted
        .get("preferredNonFullAccessModesByHostId")
        .or_else(|| persisted.get("preferred-non-full-access-agent-mode-by-host-id"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    Some(json!({
        "agentModesByHostId": agent_modes,
        "preferredNonFullAccessModesByHostId": preferred_modes
    }))
}

fn proxy_bind_address(entry: &RuntimeEntry) -> RuntimeResult<SocketAddr> {
    let ip = match entry.proxy_host.as_str() {
        "localhost" => IpAddr::V4(Ipv4Addr::LOCALHOST),
        value => value.parse::<IpAddr>().map_err(|_| {
            RuntimeError::typed("manifest_invalid", "Codex app-server proxy host is invalid")
        })?,
    };
    if !ip.is_loopback() {
        return Err(RuntimeError::typed(
            "manifest_invalid",
            "Codex app-server proxy must use a loopback address",
        ));
    }
    Ok(SocketAddr::new(ip, entry.proxy_port))
}

fn bind_proxy_listener(requested: SocketAddr) -> RuntimeResult<TcpListener> {
    match TcpListener::bind(requested) {
        Ok(listener) => Ok(listener),
        Err(first_error) if requested.port() != 0 => {
            let fallback = SocketAddr::new(requested.ip(), 0);
            runtime_log(&format!(
                "failed to bind app-server proxy to {requested}; using an available loopback port"
            ));
            TcpListener::bind(fallback).map_err(|fallback_error| {
                RuntimeError::internal(format!(
                    "Failed to bind Codex app-server proxy to {requested} ({first_error}) or an available fallback port ({fallback_error})"
                ))
            })
        }
        Err(error) => Err(RuntimeError::internal(format!(
            "Failed to bind Codex app-server proxy: {error}"
        ))),
    }
}

fn start_app_server(
    entry: &RuntimeEntry,
    extension_id: &str,
    client_id: &str,
    proxy_port: u16,
    runtime_root: &Path,
) -> RuntimeResult<ManagedProcess> {
    prepare_private_dir(runtime_root).map_err(|error| {
        RuntimeError::internal(format!(
            "Failed to prepare Chrome runtime directory: {error}"
        ))
    })?;
    let client_hash = short_hash(client_id.as_bytes());
    let socket_path = runtime_root.join(format!("a-{client_hash}.sock"));
    if !unix_socket_path_fits(&socket_path) {
        return Err(RuntimeError::internal(
            "Codex app-server Unix socket path is too long",
        ));
    }
    match fs::remove_file(&socket_path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(RuntimeError::internal(format!(
                "Failed to remove stale Codex app-server socket: {error}"
            )))
        }
    }

    let mut command = Command::new(&entry.paths.codex_cli_path);
    command
        .arg("app-server")
        .arg("--listen")
        .arg(format!("unix://{}", socket_path.display()))
        .arg("--analytics-default-enabled")
        .current_dir(&entry.paths.codex_home)
        .env("CODEX_HOME", &entry.paths.codex_home)
        .env("CODEX_CLI_PATH", &entry.paths.codex_cli_path)
        .env("CODEX_EXTENSION_ID", extension_id)
        .env("CODEX_BROWSER_USE_NODE_PATH", &entry.paths.node_path)
        .env("CODEX_APP_SERVER_PROXY_HOST", &entry.proxy_host)
        .env("CODEX_APP_SERVER_PROXY_PORT", proxy_port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(path) = &entry.paths.browser_client_path {
        command.env("CODEX_BROWSER_CLIENT_PATH", path);
    }
    if let Some(path) = &entry.paths.node_repl_path {
        command.env("CODEX_NODE_REPL_PATH", path);
    }
    let parent_pid = unsafe { libc::getpid() };
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != parent_pid {
                return Err(io::Error::from_raw_os_error(libc::EPIPE));
            }
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(|error| {
        RuntimeError::internal(format!("Failed to start Codex app-server: {error}"))
    })?;
    if let Some(stderr) = child.stderr.take() {
        let _ = thread::Builder::new()
            .name("codex-app-server-stderr".to_string())
            .spawn(move || {
                for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                    runtime_log(&format!("app-server stderr: {line}"));
                }
            });
    }

    let process_group = child.id() as libc::pid_t;
    let deadline = Instant::now() + APP_SERVER_START_TIMEOUT;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(status)) => {
                let _ = fs::remove_file(&socket_path);
                return Err(RuntimeError::internal(format!(
                    "Codex app-server exited before becoming ready ({status})"
                )));
            }
            Ok(None) => {}
            Err(error) => {
                let mut process = ManagedProcess {
                    child,
                    entry_id: entry.entry_id.clone(),
                    process_group,
                    proxy_host: entry.proxy_host.clone(),
                    proxy_port,
                    socket_path,
                };
                stop_managed_process(&mut process);
                return Err(RuntimeError::internal(format!(
                    "Failed to inspect Codex app-server: {error}"
                )));
            }
        }
        if socket_is_ready(&socket_path) {
            return Ok(ManagedProcess {
                child,
                entry_id: entry.entry_id.clone(),
                process_group,
                proxy_host: entry.proxy_host.clone(),
                proxy_port,
                socket_path,
            });
        }
        thread::sleep(Duration::from_millis(50));
    }
    let mut process = ManagedProcess {
        child,
        entry_id: entry.entry_id.clone(),
        process_group,
        proxy_host: entry.proxy_host.clone(),
        proxy_port,
        socket_path,
    };
    stop_managed_process(&mut process);
    Err(RuntimeError::internal(
        "Timed out waiting for Codex app-server to start",
    ))
}

fn stop_managed_process(process: &mut ManagedProcess) {
    if process.child.try_wait().ok().flatten().is_none() {
        unsafe {
            libc::kill(-process.process_group, libc::SIGTERM);
        }
        let deadline = Instant::now() + APP_SERVER_STOP_TIMEOUT;
        while Instant::now() < deadline {
            if process.child.try_wait().ok().flatten().is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
        if process.child.try_wait().ok().flatten().is_none() {
            unsafe {
                libc::kill(-process.process_group, libc::SIGKILL);
            }
        }
    }
    let _ = process.child.wait();
    let _ = fs::remove_file(&process.socket_path);
}

fn socket_is_ready(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.file_type().is_socket() && metadata.uid() == unsafe { libc::geteuid() }
    })
}

fn stop_proxy(proxy: &mut ProxyServer) {
    if let Some(shutdown) = proxy.shutdown.take() {
        let _ = shutdown.send(());
    }
    if let Some(join) = proxy.join.take() {
        let _ = join.join();
    }
}

async fn run_proxy(
    listener: TcpListener,
    manager: Arc<RuntimeManager>,
    allowed_origin: String,
    token: String,
    mut shutdown: oneshot::Receiver<()>,
) {
    let listener = match TokioTcpListener::from_std(listener) {
        Ok(listener) => listener,
        Err(error) => {
            runtime_log(&format!("proxy listener setup failed: {error}"));
            return;
        }
    };
    let connection_permits = Arc::new(Semaphore::new(MAX_PROXY_CONNECTIONS));
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                let Ok(permit) = Arc::clone(&connection_permits).try_acquire_owned() else {
                    continue;
                };
                let manager = Arc::clone(&manager);
                let allowed_origin = allowed_origin.clone();
                let token = token.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) = handle_proxy_connection(stream, manager, &allowed_origin, &token).await {
                        runtime_log(&format!("app-server proxy connection failed: {error}"));
                    }
                });
            }
        }
    }
}

async fn handle_proxy_connection(
    stream: tokio::net::TcpStream,
    manager: Arc<RuntimeManager>,
    allowed_origin: &str,
    token: &str,
) -> Result<()> {
    let selected_client = Arc::new(Mutex::new(None::<String>));
    let browser = tokio::time::timeout(
        PROXY_HANDSHAKE_TIMEOUT,
        accept_hdr_async(
            stream,
            ProxyHandshakeCallback {
                allowed_origin: allowed_origin.to_string(),
                selected_client: Arc::clone(&selected_client),
                token: token.to_string(),
            },
        ),
    )
    .await
    .context("browser WebSocket handshake timed out")?
    .context("browser WebSocket handshake failed")?;
    let client_id = selected_client
        .lock()
        .expect("proxy client mutex poisoned")
        .take()
        .context("proxy client id was not selected")?;
    let socket_path = manager
        .process_socket(&client_id)
        .map_err(|error| anyhow::anyhow!(error.message))?;
    let unix = tokio::time::timeout(
        PROXY_HANDSHAKE_TIMEOUT,
        TokioUnixStream::connect(&socket_path),
    )
    .await
    .context("app-server Unix socket connection timed out")?
    .with_context(|| format!("failed to connect {}", socket_path.display()))?;
    let (app_server, _) = tokio::time::timeout(
        PROXY_HANDSHAKE_TIMEOUT,
        client_async("ws://localhost/rpc", unix),
    )
    .await
    .context("app-server WebSocket handshake timed out")?
    .context("app-server WebSocket handshake failed")?;

    let (mut browser_tx, mut browser_rx) = browser.split();
    let (mut app_server_tx, mut app_server_rx) = app_server.split();
    loop {
        tokio::select! {
            message = browser_rx.next() => match message {
                Some(Ok(message)) => {
                    if app_server_tx.send(message).await.is_err() { break; }
                }
                Some(Err(error)) => return Err(error).context("browser WebSocket read failed"),
                None => break,
            },
            message = app_server_rx.next() => match message {
                Some(Ok(message)) => {
                    if browser_tx.send(message).await.is_err() { break; }
                }
                Some(Err(error)) => return Err(error).context("app-server WebSocket read failed"),
                None => break,
            },
        }
    }
    let _ = browser_tx.close().await;
    let _ = app_server_tx.close().await;
    Ok(())
}

fn validate_proxy_request(
    request: &Request,
    allowed_origin: &str,
    expected_token: &str,
) -> std::result::Result<String, &'static str> {
    let origin = request
        .headers()
        .get("origin")
        .and_then(|value| value.to_str().ok())
        .ok_or("Forbidden")?;
    if origin != allowed_origin && origin != format!("{allowed_origin}/") {
        return Err("Forbidden");
    }
    if request.uri().path() != "/" {
        return Err("Not Found");
    }
    parse_proxy_query(request.uri().query(), expected_token)
}

fn parse_proxy_query(
    query: Option<&str>,
    expected_token: &str,
) -> std::result::Result<String, &'static str> {
    let mut token = None;
    let mut client_id = None;
    for item in query.ok_or("Forbidden")?.split('&') {
        let (key, value) = item.split_once('=').ok_or("Forbidden")?;
        if value.contains('%') || !value.is_ascii() {
            return Err("Forbidden");
        }
        match key {
            "token" if token.is_none() => token = Some(value),
            "clientId" if client_id.is_none() => client_id = Some(value),
            _ => return Err("Forbidden"),
        }
    }
    if !constant_time_eq(
        token.ok_or("Forbidden")?.as_bytes(),
        expected_token.as_bytes(),
    ) {
        return Err("Forbidden");
    }
    normalized_client_id(client_id.map(Value::from).as_ref()).map_err(|_| "Forbidden")
}

fn forbidden_response(message: &'static str) -> ErrorResponse {
    let status = if message == "Not Found" {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::FORBIDDEN
    };
    let mut response = ErrorResponse::new(Some(message.to_string()));
    *response.status_mut() = status;
    response
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn normalized_client_id(value: Option<&Value>) -> RuntimeResult<String> {
    let client_id = match value {
        None | Some(Value::Null) => "default",
        Some(Value::String(value)) => value.as_str(),
        Some(_) => return Err(RuntimeError::invalid_params("Invalid clientId")),
    };
    if client_id.is_empty()
        || client_id.len() > MAX_CLIENT_ID_BYTES
        || !client_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(RuntimeError::invalid_params("Invalid clientId"));
    }
    Ok(client_id.to_string())
}

fn required_string<'a>(params: &'a Value, name: &str) -> RuntimeResult<&'a str> {
    params
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| RuntimeError::invalid_params(format!("Missing required parameter: {name}")))
}

fn validate_asset_file_name(file_name: &str) -> RuntimeResult<()> {
    if file_name.len() > 255
        || file_name == "."
        || file_name == ".."
        || file_name.contains('/')
        || file_name.contains('\\')
        || file_name.contains('\0')
    {
        return Err(RuntimeError::invalid_params(
            "Invalid Chrome tab context asset file name",
        ));
    }
    Ok(())
}

fn validate_openable_file(path: &Path) -> RuntimeResult<()> {
    if !path.is_absolute() {
        return Err(RuntimeError::invalid_params(
            "Local file path must be absolute",
        ));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| RuntimeError::invalid_params("Local file does not exist"))?;
    if metadata.file_type().is_symlink() {
        return Err(RuntimeError::invalid_params(
            "Opening symbolic links is not supported",
        ));
    }
    if !metadata.is_file() {
        return Err(RuntimeError::invalid_params("Invalid local file path"));
    }
    let forbidden_extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .is_some_and(|extension| {
            matches!(
                extension.as_str(),
                "command" | "desktop" | "jar" | "terminal" | "tool"
            )
        });
    if forbidden_extension || metadata.permissions().mode() & 0o111 != 0 {
        return Err(RuntimeError::invalid_params(
            "Opening executable files is not supported",
        ));
    }
    Ok(())
}

fn prepare_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "runtime path is not a directory",
        ));
    }
    let euid = unsafe { libc::geteuid() };
    if metadata.uid() != euid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "runtime directory has an unexpected owner",
        ));
    }
    if metadata.permissions().mode() & 0o777 != 0o700 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn has_unsafe_write_permissions(metadata: &fs::Metadata) -> bool {
    let mode = metadata.permissions().mode();
    if mode & 0o002 != 0 {
        return true;
    }
    if mode & 0o020 == 0 {
        return false;
    }
    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };
    metadata.uid() != euid || metadata.gid() != egid
}

fn unique_runtime_root() -> PathBuf {
    let uid = unsafe { libc::geteuid() };
    let base = private_runtime_base(uid);
    let nonce = random_hex(8).unwrap_or_else(|_| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos().to_string())
            .unwrap_or_else(|_| "fallback".to_string())
    });
    let leaf = format!("h-{}-{nonce}", std::process::id());
    let candidate = base.join("cdx-r").join(&leaf);
    if unix_socket_path_fits(&candidate.join("a-0000000000000000.sock")) {
        return candidate;
    }
    PathBuf::from("/tmp")
        .join(format!("cdx-r-{uid}-{nonce}"))
        .join(leaf)
}

fn private_runtime_base(uid: libc::uid_t) -> PathBuf {
    if let Some(path) = env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from) {
        if path.is_absolute()
            && fs::symlink_metadata(&path).is_ok_and(|metadata| {
                metadata.is_dir()
                    && !metadata.file_type().is_symlink()
                    && metadata.uid() == uid
                    && metadata.permissions().mode() & 0o077 == 0
            })
        {
            return path;
        }
    }
    if let Some(home) = env::var_os("HOME").map(PathBuf::from) {
        if home.is_absolute()
            && fs::symlink_metadata(&home).is_ok_and(|metadata| {
                metadata.is_dir() && !metadata.file_type().is_symlink() && metadata.uid() == uid
            })
        {
            return home.join(".cache");
        }
    }
    let nonce = random_hex(16).unwrap_or_else(|_| std::process::id().to_string());
    PathBuf::from("/tmp").join(format!("codex-chrome-runtime-{uid}-{nonce}"))
}

fn random_hex(byte_count: usize) -> io::Result<String> {
    let mut bytes = vec![0_u8; byte_count];
    getrandom::fill(&mut bytes).map_err(io::Error::other)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn unix_socket_path_fits(path: &Path) -> bool {
    path.as_os_str().as_bytes().len() <= MAX_UNIX_SOCKET_PATH_BYTES
}

fn short_hash(value: &[u8]) -> String {
    hex_encode(Sha256::digest(value).as_slice())[..16].to_string()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn executable_in_path(name: &str) -> bool {
    env::var_os("PATH").is_some_and(|path| {
        env::split_paths(&path).any(|directory| {
            fs::metadata(directory.join(name)).is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
    })
}

fn display_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
    }
}

fn runtime_log(message: &str) {
    let _ = writeln!(io::stderr(), "[chrome-runtime] {message}");
}

pub fn is_runtime_request(message: &Value) -> bool {
    message.get("id").is_some()
        && message
            .get("method")
            .and_then(Value::as_str)
            .is_some_and(|method| method.starts_with("codexRuntime/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn parses_proxy_query_and_rejects_untrusted_inputs() {
        assert_eq!(
            parse_proxy_query(Some("token=secret&clientId=sidepanel-window-42"), "secret"),
            Ok("sidepanel-window-42".to_string())
        );
        assert_eq!(
            parse_proxy_query(Some("token=secret"), "secret"),
            Ok("default".to_string())
        );
        assert!(parse_proxy_query(Some("token=wrong"), "secret").is_err());
        assert!(parse_proxy_query(Some("token=secret&token=secret"), "secret").is_err());
        assert!(parse_proxy_query(Some("token=secret&clientId=../escape"), "secret").is_err());
        assert!(parse_proxy_query(Some("token=secret&extra=value"), "secret").is_err());
        assert!(parse_proxy_query(Some("clientId=default&token=secret"), "secret").is_ok());
        assert!(parse_proxy_query(Some("token=secret&clientId=a%2Fb"), "secret").is_err());
    }

    #[test]
    fn proxy_request_requires_exact_origin_path_and_token() {
        let request = Request::builder()
            .uri("/?token=secret&clientId=sidepanel-window-7")
            .header("origin", "chrome-extension://abcdefghijklmnop")
            .body(())
            .unwrap();
        assert_eq!(
            validate_proxy_request(&request, "chrome-extension://abcdefghijklmnop", "secret"),
            Ok("sidepanel-window-7".to_string())
        );

        let wrong_origin = Request::builder()
            .uri("/?token=secret")
            .header("origin", "https://example.com")
            .body(())
            .unwrap();
        assert!(validate_proxy_request(
            &wrong_origin,
            "chrome-extension://abcdefghijklmnop",
            "secret"
        )
        .is_err());

        let wrong_path = Request::builder()
            .uri("/rpc?token=secret")
            .header("origin", "chrome-extension://abcdefghijklmnop")
            .body(())
            .unwrap();
        assert!(validate_proxy_request(
            &wrong_path,
            "chrome-extension://abcdefghijklmnop",
            "secret"
        )
        .is_err());
    }

    #[test]
    fn proxy_reuses_an_available_port_when_the_requested_port_is_busy() {
        let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let requested_port = occupied.local_addr().unwrap().port();
        let root = test_root("proxy-port-fallback");
        let manager = Arc::new(RuntimeManager::with_runtime_root(
            Some("abcdefghijklmnopabcdefghijklmnop".to_string()),
            root.clone(),
            None,
        ));
        let mut entry = test_entry();
        entry.proxy_port = requested_port;

        let (first_address, first_token) = manager.ensure_proxy(&entry).unwrap();
        assert_eq!(first_address.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_ne!(first_address.port(), requested_port);
        let (second_address, second_token) = manager.ensure_proxy(&entry).unwrap();
        assert_eq!(second_address, first_address);
        assert_eq!(second_token, first_token);

        manager.shutdown();
        assert!(!root.exists());
    }

    #[test]
    fn validates_client_ids() {
        assert_eq!(normalized_client_id(None).unwrap(), "default");
        assert_eq!(
            normalized_client_id(Some(&json!("sidepanel-window-7"))).unwrap(),
            "sidepanel-window-7"
        );
        assert!(normalized_client_id(Some(&json!(""))).is_err());
        assert!(normalized_client_id(Some(&json!("../sidepanel"))).is_err());
        assert!(normalized_client_id(Some(&json!(7))).is_err());
        assert!(normalized_client_id(Some(&json!("a".repeat(MAX_CLIENT_ID_BYTES + 1)))).is_err());
    }

    #[test]
    fn runtime_requests_return_structured_errors_for_bad_input() {
        let manager = Arc::new(RuntimeManager::with_runtime_root(
            Some("abcdefghijklmnopabcdefghijklmnop".to_string()),
            test_root("request-errors"),
            None,
        ));
        let unknown = manager.handle_request(&json!({
            "jsonrpc": "2.0",
            "id": "unknown",
            "method": "codexRuntime/notSupported",
            "params": {}
        }));
        assert_eq!(unknown["error"]["code"], -32601);

        let malformed = manager.handle_request(&json!({
            "jsonrpc": "2.0",
            "id": "malformed",
            "method": "codexRuntime/hello",
            "params": { "constraints": [] }
        }));
        assert_eq!(malformed["error"]["code"], -32602);
        manager.shutdown();
    }

    #[test]
    fn tab_context_asset_lifecycle_is_bounded_and_idempotent() {
        let root = test_root("asset-lifecycle");
        let manager = Arc::new(RuntimeManager::with_runtime_root(None, root.clone(), None));
        let created = manager
            .create_asset(&json!({ "fileName": "capture.txt" }))
            .unwrap();
        let asset_id = created["assetId"].as_str().unwrap();
        let path = PathBuf::from(created["path"].as_str().unwrap());

        manager
            .append_asset(&json!({ "assetId": asset_id, "dataBase64": "aGVsbG8=" }))
            .unwrap();
        let finished = manager
            .finish_asset(&json!({ "assetId": asset_id }))
            .unwrap();
        assert_eq!(finished["path"], created["path"]);
        assert!(manager
            .finish_asset(&json!({ "assetId": asset_id }))
            .is_ok());
        assert_eq!(fs::read(&path).unwrap(), b"hello");
        assert!(manager
            .append_asset(&json!({ "assetId": asset_id, "dataBase64": "IQ==" }))
            .is_err());
        manager
            .remove_asset(&json!({ "assetId": asset_id }))
            .unwrap();
        assert!(!path.exists());
        assert!(manager
            .remove_asset(&json!({ "assetId": asset_id }))
            .is_err());
        manager.shutdown();
        assert!(!root.exists());
    }

    #[test]
    fn tab_context_assets_reject_traversal_and_invalid_base64() {
        let root = test_root("asset-invalid");
        let manager = Arc::new(RuntimeManager::with_runtime_root(None, root, None));
        assert!(manager
            .create_asset(&json!({ "fileName": "../escape.txt" }))
            .is_err());
        let created = manager
            .create_asset(&json!({ "fileName": "safe.txt" }))
            .unwrap();
        assert!(manager
            .append_asset(&json!({
                "assetId": created["assetId"],
                "dataBase64": "not base64"
            }))
            .is_err());
        assert!(manager
            .append_asset(&json!({
                "assetId": created["assetId"],
                "dataBase64": "A".repeat(MAX_ASSET_CHUNK_BASE64 + 1)
            }))
            .is_err());
        {
            let mut assets = manager.assets.lock().unwrap();
            assets
                .get_mut(created["assetId"].as_str().unwrap())
                .unwrap()
                .size = MAX_ASSET_BYTES;
        }
        assert!(manager
            .append_asset(&json!({
                "assetId": created["assetId"],
                "dataBase64": "YQ=="
            }))
            .is_err());
        manager.shutdown();
    }

    #[test]
    fn tab_context_asset_count_is_bounded() {
        let root = test_root("asset-count");
        let manager = Arc::new(RuntimeManager::with_runtime_root(None, root, None));
        for index in 0..MAX_ACTIVE_ASSETS {
            manager
                .create_asset(&json!({ "fileName": format!("capture-{index}.txt") }))
                .unwrap();
        }
        assert!(manager
            .create_asset(&json!({ "fileName": "one-too-many.txt" }))
            .is_err());
        manager.shutdown();
        manager.shutdown();
    }

    #[test]
    fn open_local_file_validation_rejects_symlinks_and_executables() {
        use std::os::unix::fs::symlink;

        let root = test_root("open-file");
        fs::create_dir_all(&root).unwrap();
        let regular = root.join("document.txt");
        fs::write(&regular, "ok").unwrap();
        assert!(validate_openable_file(&regular).is_ok());

        let executable = root.join("run.sh");
        fs::write(&executable, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(validate_openable_file(&executable).is_err());

        let desktop = root.join("launcher.desktop");
        fs::write(&desktop, "[Desktop Entry]\n").unwrap();
        assert!(validate_openable_file(&desktop).is_err());

        let link = root.join("link.txt");
        symlink(&regular, &link).unwrap();
        assert!(validate_openable_file(&link).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn entry_matching_requires_all_protocol_and_identity_constraints() {
        let constraints = test_constraints();
        let entry = test_entry();
        assert!(entry.matches(&constraints));

        let mut wrong_protocol = entry.clone();
        wrong_protocol.app_server_protocol_version = 3;
        assert!(!wrong_protocol.matches(&constraints));

        let mut wrong_extension = entry;
        wrong_extension.extension_ids = vec!["other".to_string()];
        assert!(!wrong_extension.matches(&constraints));
    }

    #[test]
    fn manifest_selection_ignores_newer_entry_for_another_host() {
        let root = test_root("manifest-selection");
        fs::create_dir_all(&root).unwrap();
        let manifest_path = root.join(MANIFEST_FILE_NAME);
        let current_host = PathBuf::from("/proc/self/exe");
        fs::write(
            &manifest_path,
            serde_json::to_vec(&json!({
                "schemaVersion": 2,
                "entries": [
                    manifest_entry_json("other-host", Path::new("/bin/true"), "2099-01-01T00:00:00Z"),
                    manifest_entry_json("current-host", &current_host, "2026-07-10T00:00:00Z")
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        let selected = select_runtime_entry(&test_constraints(), Some(&[manifest_path])).unwrap();
        assert_eq!(selected.entry_id, "current-host");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn manifest_selection_reports_missing_invalid_and_no_match() {
        let root = test_root("manifest-errors");
        fs::create_dir_all(&root).unwrap();
        let missing = root.join("missing.json");
        assert_eq!(
            select_runtime_entry(&test_constraints(), Some(&[missing]))
                .unwrap_err()
                .kind,
            Some("manifest_missing")
        );

        let invalid = root.join("invalid.json");
        fs::write(&invalid, "not-json").unwrap();
        assert_eq!(
            select_runtime_entry(&test_constraints(), Some(&[invalid]))
                .unwrap_err()
                .kind,
            Some("manifest_invalid")
        );

        let no_match = root.join("no-match.json");
        fs::write(
            &no_match,
            serde_json::to_vec(&json!({
                "schemaVersion": 2,
                "entries": [manifest_entry_json(
                    "wrong-extension",
                    Path::new("/proc/self/exe"),
                    "2026-07-10T00:00:00Z"
                )]
            }))
            .unwrap(),
        )
        .unwrap();
        let mut constraints = test_constraints();
        constraints.extension_id = "other-extension".to_string();
        assert_eq!(
            select_runtime_entry(&constraints, Some(&[no_match]))
                .unwrap_err()
                .kind,
            Some("no_matching_codex_install")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn runtime_paths_reject_world_writable_files_and_accept_private_group_mode() {
        let root = test_root("path-permissions");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("binary");
        fs::write(&path, "binary").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(!has_unsafe_write_permissions(&fs::metadata(&path).unwrap()));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(has_unsafe_write_permissions(&fs::metadata(&path).unwrap()));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn executable_validation_rejects_a_world_writable_parent() {
        let root = test_root("unsafe-parent");
        let unsafe_parent = root.join("shared");
        fs::create_dir_all(&unsafe_parent).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777)).unwrap();
        let executable = unsafe_parent.join("codex");
        fs::write(&executable, "binary").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(validate_owned_file(&executable, true).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn socket_readiness_requires_an_owned_unix_socket() {
        let root = test_root("socket-ready");
        fs::create_dir_all(&root).unwrap();
        let regular = root.join("regular.sock");
        fs::write(&regular, "not a socket").unwrap();
        assert!(!socket_is_ready(&regular));

        let socket = root.join("real.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        assert!(socket_is_ready(&socket));
        drop(listener);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn runtime_socket_paths_stay_within_the_linux_sun_path_limit() {
        let root = unique_runtime_root();
        assert!(unix_socket_path_fits(&root.join("a-0000000000000000.sock")));
        assert!(!unix_socket_path_fits(
            &PathBuf::from("/tmp").join("x".repeat(MAX_UNIX_SOCKET_PATH_BYTES))
        ));
    }

    #[test]
    fn process_reuse_requires_the_current_proxy_endpoint() {
        let root = test_root("process-reuse");
        fs::create_dir_all(&root).unwrap();
        let socket = root.join("app-server.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let mut command = Command::new("sleep");
        command.arg("300");
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().unwrap();
        let process_group = child.id() as libc::pid_t;
        let mut process = ManagedProcess {
            child,
            entry_id: "entry".to_string(),
            process_group,
            proxy_host: "127.0.0.1".to_string(),
            proxy_port: 41000,
            socket_path: socket,
        };
        let entry = test_entry();
        assert!(process_is_reusable(&mut process, &entry, 41000, false).unwrap());
        assert!(!process_is_reusable(&mut process, &entry, 41001, false).unwrap());
        assert!(!process_is_reusable(&mut process, &entry, 41000, true).unwrap());
        stop_managed_process(&mut process);
        drop(listener);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn desktop_agent_modes_support_current_persisted_state_shape() {
        let root = test_root("agent-modes");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join(".codex-global-state.json"),
            serde_json::to_vec(&json!({
                "electron-persisted-atom-state": {
                    "agent-mode-by-host-id": { "local": "full-access" },
                    "preferred-non-full-access-agent-mode-by-host-id": { "local": "workspace-write" }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let defaults = desktop_agent_mode_defaults(&root).unwrap();
        assert_eq!(defaults["agentModesByHostId"]["local"], "full-access");
        assert_eq!(
            defaults["preferredNonFullAccessModesByHostId"]["local"],
            "workspace-write"
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn test_constraints() -> RuntimeConstraints {
        RuntimeConstraints {
            extension_build_channel: "prod".to_string(),
            extension_id: "abcdefghijklmnopabcdefghijklmnop".to_string(),
            extension_version: "1.2.3".to_string(),
            native_host_name: "com.openai.codexextension".to_string(),
            required_app_server_protocol_version: 2,
            required_native_host_protocol_version: 2,
        }
    }

    fn test_entry() -> RuntimeEntry {
        RuntimeEntry {
            schema_version: 2,
            app_server_protocol_version: 2,
            app_version: "1.2.3".to_string(),
            channel: "prod".to_string(),
            cli_version: "1.2.3".to_string(),
            entry_id: "entry".to_string(),
            extension_build_channels: vec!["prod".to_string()],
            extension_ids: vec!["abcdefghijklmnopabcdefghijklmnop".to_string()],
            install_id: "install".to_string(),
            native_host_names: vec!["com.openai.codexextension".to_string()],
            native_host_protocol_version: 2,
            native_host_version: "1.2.3".to_string(),
            paths: RuntimePaths {
                browser_client_path: None,
                codex_cli_path: PathBuf::from("/bin/true"),
                codex_home: PathBuf::from("/tmp"),
                extension_host_path: PathBuf::from("/bin/true"),
                node_path: PathBuf::from("/bin/true"),
                node_module_dirs: Vec::new(),
                node_repl_path: None,
                resources_path: PathBuf::from("/tmp"),
            },
            proxy_host: "127.0.0.1".to_string(),
            proxy_port: 0,
            updated_at: "2026-07-10T00:00:00Z".to_string(),
        }
    }

    fn manifest_entry_json(entry_id: &str, extension_host_path: &Path, updated_at: &str) -> Value {
        json!({
            "schemaVersion": 2,
            "appServerProtocolVersion": 2,
            "appVersion": "1.2.3",
            "channel": "prod",
            "cliVersion": "1.2.3",
            "entryId": entry_id,
            "extensionBuildChannels": ["prod"],
            "extensionIds": ["abcdefghijklmnopabcdefghijklmnop"],
            "installId": "install",
            "nativeHostNames": ["com.openai.codexextension"],
            "nativeHostProtocolVersion": 2,
            "nativeHostVersion": "1.2.3",
            "paths": {
                "codexCliPath": "/bin/true",
                "codexHome": "/tmp",
                "extensionHostPath": extension_host_path,
                "nodePath": "/bin/true",
                "resourcesPath": "/tmp"
            },
            "proxyHost": "127.0.0.1",
            "proxyPort": 0,
            "updatedAt": updated_at
        })
    }

    fn test_root(name: &str) -> PathBuf {
        env::temp_dir().join(format!(
            "chrome-runtime-test-{name}-{}-{}",
            std::process::id(),
            random_hex(4).unwrap()
        ))
    }
}
