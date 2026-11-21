import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { open, save } from '@tauri-apps/plugin-dialog';
import { readText, writeText } from '@tauri-apps/plugin-clipboard-manager';
import { getCurrentWebview } from '@tauri-apps/api/webview';

const event = (name, cb) => {
  listen(name, ({ payload }) => cb(...(Array.isArray(payload) ? payload : [payload])));
};

export const api = {
  listSessions: () => invoke('sessions_list'),
  saveSession: (s) => invoke('sessions_save', { input: s }),
  deleteSession: (id) => invoke('sessions_delete', { id }),
  pickKey: () => open({ title: 'Elegir clave privada', defaultPath: `${home}/.ssh`, multiple: false }),
  connect: (opts) => invoke('ssh_connect', { opts }),
  trustHost: (hostId, fingerprint) => invoke('known_host_trust', { hostId, fingerprint }),
  write: (id, data) => invoke('terminal_write', { id, data }),
  resize: (id, cols, rows) => invoke('terminal_resize', { id, cols, rows }),
  disconnect: (id) => invoke('terminal_disconnect', { id }),
  onData: (cb) => event('ssh:data', cb),
  onStatus: (cb) => event('ssh:status', cb),
  onClosed: (cb) => event('ssh:closed', cb),
  onProgress: (cb) => event('sftp:progress', cb),
  onStats: (cb) => event('ssh:stats', cb),
  local: {
    shells: () => invoke('local_shells'),
    open: (opts) => invoke('local_open', { opts }),
  },
  sftp: {
    home: (id) => invoke('sftp_home', { id }),
    list: (id, dir) => invoke('sftp_list', { id, dir }),
    download: async (id, remotePath) => {
      const localPath = await save({ title: 'Guardar archivo', defaultPath: remotePath.split('/').pop() });
      return localPath ? invoke('sftp_download', { id, remotePath, localPath }) : false;
    },
    upload: async (id, remoteDir) => {
      const paths = await open({ title: 'Subir archivos', multiple: true });
      return paths?.length ? invoke('sftp_upload', { id, remoteDir, localPaths: paths }) : 0;
    },
    uploadDropped: (id, remoteDir, localPaths) => invoke('sftp_upload', { id, remoteDir, localPaths }),
    mkdir: (id, remotePath) => invoke('sftp_mkdir', { id, remotePath }),
    remove: (id, remotePath, isDir) => invoke('sftp_remove', { id, remotePath, isDir }),
    rename: (id, from, to) => invoke('sftp_rename', { id, from, to }),
    setSudo: (id, on) => invoke('sftp_set_sudo', { id, on }),
    edit: (id, remotePath) => invoke('sftp_edit', { id, remotePath }),
  },
  onEdited: (cb) => event('sftp:edited', cb),
  onFileDrop: (cb) => getCurrentWebview().onDragDropEvent(cb),
  editor: {
    get: () => invoke('editor_get'),
    choose: async () => {
      const editorPath = await open({ title: 'Elegir editor', multiple: false });
      return editorPath ? invoke('editor_set', { editorPath }) : invoke('editor_get');
    },
    useSystem: () => invoke('editor_use_system'),
  },
  mcp: {
    get: () => invoke('mcp_get'),
    set: (change) => invoke('mcp_set', { change }),
    newToken: () => invoke('mcp_new_token'),
    copy: (kind) => invoke('mcp_copy', { kind }),
  },
  agent: {
    onApproval: (cb) => event('agent:approval', cb),
    respond: (requestId, decision) => invoke('agent_approval_respond', { requestId, decision }),
    onOpenRequest: (cb) => event('agent:open', cb),
    respondOpen: (requestId, result) => invoke('agent_open_respond', { requestId, result }),
    onPerm: (cb) => event('agent:perm', cb),
    revoke: (tab) => invoke('agent_revoke', { tab }),
    grant: (tab) => invoke('agent_grant', { tab }),
  },
  onSessionsChanged: (cb) => event('sessions:changed', cb),
  clipboard: { read: () => readText(), write: (text) => writeText(text) },
};

const home = await invoke('home_dir');
