-- 006_plugins.sql — Plugin registry schema
-- Spec: 01#31 PLUGIN AND ADAPTER ARCHITECTURE, 06#43-45 PLUGIN SECURITY/PERMISSIONS/TRUST,
--       04#52 PLUGIN-BASED EXTENSIBILITY, 08#68 PLUGIN EXTENSIBILITY.
--
-- Trust levels: CORE_TRUSTED | VERIFIED | LOCAL | THIRD_PARTY | UNTRUSTED | BLOCKED
-- Permissions (declared by the plugin, never assumed): network.access,
--   filesystem.read, filesystem.write, tool.execute, database.read, database.write
-- Status: INSTALLED | ENABLED | DISABLED | BLOCKED | UNINSTALLED

CREATE TABLE IF NOT EXISTS plugin_registry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plugin_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    author TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT 'other',
    trust_level TEXT NOT NULL DEFAULT 'THIRD_PARTY',
    status TEXT NOT NULL DEFAULT 'INSTALLED',
    source TEXT NOT NULL DEFAULT 'user',          -- bundled | user
    path TEXT NOT NULL,
    permissions TEXT NOT NULL DEFAULT '[]',       -- JSON list of declared permissions
    capabilities TEXT NOT NULL DEFAULT '[]',      -- JSON list of provided capabilities
    manifest_sha256 TEXT NOT NULL,
    installed_by TEXT NOT NULL DEFAULT '',
    installed_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);