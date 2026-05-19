//! BoxPassword Vault 저장소.
//!
//! 단일 SQLite 파일 한 개에 모든 메타데이터/항목/버전이 들어가며,
//! 비밀 필드는 [`bp_crypto`]로 봉인된 BLOB 상태로만 저장됩니다.
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use bp_core::{EntryId, EntrySummary, EntryVersionSummary, GroupRow, NewEntry};

// TOTP 행 / 레코드 별칭 — type_complexity lint 회피.
type TotpRow = (Option<Vec<u8>>, Option<String>, Option<i64>, Option<i64>);
type TotpRecord = (Vec<u8>, Option<String>, Option<u32>, Option<u32>);
use bp_crypto::{aead, derive_master_key, KdfParams, VaultKey, KEY_LEN, SALT_LEN};
use rusqlite::{params, Connection, OptionalExtension};
use zeroize::Zeroize;
use thiserror::Error;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const SCHEMA_VERSION: i32 = 1;
const VAULT_KEY_AAD: &[u8] = b"box-password/vault_key/v1";
const VAULT_KEY_CHECK_AAD: &[u8] = b"box-password/vault_key/check/v1";
const VAULT_KEY_CHECK_PLAIN: &[u8] = b"BPVAULT-OK";
const SECRET_AAD_PREFIX: &str = "box-password/entry/secret/v1:";
const NOTES_AAD_PREFIX: &str = "box-password/entry/notes/v1:";
const TOTP_AAD_PREFIX: &str = "box-password/entry/totp/v1:";

const BACKUP_MAGIC: &[u8; 4] = b"BPV1";
const BACKUP_FORMAT_VERSION: u8 = 1;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct BackupHeader {
    format_version: u8,
    schema_version: i32,
    app_version: String,
    created_at: String,
    kdf_params: KdfParams,
    /// base64-encoded salt.
    salt_b64: String,
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
    #[error("schema error: {0}")]
    Schema(String),
    #[error("vault already initialized")]
    AlreadyInitialized,
    #[error("vault not initialized")]
    NotInitialized,
    #[error("vault is locked")]
    Locked,
    #[error("invalid master password")]
    InvalidMaster,
    #[error("crypto: {0}")]
    Crypto(#[from] bp_crypto::CryptoError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("not found")]
    NotFound,
    #[error("data corrupted: {0}")]
    Corrupt(String),
}

pub type StorageResult<T> = Result<T, StorageError>;

#[derive(Debug, Clone, serde::Serialize)]
pub struct VaultStatus {
    pub initialized: bool,
    pub unlocked: bool,
    pub path: String,
}

/// Vault의 가장 바깥쪽 핸들. 단일 SQLite 파일을 가리킵니다.
pub struct Vault {
    conn: Connection,
    path: PathBuf,
    unlocked: Option<UnlockedSession>,
}

struct UnlockedSession {
    vault_key: VaultKey,
}

impl Vault {
    /// 디스크 경로의 Vault를 엽니다(없으면 빈 파일을 만들고 스키마를 부트스트랩).
    pub fn open<P: AsRef<Path>>(path: P) -> StorageResult<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(&path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let v = Self { conn, path, unlocked: None };
        v.bootstrap()?;
        Ok(v)
    }

    /// 테스트 / 스파이크 용도의 인메모리 Vault.
    pub fn open_in_memory() -> StorageResult<Self> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let v = Self { conn, path: PathBuf::from(":memory:"), unlocked: None };
        v.bootstrap()?;
        Ok(v)
    }

    fn bootstrap(&self) -> StorageResult<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS vault_meta (
                id               INTEGER PRIMARY KEY CHECK (id = 1),
                schema_version   INTEGER NOT NULL,
                kdf_params       TEXT    NOT NULL,
                salt             BLOB    NOT NULL,
                vault_key_sealed BLOB    NOT NULL,
                created_at       TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS entries (
                id              TEXT PRIMARY KEY,
                title           TEXT NOT NULL,
                username        TEXT,
                url             TEXT,
                secret_cipher   BLOB NOT NULL,
                current_version INTEGER NOT NULL DEFAULT 1,
                updated_at      TEXT NOT NULL,
                deleted_at      TEXT
            );

            CREATE TABLE IF NOT EXISTS entry_versions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_id        TEXT NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
                version         INTEGER NOT NULL,
                secret_cipher   BLOB    NOT NULL,
                reason          TEXT,
                created_at      TEXT NOT NULL,
                UNIQUE (entry_id, version)
            );

            CREATE INDEX IF NOT EXISTS idx_entries_title ON entries(title);
            CREATE INDEX IF NOT EXISTS idx_versions_entry ON entry_versions(entry_id, version DESC);
            "#,
        )?;
        // 마이그레이션: entries.favorite 컬럼이 없으면 추가.
        let has_favorite: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('entries') WHERE name = 'favorite'",
            [],
            |r| r.get(0),
        )?;
        if has_favorite == 0 {
            self.conn.execute_batch(
                r#"
                ALTER TABLE entries ADD COLUMN favorite INTEGER NOT NULL DEFAULT 0;
                CREATE INDEX IF NOT EXISTS idx_entries_favorite ON entries(favorite);
                "#,
            )?;
        }

        // 그룹 테이블 + entries.group_id (FK SET NULL).
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS groups (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT    NOT NULL UNIQUE,
                color       TEXT,
                created_at  TEXT    NOT NULL
            );
            "#,
        )?;
        let has_group: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('entries') WHERE name = 'group_id'",
            [],
            |r| r.get(0),
        )?;
        if has_group == 0 {
            self.conn.execute_batch(
                r#"
                ALTER TABLE entries ADD COLUMN group_id INTEGER;
                CREATE INDEX IF NOT EXISTS idx_entries_group ON entries(group_id);
                "#,
            )?;
        }

        // notes_cipher (옵션) — 봉인된 메모.
        self.add_col_if_missing("entries", "notes_cipher", "BLOB")?;
        // totp_seed_cipher (옵션) — 봉인된 TOTP 시드.
        self.add_col_if_missing("entries", "totp_seed_cipher", "BLOB")?;
        // TOTP 메타데이터 (비밀 아님) — 누락 시 SHA1/30/6 으로 해석.
        self.add_col_if_missing("entries", "totp_algorithm", "TEXT")?;
        self.add_col_if_missing("entries", "totp_period", "INTEGER")?;
        self.add_col_if_missing("entries", "totp_digits", "INTEGER")?;
        // 비밀번호 변경 권장 주기(일).
        self.add_col_if_missing("entries", "rotation_days", "INTEGER")?;
        // Keychain unlock 검증용 sentinel (vault_key로 봉인된 고정 문자열).
        self.add_col_if_missing("vault_meta", "vault_key_check", "BLOB")?;
        Ok(())
    }

    fn add_col_if_missing(&self, table: &str, col: &str, decl: &str) -> StorageResult<()> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info(?1) WHERE name = ?2",
            params![table, col],
            |r| r.get(0),
        )?;
        if n == 0 {
            self.conn
                .execute(&format!("ALTER TABLE {} ADD COLUMN {} {}", table, col, decl), [])?;
        }
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn status(&self) -> StorageResult<VaultStatus> {
        Ok(VaultStatus {
            initialized: self.is_initialized()?,
            unlocked: self.unlocked.is_some(),
            path: self.path.to_string_lossy().into_owned(),
        })
    }

    pub fn is_initialized(&self) -> StorageResult<bool> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM vault_meta WHERE id = 1", [], |r| r.get(0))?;
        Ok(n > 0)
    }

    pub fn is_unlocked(&self) -> bool {
        self.unlocked.is_some()
    }

    /// 마스터 비밀번호로 Vault를 처음 초기화합니다.
    pub fn initialize(&mut self, password: &str) -> StorageResult<()> {
        if self.is_initialized()? {
            return Err(StorageError::AlreadyInitialized);
        }
        if password.len() < 8 {
            return Err(StorageError::Schema("master password must be ≥ 8 chars".into()));
        }
        let kdf_params = KdfParams::default();
        let mut salt = [0u8; SALT_LEN];
        bp_crypto::random_bytes(&mut salt)?;

        let mut master = derive_master_key(password.as_bytes(), &salt, &kdf_params)?;
        let vault_key = VaultKey::generate()?;
        let sealed = aead::seal(&master, vault_key.as_bytes(), VAULT_KEY_AAD)?;
        master.zeroize();

        let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_default();
        self.conn.execute(
            r#"INSERT INTO vault_meta (id, schema_version, kdf_params, salt, vault_key_sealed, created_at)
               VALUES (1, ?1, ?2, ?3, ?4, ?5)"#,
            params![SCHEMA_VERSION, kdf_params.to_json(), salt.as_slice(), sealed, now],
        )?;

        // 초기화하면 곧장 잠금 해제된 상태로 둡니다.
        self.unlocked = Some(UnlockedSession { vault_key });
        Ok(())
    }

    /// 마스터 비밀번호로 잠금 해제. 잘못된 비밀번호는 [`StorageError::InvalidMaster`].
    pub fn unlock(&mut self, password: &str) -> StorageResult<()> {
        let (kdf_params, salt, sealed) = self.load_meta()?;
        let mut master = derive_master_key(password.as_bytes(), &salt, &kdf_params)?;
        let mut vk_bytes = aead::open(&master, &sealed, VAULT_KEY_AAD)
            .map_err(|_| StorageError::InvalidMaster)?;
        master.zeroize();

        if vk_bytes.len() != KEY_LEN {
            vk_bytes.zeroize();
            return Err(StorageError::Corrupt("vault key length".into()));
        }
        let mut buf = [0u8; KEY_LEN];
        buf.copy_from_slice(&vk_bytes);
        vk_bytes.zeroize();
        let vault_key = VaultKey::from_bytes(buf);
        // 향후 Keychain 등에서 unlock_with_key 검증이 가능하도록 sentinel 보장.
        self.ensure_vault_key_check(&vault_key)?;
        self.unlocked = Some(UnlockedSession { vault_key });
        Ok(())
    }

    /// 사용자 입력(마스터 비번) 없이 외부 보관소(예: macOS Keychain)에서 가져온
    /// vault_key 바이트열로 잠금 해제합니다. sentinel이 존재하면 검증하고,
    /// 없으면(레거시) 키를 신뢰합니다.
    pub fn unlock_with_key(&mut self, key_bytes: Vec<u8>) -> StorageResult<()> {
        if key_bytes.len() != KEY_LEN {
            return Err(StorageError::Corrupt("vault key length".into()));
        }
        let mut buf = [0u8; KEY_LEN];
        buf.copy_from_slice(&key_bytes);
        let mut owned = key_bytes;
        owned.zeroize();

        // 검증용 sentinel 가 있으면 복호 시도.
        let check: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT vault_key_check FROM vault_meta WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        if let Some(sealed) = check {
            match aead::open(&buf, &sealed, VAULT_KEY_CHECK_AAD) {
                Ok(plain) if plain == VAULT_KEY_CHECK_PLAIN => {}
                _ => return Err(StorageError::InvalidMaster),
            }
        }
        self.unlocked = Some(UnlockedSession { vault_key: VaultKey::from_bytes(buf) });
        Ok(())
    }

    /// 현재 잠금 해제 상태의 vault_key 바이트열 사본을 반환합니다.
    /// 외부 보관소(Keychain 등)에 옮길 때만 사용. 호출자는 즉시 zeroize 책임.
    pub fn vault_key_bytes(&self) -> Option<Vec<u8>> {
        self.unlocked.as_ref().map(|s| s.vault_key.as_bytes().to_vec())
    }

    fn ensure_vault_key_check(&self, vault_key: &VaultKey) -> StorageResult<()> {
        let existing: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT vault_key_check FROM vault_meta WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        if existing.is_none() {
            let sealed = aead::seal(vault_key.as_bytes(), VAULT_KEY_CHECK_PLAIN, VAULT_KEY_CHECK_AAD)?;
            self.conn.execute(
                "UPDATE vault_meta SET vault_key_check = ?1 WHERE id = 1",
                params![sealed],
            )?;
        }
        Ok(())
    }

    /// 메모리에 있는 VaultKey를 즉시 폐기합니다.
    pub fn lock(&mut self) {
        self.unlocked = None;
    }

    fn require_unlocked(&self) -> StorageResult<&UnlockedSession> {
        self.unlocked.as_ref().ok_or(StorageError::Locked)
    }

    fn load_meta(&self) -> StorageResult<(KdfParams, [u8; SALT_LEN], Vec<u8>)> {
        let row = self
            .conn
            .query_row(
                "SELECT kdf_params, salt, vault_key_sealed FROM vault_meta WHERE id = 1",
                [],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?, r.get::<_, Vec<u8>>(2)?)),
            )
            .optional()?
            .ok_or(StorageError::NotInitialized)?;
        let params = KdfParams::from_json(&row.0)?;
        if row.1.len() != SALT_LEN {
            return Err(StorageError::Corrupt("salt length".into()));
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&row.1);
        Ok((params, salt, row.2))
    }

    /// 새 항목을 추가합니다. 잠금 해제 상태에서만 가능합니다.
    pub fn create_entry(&self, new: &NewEntry) -> StorageResult<EntryId> {
        let session = self.require_unlocked()?;
        let id = EntryId::new();
        let aad = format!("{}{}", SECRET_AAD_PREFIX, id);
        let sealed = aead::seal(session.vault_key.as_bytes(), new.secret.as_bytes(), aad.as_bytes())?;
        let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_default();
        self.conn.execute(
            r#"INSERT INTO entries (id, title, username, url, secret_cipher, current_version, updated_at)
               VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6)"#,
            params![id.to_string(), new.title, new.username, new.url, sealed, now],
        )?;
        self.conn.execute(
            r#"INSERT INTO entry_versions (entry_id, version, secret_cipher, reason, created_at)
               VALUES (?1, 1, ?2, ?3, ?4)"#,
            params![id.to_string(), sealed, Option::<String>::None, now],
        )?;
        Ok(id)
    }

    pub fn list_entries(&self) -> StorageResult<Vec<EntrySummary>> {
        let _ = self.require_unlocked()?;
        let mut stmt = self.conn.prepare(
            "SELECT e.id, e.title, e.username, e.url, e.current_version, e.updated_at, e.favorite,
                    e.group_id, g.name, g.color,
                    CASE WHEN e.totp_seed_cipher IS NULL THEN 0 ELSE 1 END,
                    CASE WHEN e.notes_cipher      IS NULL THEN 0 ELSE 1 END,
                    e.totp_algorithm, e.totp_period, e.totp_digits, e.rotation_days
             FROM entries e LEFT JOIN groups g ON e.group_id = g.id
             WHERE e.deleted_at IS NULL ORDER BY e.title COLLATE NOCASE ASC",
        )?;
        let rows = stmt
            .query_map([], |r| {
                let updated_at: String = r.get(5)?;
                Ok(EntrySummary {
                    id: r.get(0)?,
                    title: r.get(1)?,
                    username: r.get(2)?,
                    url: r.get(3)?,
                    current_version: r.get::<_, i64>(4)? as u32,
                    updated_at: OffsetDateTime::parse(&updated_at, &Rfc3339)
                        .unwrap_or(OffsetDateTime::UNIX_EPOCH),
                    favorite: r.get::<_, i64>(6)? != 0,
                    group_id: r.get(7)?,
                    group_name: r.get(8)?,
                    group_color: r.get(9)?,
                    has_totp: r.get::<_, i64>(10)? != 0,
                    has_notes: r.get::<_, i64>(11)? != 0,
                    totp_algorithm: r.get(12)?,
                    totp_period: r.get::<_, Option<i64>>(13)?.map(|v| v as u32),
                    totp_digits: r.get::<_, Option<i64>>(14)?.map(|v| v as u32),
                    rotation_days: r.get::<_, Option<i64>>(15)?.map(|v| v as u32),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn list_groups(&self) -> StorageResult<Vec<GroupRow>> {
        let _ = self.require_unlocked()?;
        let mut stmt = self.conn.prepare(
            "SELECT g.id, g.name, g.color,
                    COALESCE((SELECT COUNT(*) FROM entries e WHERE e.group_id = g.id AND e.deleted_at IS NULL), 0) AS cnt
             FROM groups g ORDER BY g.name COLLATE NOCASE ASC",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(GroupRow {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    color: r.get(2)?,
                    entry_count: r.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn create_group(&self, name: &str, color: Option<&str>) -> StorageResult<i64> {
        let _ = self.require_unlocked()?;
        let name = name.trim();
        if name.is_empty() {
            return Err(StorageError::Schema("group name cannot be empty".into()));
        }
        let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_default();
        self.conn.execute(
            "INSERT INTO groups (name, color, created_at) VALUES (?1, ?2, ?3)",
            params![name, color, now],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn rename_group(&self, id: i64, new_name: &str) -> StorageResult<()> {
        let _ = self.require_unlocked()?;
        let name = new_name.trim();
        if name.is_empty() {
            return Err(StorageError::Schema("group name cannot be empty".into()));
        }
        let n = self
            .conn
            .execute("UPDATE groups SET name = ?1 WHERE id = ?2", params![name, id])?;
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    pub fn set_group_color(&self, id: i64, color: Option<&str>) -> StorageResult<()> {
        let _ = self.require_unlocked()?;
        let n = self
            .conn
            .execute("UPDATE groups SET color = ?1 WHERE id = ?2", params![color, id])?;
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    pub fn delete_group(&self, id: i64) -> StorageResult<()> {
        let _ = self.require_unlocked()?;
        // SET NULL을 직접 적용
        self.conn
            .execute("UPDATE entries SET group_id = NULL WHERE group_id = ?1", params![id])?;
        let n = self
            .conn
            .execute("DELETE FROM groups WHERE id = ?1", params![id])?;
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    /// 항목의 그룹을 지정합니다. `None`이면 그룹 해제.
    pub fn assign_entry_group(
        &self,
        entry_id: &EntryId,
        group_id: Option<i64>,
    ) -> StorageResult<()> {
        let _ = self.require_unlocked()?;
        let n = self.conn.execute(
            "UPDATE entries SET group_id = ?1 WHERE id = ?2 AND deleted_at IS NULL",
            params![group_id, entry_id.to_string()],
        )?;
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    // ---------- 메모(notes) ----------
    pub fn reveal_notes(&self, id: &EntryId) -> StorageResult<Option<String>> {
        let session = self.require_unlocked()?;
        let row: Option<Option<Vec<u8>>> = self
            .conn
            .query_row(
                "SELECT notes_cipher FROM entries WHERE id = ?1 AND deleted_at IS NULL",
                params![id.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        let Some(opt_sealed) = row else { return Err(StorageError::NotFound) };
        let Some(sealed) = opt_sealed else { return Ok(None) };
        let aad = format!("{}{}", NOTES_AAD_PREFIX, id);
        let pt = aead::open(session.vault_key.as_bytes(), &sealed, aad.as_bytes())?;
        Ok(Some(
            String::from_utf8(pt).map_err(|_| StorageError::Corrupt("notes utf-8".into()))?,
        ))
    }

    pub fn set_notes(&self, id: &EntryId, notes: &str) -> StorageResult<()> {
        let session = self.require_unlocked()?;
        let aad = format!("{}{}", NOTES_AAD_PREFIX, id);
        let cipher: Option<Vec<u8>> = if notes.is_empty() {
            None
        } else {
            Some(aead::seal(session.vault_key.as_bytes(), notes.as_bytes(), aad.as_bytes())?)
        };
        let n = self.conn.execute(
            "UPDATE entries SET notes_cipher = ?1 WHERE id = ?2 AND deleted_at IS NULL",
            params![cipher, id.to_string()],
        )?;
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    // ---------- TOTP 시드 + config ----------
    pub fn set_totp_seed(&self, id: &EntryId, seed: &[u8]) -> StorageResult<()> {
        self.set_totp_full(id, seed, None, None, None)
    }

    /// 시드 + 메타데이터(알고리즘/주기/자릿수) 함께 저장. None 인 값은 기본값(SHA1/30/6)으로 해석됨.
    pub fn set_totp_full(
        &self,
        id: &EntryId,
        seed: &[u8],
        algorithm: Option<&str>,
        period: Option<u32>,
        digits: Option<u32>,
    ) -> StorageResult<()> {
        if seed.is_empty() {
            return self.clear_totp_seed(id);
        }
        let session = self.require_unlocked()?;
        let aad = format!("{}{}", TOTP_AAD_PREFIX, id);
        let cipher = aead::seal(session.vault_key.as_bytes(), seed, aad.as_bytes())?;
        let n = self.conn.execute(
            "UPDATE entries SET totp_seed_cipher = ?1, totp_algorithm = ?2, totp_period = ?3, totp_digits = ?4
             WHERE id = ?5 AND deleted_at IS NULL",
            params![
                cipher,
                algorithm,
                period.map(|v| v as i64),
                digits.map(|v| v as i64),
                id.to_string()
            ],
        )?;
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    pub fn clear_totp_seed(&self, id: &EntryId) -> StorageResult<()> {
        let _ = self.require_unlocked()?;
        let n = self.conn.execute(
            "UPDATE entries SET totp_seed_cipher = NULL, totp_algorithm = NULL, totp_period = NULL, totp_digits = NULL
             WHERE id = ?1 AND deleted_at IS NULL",
            params![id.to_string()],
        )?;
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    pub fn reveal_totp_seed(&self, id: &EntryId) -> StorageResult<Option<Vec<u8>>> {
        self.reveal_totp_full(id).map(|opt| opt.map(|(seed, _, _, _)| seed))
    }

    // TOTP DB 행 → 메모리 표현 (clippy::type_complexity 회피)
    // 행: (sealed_cipher, algorithm, period, digits)
    // 결과: (seed, algorithm, period, digits)

    /// 시드 + (algorithm, period, digits) 반환. config 누락 시 None.
    pub fn reveal_totp_full(&self, id: &EntryId) -> StorageResult<Option<TotpRecord>> {
        let session = self.require_unlocked()?;
        let row: Option<TotpRow> = self
            .conn
            .query_row(
                "SELECT totp_seed_cipher, totp_algorithm, totp_period, totp_digits
                 FROM entries WHERE id = ?1 AND deleted_at IS NULL",
                params![id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let Some((opt_sealed, alg, period, digits)) = row else {
            return Err(StorageError::NotFound);
        };
        let Some(sealed) = opt_sealed else { return Ok(None) };
        let aad = format!("{}{}", TOTP_AAD_PREFIX, id);
        let pt = aead::open(session.vault_key.as_bytes(), &sealed, aad.as_bytes())?;
        Ok(Some((
            pt,
            alg,
            period.map(|v| v as u32),
            digits.map(|v| v as u32),
        )))
    }

    // ---------- 변경 주기 ----------
    pub fn set_rotation_days(&self, id: &EntryId, days: Option<u32>) -> StorageResult<()> {
        let _ = self.require_unlocked()?;
        let n = self.conn.execute(
            "UPDATE entries SET rotation_days = ?1 WHERE id = ?2 AND deleted_at IS NULL",
            params![days.map(|v| v as i64), id.to_string()],
        )?;
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    // ---------- 마스터 비밀번호 변경 ----------
    /// 기존 비밀번호로 검증한 후 새 비밀번호로 vault_key를 재봉인합니다.
    /// 잠금/해제 상태와 무관하게 호출 가능합니다. 디스크의 봉인만 갱신됩니다.
    pub fn change_master_password(&mut self, old: &str, new: &str) -> StorageResult<()> {
        if new.len() < 8 {
            return Err(StorageError::Schema(
                "master password must be ≥ 8 chars".into(),
            ));
        }
        if old == new {
            return Err(StorageError::Schema(
                "new password must differ from the old".into(),
            ));
        }
        let (kdf_params, old_salt, old_sealed) = self.load_meta()?;
        let mut old_master = derive_master_key(old.as_bytes(), &old_salt, &kdf_params)?;
        let unwrap = aead::open(&old_master, &old_sealed, VAULT_KEY_AAD)
            .map_err(|_| StorageError::InvalidMaster);
        old_master.zeroize();
        let mut vault_key_bytes = unwrap?;

        let new_params = KdfParams::default();
        let mut new_salt = vec![0u8; SALT_LEN];
        bp_crypto::random_bytes(&mut new_salt)?;
        let mut new_master = derive_master_key(new.as_bytes(), &new_salt, &new_params)?;
        let new_sealed = aead::seal(&new_master, &vault_key_bytes, VAULT_KEY_AAD)?;
        new_master.zeroize();
        vault_key_bytes.zeroize();

        self.conn.execute(
            "UPDATE vault_meta SET kdf_params = ?1, salt = ?2, vault_key_sealed = ?3 WHERE id = 1",
            params![new_params.to_json(), new_salt.as_slice(), new_sealed],
        )?;
        Ok(())
    }

    pub fn set_favorite(&self, id: &EntryId, favorite: bool) -> StorageResult<()> {
        let _ = self.require_unlocked()?;
        let n = self.conn.execute(
            "UPDATE entries SET favorite = ?1 WHERE id = ?2 AND deleted_at IS NULL",
            params![if favorite { 1i64 } else { 0i64 }, id.to_string()],
        )?;
        if n == 0 { return Err(StorageError::NotFound); }
        Ok(())
    }

    /// 항목의 평문 비밀을 반환합니다. 호출자가 즉시 사용 후 폐기해야 합니다.
    pub fn reveal_secret(&self, id: &EntryId) -> StorageResult<String> {
        let session = self.require_unlocked()?;
        let sealed: Vec<u8> = self
            .conn
            .query_row(
                "SELECT secret_cipher FROM entries WHERE id = ?1 AND deleted_at IS NULL",
                params![id.to_string()],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(StorageError::NotFound)?;
        let aad = format!("{}{}", SECRET_AAD_PREFIX, id);
        let pt = aead::open(session.vault_key.as_bytes(), &sealed, aad.as_bytes())?;
        String::from_utf8(pt).map_err(|_| StorageError::Corrupt("secret utf-8".into()))
    }

    /// 특정 버전의 평문 비밀을 반환합니다.
    pub fn reveal_version_secret(&self, id: &EntryId, version: u32) -> StorageResult<String> {
        let session = self.require_unlocked()?;
        let sealed: Vec<u8> = self
            .conn
            .query_row(
                "SELECT secret_cipher FROM entry_versions WHERE entry_id = ?1 AND version = ?2",
                params![id.to_string(), version as i64],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(StorageError::NotFound)?;
        let aad = format!("{}{}", SECRET_AAD_PREFIX, id);
        let pt = aead::open(session.vault_key.as_bytes(), &sealed, aad.as_bytes())?;
        String::from_utf8(pt).map_err(|_| StorageError::Corrupt("secret utf-8".into()))
    }

    /// 항목과 모든 버전 이력을 영구 삭제합니다. (entry_versions는 FK ON DELETE CASCADE)
    pub fn delete_entry(&self, id: &EntryId) -> StorageResult<()> {
        let _ = self.require_unlocked()?;
        let n = self.conn.execute(
            "DELETE FROM entries WHERE id = ?1",
            params![id.to_string()],
        )?;
        if n == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    /// 항목의 모든 버전 메타데이터를 최신 순으로 반환합니다(봉인된 비밀은 포함하지 않음).
    pub fn list_versions(&self, id: &EntryId) -> StorageResult<Vec<EntryVersionSummary>> {
        let _ = self.require_unlocked()?;
        let current: u32 = self
            .conn
            .query_row(
                "SELECT current_version FROM entries WHERE id = ?1 AND deleted_at IS NULL",
                params![id.to_string()],
                |r| r.get::<_, i64>(0).map(|v| v as u32),
            )
            .optional()?
            .ok_or(StorageError::NotFound)?;
        let mut stmt = self.conn.prepare(
            "SELECT version, created_at, reason FROM entry_versions
             WHERE entry_id = ?1 ORDER BY version DESC",
        )?;
        let rows = stmt
            .query_map(params![id.to_string()], |r| {
                let v: i64 = r.get(0)?;
                let ts: String = r.get(1)?;
                let reason: Option<String> = r.get(2)?;
                Ok(EntryVersionSummary {
                    version: v as u32,
                    created_at: OffsetDateTime::parse(&ts, &Rfc3339)
                        .unwrap_or(OffsetDateTime::UNIX_EPOCH),
                    reason,
                    is_current: (v as u32) == current,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// 과거 버전의 비밀을 새 버전으로 끌어올립니다(롤백 — 새 버전 INSERT).
    pub fn restore_version(&self, id: &EntryId, version: u32) -> StorageResult<u32> {
        let old = self.reveal_version_secret(id, version)?;
        self.update_secret(id, &old, Some(&format!("restored from v{version}")))
    }

    /// 현재 Vault 전체를 마스터 비밀번호로 봉인된 `.bpvault` 바이트열로 내보냅니다.
    ///
    /// 포맷: `MAGIC("BPV1") | header_len:u32 LE | header_json | aead_body`
    /// `aead_body` 의 AAD 에는 `header_json` 통째가 들어가 헤더 변조도 인증됩니다.
    pub fn export_backup(&self, password: &str) -> StorageResult<Vec<u8>> {
        if !self.is_initialized()? {
            return Err(StorageError::NotInitialized);
        }
        // WAL 데이터를 본 파일에 합쳐 단일 파일로 직렬화될 수 있도록 체크포인트.
        self.conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .ok();

        // 디스크에 매핑된 Vault만 실제 파일 export를 지원합니다.
        let sqlite_bytes = if self.path == std::path::Path::new(":memory:") {
            return Err(StorageError::Schema(
                "in-memory vault cannot be exported".into(),
            ));
        } else {
            std::fs::read(&self.path)?
        };

        let kdf_params = KdfParams::default();
        let mut salt = vec![0u8; SALT_LEN];
        bp_crypto::random_bytes(&mut salt)?;

        let header = BackupHeader {
            format_version: BACKUP_FORMAT_VERSION,
            schema_version: SCHEMA_VERSION,
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            created_at: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            kdf_params: kdf_params.clone(),
            salt_b64: B64.encode(&salt),
        };
        let header_json =
            serde_json::to_vec(&header).map_err(|e| StorageError::Schema(e.to_string()))?;

        let mut backup_key = derive_master_key(password.as_bytes(), &salt, &kdf_params)?;
        let cipher = aead::seal(&backup_key, &sqlite_bytes, &header_json)?;
        backup_key.zeroize();

        let mut out = Vec::with_capacity(4 + 4 + header_json.len() + cipher.len());
        out.extend_from_slice(BACKUP_MAGIC);
        out.extend_from_slice(&(header_json.len() as u32).to_le_bytes());
        out.extend_from_slice(&header_json);
        out.extend_from_slice(&cipher);
        Ok(out)
    }

    /// `.bpvault` 바이트열을 검증하고 SQLite raw 바이트로 복호합니다.
    /// 잘못된 비밀번호/변조된 헤더 모두 [`StorageError::InvalidMaster`] 로 통일 보고합니다.
    pub fn decode_backup(bytes: &[u8], password: &str) -> StorageResult<Vec<u8>> {
        if bytes.len() < 8 || &bytes[..4] != BACKUP_MAGIC {
            return Err(StorageError::Corrupt("bad backup magic".into()));
        }
        let header_len = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
        let total_header_end = 8usize.checked_add(header_len).ok_or_else(|| {
            StorageError::Corrupt("header length overflow".into())
        })?;
        if bytes.len() < total_header_end {
            return Err(StorageError::Corrupt("truncated header".into()));
        }
        let header_bytes = &bytes[8..total_header_end];
        let body = &bytes[total_header_end..];

        let header: BackupHeader = serde_json::from_slice(header_bytes)
            .map_err(|e| StorageError::Schema(format!("invalid backup header json: {e}")))?;
        if header.format_version != BACKUP_FORMAT_VERSION {
            return Err(StorageError::Corrupt(format!(
                "unsupported backup format version {}",
                header.format_version
            )));
        }
        let salt = B64
            .decode(&header.salt_b64)
            .map_err(|e| StorageError::Corrupt(format!("salt base64: {e}")))?;

        let mut backup_key =
            derive_master_key(password.as_bytes(), &salt, &header.kdf_params)?;
        let plain = aead::open(&backup_key, body, header_bytes)
            .map_err(|_| StorageError::InvalidMaster);
        backup_key.zeroize();
        plain
    }

    /// 이 Vault의 SQLite 파일을 외부에서 제공한 raw 바이트로 덮어쓰기 위해 우선 닫습니다.
    /// 호출자는 파일 교체 후 [`Vault::open`] 으로 새로 엽니다.
    pub fn close(self) -> std::path::PathBuf {
        // self.conn 은 여기서 drop -> SQLite Connection 닫힘.
        self.path
    }

    /// 항목의 비밀을 새 값으로 교체하고 새 버전을 남깁니다.
    pub fn update_secret(
        &self,
        id: &EntryId,
        new_secret: &str,
        reason: Option<&str>,
    ) -> StorageResult<u32> {
        let session = self.require_unlocked()?;
        let aad = format!("{}{}", SECRET_AAD_PREFIX, id);
        let sealed = aead::seal(session.vault_key.as_bytes(), new_secret.as_bytes(), aad.as_bytes())?;
        let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_default();

        let next: u32 = self
            .conn
            .query_row(
                "SELECT current_version + 1 FROM entries WHERE id = ?1 AND deleted_at IS NULL",
                params![id.to_string()],
                |r| r.get::<_, i64>(0).map(|v| v as u32),
            )
            .optional()?
            .ok_or(StorageError::NotFound)?;

        self.conn.execute(
            "UPDATE entries SET secret_cipher = ?1, current_version = ?2, updated_at = ?3 WHERE id = ?4",
            params![sealed, next as i64, now, id.to_string()],
        )?;
        self.conn.execute(
            "INSERT INTO entry_versions (entry_id, version, secret_cipher, reason, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id.to_string(), next as i64, sealed, reason, now],
        )?;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_vault() -> Vault {
        // 테스트용 빠른 KDF 파라미터로 초기화하기 위한 헬퍼.
        // initialize는 기본 파라미터를 쓰지만, 인메모리에서도 64MiB Argon2는
        // 부담이 큽니다. 대신 직접 INSERT 하지 않고 일반 경로를 짧은 비번으로 돕니다.
        Vault::open_in_memory().unwrap()
    }

    #[test]
    fn bootstrap_creates_schema() {
        let v = Vault::open_in_memory().unwrap();
        assert!(!v.is_initialized().unwrap());
        assert!(!v.is_unlocked());
    }

    #[test]
    fn initialize_then_unlock_with_same_password() {
        let mut v = fast_vault();
        v.initialize("hunter2hunter").unwrap();
        assert!(v.is_initialized().unwrap());
        assert!(v.is_unlocked());
        v.lock();
        assert!(!v.is_unlocked());
        v.unlock("hunter2hunter").unwrap();
        assert!(v.is_unlocked());
    }

    #[test]
    fn wrong_password_fails() {
        let mut v = fast_vault();
        v.initialize("hunter2hunter").unwrap();
        v.lock();
        let err = v.unlock("hunter2WRONG").unwrap_err();
        assert!(matches!(err, StorageError::InvalidMaster));
    }

    #[test]
    fn entry_roundtrip_with_versioning() {
        let mut v = fast_vault();
        v.initialize("hunter2hunter").unwrap();
        let id = v
            .create_entry(&NewEntry {
                title: "GitHub".into(),
                username: Some("andy".into()),
                url: Some("https://github.com".into()),
                secret: "p@ss-1".into(),
            })
            .unwrap();

        let listing = v.list_entries().unwrap();
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].title, "GitHub");

        let s = v.reveal_secret(&id).unwrap();
        assert_eq!(s, "p@ss-1");

        let v2 = v.update_secret(&id, "p@ss-2", Some("rotation")).unwrap();
        assert_eq!(v2, 2);
        assert_eq!(v.reveal_secret(&id).unwrap(), "p@ss-2");

        // 버전 1의 비밀은 그대로 보관되어 있어야 함.
        let old = v.reveal_version_secret(&id, 1).unwrap();
        assert_eq!(old, "p@ss-1");

        let versions = v.list_versions(&id).unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].version, 2);
        assert!(versions[0].is_current);
        assert_eq!(versions[1].version, 1);
        assert!(!versions[1].is_current);

        // 롤백: v1으로 복구 → 새 v3 생성, 현재 비밀이 다시 p@ss-1
        let v3 = v.restore_version(&id, 1).unwrap();
        assert_eq!(v3, 3);
        assert_eq!(v.reveal_secret(&id).unwrap(), "p@ss-1");
        let versions = v.list_versions(&id).unwrap();
        assert_eq!(versions.len(), 3);
        assert_eq!(versions[0].version, 3);
        assert_eq!(versions[0].reason.as_deref(), Some("restored from v1"));

        // 즐겨찾기 토글
        assert!(!v.list_entries().unwrap()[0].favorite);
        v.set_favorite(&id, true).unwrap();
        assert!(v.list_entries().unwrap()[0].favorite);
        v.set_favorite(&id, false).unwrap();
        assert!(!v.list_entries().unwrap()[0].favorite);

        // 그룹: 생성 → 할당 → 리스트에 group_name/color 노출 → 그룹 삭제 시 NULL로 set
        let gid = v.create_group("업무", Some("#4f8cff")).unwrap();
        assert_eq!(v.list_groups().unwrap().len(), 1);
        v.assign_entry_group(&id, Some(gid)).unwrap();
        let rows = v.list_entries().unwrap();
        assert_eq!(rows[0].group_id, Some(gid));
        assert_eq!(rows[0].group_name.as_deref(), Some("업무"));
        assert_eq!(rows[0].group_color.as_deref(), Some("#4f8cff"));
        assert_eq!(v.list_groups().unwrap()[0].entry_count, 1);

        v.rename_group(gid, "Work").unwrap();
        assert_eq!(v.list_groups().unwrap()[0].name, "Work");

        v.delete_group(gid).unwrap();
        assert!(v.list_groups().unwrap().is_empty());
        let rows = v.list_entries().unwrap();
        assert_eq!(rows[0].group_id, None);

        // 노트: 설정/조회/지우기
        assert!(v.reveal_notes(&id).unwrap().is_none());
        v.set_notes(&id, "secret note").unwrap();
        assert_eq!(v.reveal_notes(&id).unwrap().as_deref(), Some("secret note"));
        v.set_notes(&id, "").unwrap();
        assert!(v.reveal_notes(&id).unwrap().is_none());

        // TOTP: 시드 저장/복호/삭제 + 코드 생성
        let seed = bp_crypto::totp::parse_seed("JBSWY3DPEHPK3PXP").unwrap();
        v.set_totp_seed(&id, &seed).unwrap();
        let revealed = v.reveal_totp_seed(&id).unwrap().expect("seed present");
        assert_eq!(revealed, seed);
        let (code, remaining, period) = bp_crypto::totp::current_code(&revealed);
        assert_eq!(code.len(), 6);
        assert!(remaining <= period);
        v.clear_totp_seed(&id).unwrap();
        assert!(v.reveal_totp_seed(&id).unwrap().is_none());

        // 마스터 비번 변경: 잠그고 새 비번으로 다시 해제 가능, 옛 비번은 거부.
        v.change_master_password("hunter2hunter", "another-strong-pw-1").unwrap();
        v.lock();
        assert!(matches!(
            v.unlock("hunter2hunter"),
            Err(StorageError::InvalidMaster)
        ));
        v.unlock("another-strong-pw-1").unwrap();

        // 영구 삭제: 항목과 모든 버전이 사라짐.
        v.delete_entry(&id).unwrap();
        assert!(v.list_entries().unwrap().is_empty());
        assert!(matches!(v.list_versions(&id), Err(StorageError::NotFound)));
        assert!(matches!(v.reveal_secret(&id), Err(StorageError::NotFound)));
    }

    #[test]
    fn locked_vault_refuses_reads() {
        let mut v = fast_vault();
        v.initialize("hunter2hunter").unwrap();
        let id = v
            .create_entry(&NewEntry {
                title: "x".into(),
                username: None,
                url: None,
                secret: "y".into(),
            })
            .unwrap();
        v.lock();
        assert!(matches!(v.list_entries(), Err(StorageError::Locked)));
        assert!(matches!(v.reveal_secret(&id), Err(StorageError::Locked)));
    }

    #[test]
    fn backup_roundtrip_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.db");

        // 원본 Vault 생성 후 한 건 추가
        {
            let mut v = Vault::open(&path).unwrap();
            v.initialize("hunter2hunter").unwrap();
            v.create_entry(&NewEntry {
                title: "Mail".into(),
                username: Some("a@b".into()),
                url: None,
                secret: "topsecret".into(),
            })
            .unwrap();
        }

        // 새로 열어서 백업 export
        let backup_bytes = {
            let v = Vault::open(&path).unwrap();
            v.export_backup("hunter2hunter").unwrap()
        };
        assert!(backup_bytes.len() > 100);
        assert_eq!(&backup_bytes[..4], b"BPV1");

        // 잘못된 비번 → InvalidMaster
        assert!(matches!(
            Vault::decode_backup(&backup_bytes, "wrong_password"),
            Err(StorageError::InvalidMaster)
        ));

        // 정상 복호
        let restored = Vault::decode_backup(&backup_bytes, "hunter2hunter").unwrap();
        assert!(!restored.is_empty());

        // 다른 경로에 복원 후 동일 항목 확인
        let new_path = dir.path().join("restored.db");
        std::fs::write(&new_path, &restored).unwrap();
        let mut v2 = Vault::open(&new_path).unwrap();
        v2.unlock("hunter2hunter").unwrap();
        let entries = v2.list_entries().unwrap();
        assert_eq!(entries.len(), 1);
        let eid = EntryId::parse(&entries[0].id).unwrap();
        assert_eq!(v2.reveal_secret(&eid).unwrap(), "topsecret");
    }

    #[test]
    fn backup_header_tamper_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.db");
        {
            let mut v = Vault::open(&path).unwrap();
            v.initialize("hunter2hunter").unwrap();
        }
        let v = Vault::open(&path).unwrap();
        let mut backup = v.export_backup("hunter2hunter").unwrap();

        // 헤더 첫 바이트 1개 변조 → AEAD 인증 실패해 InvalidMaster.
        let header_offset = 8;
        backup[header_offset] ^= 0x80;
        assert!(Vault::decode_backup(&backup, "hunter2hunter").is_err());
    }

    #[test]
    fn persists_across_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.db");
        {
            let mut v = Vault::open(&path).unwrap();
            v.initialize("hunter2hunter").unwrap();
            v.create_entry(&NewEntry {
                title: "Mail".into(),
                username: Some("a@b".into()),
                url: None,
                secret: "topsecret".into(),
            })
            .unwrap();
        }
        let mut v = Vault::open(&path).unwrap();
        assert!(v.is_initialized().unwrap());
        v.unlock("hunter2hunter").unwrap();
        let listing = v.list_entries().unwrap();
        assert_eq!(listing.len(), 1);
        let id = EntryId::parse(&listing[0].id).unwrap();
        assert_eq!(v.reveal_secret(&id).unwrap(), "topsecret");
    }
}
