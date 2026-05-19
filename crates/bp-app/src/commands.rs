//! Tauri 커맨드 핸들러.
//!
//! 모든 커맨드는 결과를 `Result<T, String>`으로 돌려주어 프론트엔드에서 그대로 표시할 수 있게 합니다.
//! 평문 비밀번호는 가능한 한 좁은 범위에서만 사용하고, 클립보드 복사 후에는 N초 뒤 자동 클리어합니다.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use bp_core::{EntryId, EntrySummary, EntryVersionSummary, GroupRow, NewEntry, PasswordPolicy};
use bp_passgen::StrengthSummary;
use bp_storage::{Vault, VaultStatus};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;
use zeroize::Zeroize;

use crate::state::AppState;

const CLIPBOARD_CLEAR_AFTER_MS_DEFAULT: u64 = 30_000;

fn hash_text(s: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let res = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&res);
    out
}

fn lock<'r>(state: &'r State<'r, Mutex<AppState>>) -> std::sync::MutexGuard<'r, AppState> {
    state.lock().expect("AppState mutex poisoned")
}

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

#[tauri::command]
pub fn app_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[tauri::command]
pub fn vault_status(state: State<'_, Mutex<AppState>>) -> Result<VaultStatus, String> {
    lock(&state).vault.status().map_err(err)
}

#[tauri::command]
pub fn initialize_vault(
    app: AppHandle,
    mut password: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<VaultStatus, String> {
    let result = {
        let mut guard = lock(&state);
        guard.vault.initialize(&password).map_err(err)?;
        guard.vault.status().map_err(err)
    };
    password.zeroize();
    if result.is_ok() { crate::refresh_tray(&app); }
    result
}

#[tauri::command]
pub fn unlock_vault(
    app: AppHandle,
    mut password: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<VaultStatus, String> {
    let result = {
        let mut guard = lock(&state);
        guard.vault.unlock(&password).map_err(err)?;
        guard.vault.status().map_err(err)
    };
    password.zeroize();
    if result.is_ok() { crate::refresh_tray(&app); }
    result
}

#[tauri::command]
pub fn lock_vault(app: AppHandle, state: State<'_, Mutex<AppState>>) -> Result<VaultStatus, String> {
    let result = {
        let mut guard = lock(&state);
        guard.vault.lock();
        guard.vault.status().map_err(err)
    };
    crate::refresh_tray(&app);
    result
}

#[tauri::command]
pub fn list_entries(state: State<'_, Mutex<AppState>>) -> Result<Vec<EntrySummary>, String> {
    lock(&state).vault.list_entries().map_err(err)
}

#[tauri::command]
pub fn create_entry(
    app: AppHandle,
    title: String,
    username: Option<String>,
    url: Option<String>,
    mut secret: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<String, String> {
    let id = {
        let guard = lock(&state);
        guard
            .vault
            .create_entry(&NewEntry { title, username, url, secret: secret.clone() })
            .map_err(err)?
    };
    secret.zeroize();
    crate::refresh_tray(&app);
    Ok(id.to_string())
}

/// 사용자가 명시적으로 '보기'를 눌렀을 때만 평문을 반환합니다.
#[tauri::command]
pub fn reveal_secret(
    entry_id: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<String, String> {
    let id = EntryId::parse(&entry_id).ok_or_else(|| "invalid entry id".to_string())?;
    lock(&state).vault.reveal_secret(&id).map_err(err)
}

#[tauri::command]
pub fn reveal_version_secret(
    entry_id: String,
    version: u32,
    state: State<'_, Mutex<AppState>>,
) -> Result<String, String> {
    let id = EntryId::parse(&entry_id).ok_or_else(|| "invalid entry id".to_string())?;
    lock(&state).vault.reveal_version_secret(&id, version).map_err(err)
}

#[tauri::command]
pub fn list_versions(
    entry_id: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<EntryVersionSummary>, String> {
    let id = EntryId::parse(&entry_id).ok_or_else(|| "invalid entry id".to_string())?;
    lock(&state).vault.list_versions(&id).map_err(err)
}

#[tauri::command]
pub fn update_secret(
    app: AppHandle,
    entry_id: String,
    mut new_secret: String,
    reason: Option<String>,
    state: State<'_, Mutex<AppState>>,
) -> Result<u32, String> {
    let id = EntryId::parse(&entry_id).ok_or_else(|| "invalid entry id".to_string())?;
    let result = lock(&state)
        .vault
        .update_secret(&id, &new_secret, reason.as_deref())
        .map_err(err);
    new_secret.zeroize();
    if result.is_ok() { crate::refresh_tray(&app); }
    result
}

#[tauri::command]
pub fn restore_version(
    app: AppHandle,
    entry_id: String,
    version: u32,
    state: State<'_, Mutex<AppState>>,
) -> Result<u32, String> {
    let id = EntryId::parse(&entry_id).ok_or_else(|| "invalid entry id".to_string())?;
    let result = lock(&state).vault.restore_version(&id, version).map_err(err);
    if result.is_ok() { crate::refresh_tray(&app); }
    result
}

#[tauri::command]
pub fn delete_entry(
    app: AppHandle,
    entry_id: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), String> {
    let id = EntryId::parse(&entry_id).ok_or_else(|| "invalid entry id".to_string())?;
    let result = lock(&state).vault.delete_entry(&id).map_err(err);
    if result.is_ok() { crate::refresh_tray(&app); }
    result
}

#[derive(Debug, Serialize)]
pub struct GeneratedCandidate {
    pub password: String,
    pub strength: StrengthSummary,
}

/// 정책에 따라 후보 N개를 생성하고 각 후보의 강도까지 함께 반환합니다.
#[tauri::command]
pub fn generate_passwords(
    policy: PasswordPolicy,
    count: u8,
) -> Result<Vec<GeneratedCandidate>, String> {
    let pwds = bp_passgen::generate(&policy, count.min(10) as usize).map_err(err)?;
    Ok(pwds
        .into_iter()
        .map(|p| GeneratedCandidate {
            strength: bp_passgen::estimate_strength(&p),
            password: p,
        })
        .collect())
}

/// 라이브 입력에 대한 강도 추정. 평문은 곧장 즉시 호출 범위 밖으로 나가지 않습니다.
#[tauri::command]
pub fn estimate_strength(password: String) -> StrengthSummary {
    let s = bp_passgen::estimate_strength(&password);
    // password 인자는 함수 끝에서 drop. 명시적 zeroize는 String 내부 버퍼까지 보장하기 위해.
    let mut p = password;
    p.zeroize();
    s
}

// ============================================================ CSV 가져오기

#[derive(Debug, Serialize)]
pub struct ImportCsvResult {
    pub imported: u32,
    pub skipped: u32,
    pub created_groups: u32,
    pub errors: Vec<String>,
}

/// 1Password / Bitwarden / Chrome 등에서 export한 CSV를 가져옵니다.
/// 헤더에서 다음 컬럼을 자동 인식합니다(대소문자 무시):
/// - 제목: name / title
/// - 사용자명: username / user / login_username / email
/// - 패스워드: password / login_password
/// - URL: url / website / login_uri
/// - 메모: notes / note
/// - 그룹: folder / group / category
/// - TOTP: totp / login_totp / otp
#[tauri::command]
pub fn import_csv(
    app: AppHandle,
    csv_text: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<ImportCsvResult, String> {
    use bp_core::NewEntry;
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(csv_text.as_bytes());

    let headers = rdr.headers().map_err(|e| e.to_string())?.clone();
    let mut idx: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    let aliases: &[(&str, &[&str])] = &[
        ("title", &["name", "title", "item name", "entry"]),
        ("username", &["username", "user", "login_username", "email", "user name"]),
        ("password", &["password", "login_password", "pass"]),
        ("url", &["url", "website", "login_uri", "uri", "site"]),
        ("notes", &["notes", "note", "comments", "extra"]),
        ("group", &["folder", "group", "category", "tag", "tags"]),
        ("totp", &["totp", "login_totp", "otp", "two_factor"]),
    ];
    for (i, h) in headers.iter().enumerate() {
        let lower = h.trim().to_ascii_lowercase();
        for (canonical, opts) in aliases {
            if opts.iter().any(|o| **o == lower) {
                idx.insert(canonical, i);
                break;
            }
        }
    }
    if !idx.contains_key("title") || !idx.contains_key("password") {
        return Err("CSV에 'name(title)'과 'password' 열이 필요합니다".into());
    }

    let mut imported = 0u32;
    let mut skipped = 0u32;
    let mut created_groups = 0u32;
    let mut errors: Vec<String> = Vec::new();

    // 그룹 이름 → id 매핑(기존 + 새로 생성)
    let mut groups: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    {
        let guard = lock(&state);
        if let Ok(gs) = guard.vault.list_groups() {
            for g in gs {
                groups.insert(g.name, g.id);
            }
        }
    }

    for (row_no, rec) in rdr.records().enumerate() {
        let row = match rec {
            Ok(r) => r,
            Err(e) => {
                skipped += 1;
                errors.push(format!("행 {}: {}", row_no + 2, e));
                continue;
            }
        };
        let get = |key: &str| -> Option<String> {
            idx.get(key).and_then(|i| row.get(*i)).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
        };
        let Some(title) = get("title") else {
            skipped += 1;
            errors.push(format!("행 {}: title 없음", row_no + 2));
            continue;
        };
        let Some(password) = get("password") else {
            skipped += 1;
            errors.push(format!("행 {}: password 없음 ({})", row_no + 2, title));
            continue;
        };
        let username = get("username");
        let url = get("url");
        let notes = get("notes");
        let group_name = get("group");
        let totp_input = get("totp");

        let new_entry = NewEntry {
            title: title.clone(),
            username,
            url,
            secret: password,
        };
        // 항목 생성
        let id_result = {
            let guard = lock(&state);
            guard.vault.create_entry(&new_entry).map_err(err)
        };
        let id = match id_result {
            Ok(i) => i,
            Err(e) => {
                skipped += 1;
                errors.push(format!("행 {}: {}", row_no + 2, e));
                continue;
            }
        };

        // 메모
        if let Some(n) = notes {
            let guard = lock(&state);
            let _ = guard.vault.set_notes(&id, &n);
        }
        // 그룹 (기존 매핑 or 새로 생성)
        if let Some(gname) = group_name {
            let gid = match groups.get(&gname) {
                Some(g) => *g,
                None => {
                    let guard = lock(&state);
                    match guard.vault.create_group(&gname, None) {
                        Ok(gid) => {
                            created_groups += 1;
                            groups.insert(gname.clone(), gid);
                            gid
                        }
                        Err(_) => {
                            // 동시성 또는 기존이 있는 경우 list 재조회
                            if let Ok(gs) = guard.vault.list_groups() {
                                gs.iter()
                                    .find(|g| g.name == gname)
                                    .map(|g| g.id)
                                    .unwrap_or(-1)
                            } else {
                                -1
                            }
                        }
                    }
                }
            };
            if gid > 0 {
                let guard = lock(&state);
                let _ = guard.vault.assign_entry_group(&id, Some(gid));
            }
        }
        // TOTP
        if let Some(t) = totp_input {
            if let Ok(parsed) = bp_crypto::totp::parse(&t) {
                let guard = lock(&state);
                let _ = guard.vault.set_totp_full(
                    &id,
                    &parsed.seed,
                    Some(parsed.config.algorithm.as_str()),
                    Some(parsed.config.period as u32),
                    Some(parsed.config.digits),
                );
            }
        }

        imported += 1;
    }

    crate::refresh_tray(&app);
    Ok(ImportCsvResult { imported, skipped, created_groups, errors })
}

#[derive(Debug, Serialize)]
pub struct BackupResult {
    pub path: String,
    pub bytes: u64,
}

/// 현재 Vault를 `.bpvault` 파일로 내보냅니다. 사용자에게 저장 위치 다이얼로그를 띄웁니다.
#[tauri::command]
pub async fn export_vault(
    app: AppHandle,
    mut password: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<Option<BackupResult>, String> {
    // 1) 봉인 바이트열 생성 (mutex는 짧게 잡고 즉시 해제)
    let bytes_result = {
        let guard = state.lock().expect("AppState mutex poisoned");
        guard.vault.export_backup(&password).map_err(err)
    };
    password.zeroize();
    let bytes = bytes_result?;

    // 2) 저장 다이얼로그
    let path_opt = app
        .dialog()
        .file()
        .add_filter("BoxPassword Vault", &["bpvault"])
        .set_file_name("boxpassword-backup.bpvault")
        .blocking_save_file();

    let Some(file_path) = path_opt else {
        return Ok(None);
    };
    let dest = file_path
        .into_path()
        .map_err(|e| format!("path: {e}"))?;

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let len = bytes.len() as u64;
    std::fs::write(&dest, bytes).map_err(|e| e.to_string())?;

    Ok(Some(BackupResult {
        path: dest.to_string_lossy().into_owned(),
        bytes: len,
    }))
}

#[derive(Debug, Serialize)]
pub struct RestoreResult {
    pub vault_path: String,
    pub backup_kept_at: Option<String>,
}

/// `.bpvault` 파일을 열어 현재 Vault를 교체합니다.
/// 기존 Vault 파일은 동일 디렉터리에 `.bak` 확장자로 자동 보존됩니다.
#[tauri::command]
pub async fn import_vault(
    app: AppHandle,
    mut password: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<Option<RestoreResult>, String> {
    // 1) 백업 파일 선택
    let picked = app
        .dialog()
        .file()
        .add_filter("BoxPassword Vault", &["bpvault"])
        .blocking_pick_file();

    let Some(file_path) = picked else {
        password.zeroize();
        return Ok(None);
    };
    let src = file_path
        .into_path()
        .map_err(|e| format!("path: {e}"))?;

    // 2) 디코딩
    let backup_bytes = std::fs::read(&src).map_err(|e| e.to_string())?;
    let sqlite_bytes_result = Vault::decode_backup(&backup_bytes, &password).map_err(err);
    password.zeroize();
    let sqlite_bytes = sqlite_bytes_result?;

    // 3) 현재 Vault 닫고 파일 교체
    let mut guard = state.lock().expect("AppState mutex poisoned");
    let vault_path = guard.vault.path().to_path_buf();

    // 현재 Vault drop 을 위해 인메모리 더미로 잠시 교체
    let dummy = Vault::open_in_memory().map_err(err)?;
    let old = std::mem::replace(&mut guard.vault, dummy);
    let _ = old.close(); // Connection 닫힘

    // 기존 파일을 .bak로 (있을 때만)
    let mut bak_path = None;
    if vault_path.exists() {
        let candidate = vault_path.with_extension("db.bak");
        // 기존 .bak가 있으면 timestamp 붙여 회피
        let final_bak = if candidate.exists() {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            vault_path.with_extension(format!("db.{}.bak", stamp))
        } else {
            candidate
        };
        std::fs::rename(&vault_path, &final_bak).map_err(|e| e.to_string())?;
        bak_path = Some(final_bak.to_string_lossy().into_owned());
    }

    if let Some(parent) = vault_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(&vault_path, sqlite_bytes).map_err(|e| e.to_string())?;

    // 4) 새 Vault 열기 (잠금 상태)
    guard.vault = Vault::open(&vault_path).map_err(err)?;

    drop(guard);
    crate::refresh_tray(&app);

    Ok(Some(RestoreResult {
        vault_path: vault_path.to_string_lossy().into_owned(),
        backup_kept_at: bak_path,
    }))
}

/// 항목의 비밀을 OS 클립보드에 넣고 일정 시간 뒤 자동 클리어합니다.
///
/// 평문 비밀은 우리 메모리에 거의 머무르지 않습니다:
/// 클립보드 set 직후 SHA-256 해시만 남기고 즉시 zeroize합니다.
/// 시간이 지나 클립보드를 비울 때, 그 사이 사용자가 다른 것을 복사했는지
/// 현재 클립보드 내용의 해시로만 판별합니다.
#[tauri::command]
pub fn copy_to_clipboard(
    entry_id: String,
    delay_ms: Option<u64>,
    state: State<'_, Mutex<AppState>>,
) -> Result<u64, String> {
    let id = EntryId::parse(&entry_id).ok_or_else(|| "invalid entry id".to_string())?;
    let mut secret = lock(&state).vault.reveal_secret(&id).map_err(err)?;

    let mut clipboard = arboard::Clipboard::new().map_err(|e| e.to_string())?;
    clipboard
        .set_text(secret.clone())
        .map_err(|e| e.to_string())?;
    let expected_hash = hash_text(&secret);
    secret.zeroize();

    let delay = delay_ms.unwrap_or(CLIPBOARD_CLEAR_AFTER_MS_DEFAULT).max(1000);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(delay));
        if let Ok(mut cb) = arboard::Clipboard::new() {
            if let Ok(current) = cb.get_text() {
                if hash_text(&current) == expected_hash {
                    let _ = cb.set_text("");
                }
            }
        }
    });

    Ok(delay / 1000)
}

/// 클립보드를 즉시 비웁니다(현재 내용이 무엇이든 비움).
#[tauri::command]
pub fn clear_clipboard() -> Result<(), String> {
    let mut cb = arboard::Clipboard::new().map_err(|e| e.to_string())?;
    cb.set_text("").map_err(|e| e.to_string())?;
    Ok(())
}

// ============================================================ 건강 검진

#[derive(Debug, Serialize)]
pub struct HealthEntryRef {
    pub entry_id: String,
    pub title: String,
}

#[derive(Debug, Serialize)]
pub struct WeakEntry {
    pub entry_id: String,
    pub title: String,
    /// zxcvbn score (0~4)
    pub score: u8,
}

#[derive(Debug, Serialize)]
pub struct ReusedGroup {
    pub group_id: u32,
    pub entries: Vec<HealthEntryRef>,
}

#[derive(Debug, Serialize)]
pub struct AgedEntry {
    pub entry_id: String,
    pub title: String,
    pub age_days: u32,
}

#[derive(Debug, Serialize)]
pub struct HealthReport {
    pub total_entries: u32,
    /// 평균 zxcvbn score (0~4 사이 실수).
    pub avg_score: f64,
    pub weak: Vec<WeakEntry>,
    pub reused_groups: Vec<ReusedGroup>,
    pub aged: Vec<AgedEntry>,
}

/// 약함 임계값. 이하 점수는 약함으로 분류.
const WEAK_THRESHOLD: u8 = 1;
/// 노후 임계값(일).
const AGED_DAYS: i64 = 365;

#[tauri::command]
pub fn analyze_health(state: State<'_, Mutex<AppState>>) -> Result<HealthReport, String> {
    let guard = lock(&state);
    let entries = guard.vault.list_entries().map_err(err)?;
    let total = entries.len() as u32;
    if total == 0 {
        return Ok(HealthReport {
            total_entries: 0,
            avg_score: 0.0,
            weak: Vec::new(),
            reused_groups: Vec::new(),
            aged: Vec::new(),
        });
    }

    let now = time::OffsetDateTime::now_utc();

    let mut weak: Vec<WeakEntry> = Vec::new();
    let mut aged: Vec<AgedEntry> = Vec::new();
    let mut groups: HashMap<[u8; 32], Vec<HealthEntryRef>> = HashMap::new();
    let mut total_score: u64 = 0;

    for e in &entries {
        let id = match EntryId::parse(&e.id) {
            Some(i) => i,
            None => continue,
        };
        let mut secret = guard.vault.reveal_secret(&id).map_err(err)?;

        let strength = bp_passgen::estimate_strength(&secret);
        let score = strength.score;
        total_score += score as u64;
        if score <= WEAK_THRESHOLD {
            weak.push(WeakEntry {
                entry_id: e.id.clone(),
                title: e.title.clone(),
                score,
            });
        }

        let h = hash_text(&secret);
        secret.zeroize();

        groups.entry(h).or_default().push(HealthEntryRef {
            entry_id: e.id.clone(),
            title: e.title.clone(),
        });

        let age_days = (now - e.updated_at).whole_days();
        if age_days >= AGED_DAYS {
            aged.push(AgedEntry {
                entry_id: e.id.clone(),
                title: e.title.clone(),
                age_days: age_days as u32,
            });
        }
    }

    // 재사용 그룹(2건 이상만), 그룹 크기 큰 순.
    let mut reused: Vec<Vec<HealthEntryRef>> =
        groups.into_values().filter(|g| g.len() > 1).collect();
    reused.sort_by_key(|g| std::cmp::Reverse(g.len()));
    let reused_groups: Vec<ReusedGroup> = reused
        .into_iter()
        .enumerate()
        .map(|(i, g)| ReusedGroup {
            group_id: (i as u32) + 1,
            entries: g,
        })
        .collect();

    weak.sort_by_key(|w| w.score);
    aged.sort_by_key(|a| std::cmp::Reverse(a.age_days));

    Ok(HealthReport {
        total_entries: total,
        avg_score: (total_score as f64) / (total as f64),
        weak,
        reused_groups,
        aged,
    })
}

// ============================================================ 그룹

#[tauri::command]
pub fn list_groups(state: State<'_, Mutex<AppState>>) -> Result<Vec<GroupRow>, String> {
    lock(&state).vault.list_groups().map_err(err)
}

#[tauri::command]
pub fn create_group(
    name: String,
    color: Option<String>,
    state: State<'_, Mutex<AppState>>,
) -> Result<i64, String> {
    lock(&state).vault.create_group(&name, color.as_deref()).map_err(err)
}

#[tauri::command]
pub fn rename_group(
    group_id: i64,
    name: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), String> {
    lock(&state).vault.rename_group(group_id, &name).map_err(err)
}

#[tauri::command]
pub fn set_group_color(
    group_id: i64,
    color: Option<String>,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), String> {
    lock(&state).vault.set_group_color(group_id, color.as_deref()).map_err(err)
}

#[tauri::command]
pub fn delete_group(group_id: i64, state: State<'_, Mutex<AppState>>) -> Result<(), String> {
    lock(&state).vault.delete_group(group_id).map_err(err)
}

#[tauri::command]
pub fn assign_entry_group(
    entry_id: String,
    group_id: Option<i64>,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), String> {
    let id = EntryId::parse(&entry_id).ok_or_else(|| "invalid entry id".to_string())?;
    lock(&state).vault.assign_entry_group(&id, group_id).map_err(err)
}

/// 항목의 즐겨찾기 토글.
// ============================================================ Keychain 자동 잠금 해제

#[tauri::command]
pub fn keychain_has(_app: AppHandle) -> bool {
    crate::keychain::has_entry()
}

/// 진단용 — 존재 여부와 사유를 함께 돌려줌. UI 콘솔에 출력해 어디서 막혔는지 확인.
#[derive(serde::Serialize)]
pub struct KeychainStatus {
    pub present: bool,
    pub reason: Option<String>,
}

#[tauri::command]
pub fn keychain_status(_app: AppHandle) -> KeychainStatus {
    let (present, reason) = crate::keychain::has_entry_detailed();
    KeychainStatus { present, reason }
}

/// 현재 unlocked 상태의 vault_key를 OS Keychain 에 저장합니다.
/// 첫 호출 시 OS 가 권한 다이얼로그를 띄울 수 있습니다.
#[tauri::command]
pub fn keychain_save_current(state: State<'_, Mutex<AppState>>) -> Result<(), String> {
    let key_opt = {
        let guard = lock(&state);
        guard.vault.vault_key_bytes()
    };
    let mut key = key_opt.ok_or_else(|| "vault 가 잠겨 있습니다 — 먼저 잠금 해제하세요".to_string())?;
    let result = crate::keychain::save(&key);
    key.zeroize();
    result
}

#[tauri::command]
pub fn keychain_clear() -> Result<(), String> {
    crate::keychain::clear()
}

/// Keychain 에 저장된 키로 silently 잠금 해제 시도. 성공 시 true.
#[tauri::command]
pub fn keychain_try_unlock(app: AppHandle) -> bool {
    crate::ensure_unlocked_via_keychain(&app)
}

/// 마스터 비밀번호 변경. 이전/새 비번 입력 후 vault_key 재봉인.
#[tauri::command]
pub fn change_master_password(
    mut old_password: String,
    mut new_password: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), String> {
    let result = lock(&state)
        .vault
        .change_master_password(&old_password, &new_password)
        .map_err(err);
    old_password.zeroize();
    new_password.zeroize();
    result
}

// ---------- 메모 ----------
#[tauri::command]
pub fn get_entry_notes(
    entry_id: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<Option<String>, String> {
    let id = EntryId::parse(&entry_id).ok_or_else(|| "invalid entry id".to_string())?;
    lock(&state).vault.reveal_notes(&id).map_err(err)
}

#[tauri::command]
pub fn set_entry_notes(
    app: AppHandle,
    entry_id: String,
    mut notes: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), String> {
    let id = EntryId::parse(&entry_id).ok_or_else(|| "invalid entry id".to_string())?;
    let result = lock(&state).vault.set_notes(&id, &notes).map_err(err);
    notes.zeroize();
    if result.is_ok() {
        crate::refresh_tray(&app);
    }
    result
}

// ---------- TOTP ----------
#[derive(Debug, Serialize)]
pub struct TotpCode {
    pub code: String,
    pub remaining_seconds: u64,
    pub period: u64,
}

#[tauri::command]
pub fn set_entry_totp(
    app: AppHandle,
    entry_id: String,
    mut input: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<TotpConfigOut, String> {
    let id = EntryId::parse(&entry_id).ok_or_else(|| "invalid entry id".to_string())?;
    let parsed = bp_crypto::totp::parse(&input)?;
    input.zeroize();
    let algo = parsed.config.algorithm.as_str();
    let period = parsed.config.period as u32;
    let digits = parsed.config.digits;
    let mut seed = parsed.seed;
    let result = lock(&state)
        .vault
        .set_totp_full(&id, &seed, Some(algo), Some(period), Some(digits))
        .map_err(err);
    seed.zeroize();
    if result.is_ok() {
        crate::refresh_tray(&app);
    }
    result.map(|_| TotpConfigOut {
        algorithm: algo.to_string(),
        period,
        digits,
    })
}

#[derive(Debug, Serialize)]
pub struct TotpConfigOut {
    pub algorithm: String,
    pub period: u32,
    pub digits: u32,
}

#[tauri::command]
pub fn clear_entry_totp(
    app: AppHandle,
    entry_id: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), String> {
    let id = EntryId::parse(&entry_id).ok_or_else(|| "invalid entry id".to_string())?;
    let result = lock(&state).vault.clear_totp_seed(&id).map_err(err);
    if result.is_ok() {
        crate::refresh_tray(&app);
    }
    result
}

#[tauri::command]
pub fn entry_totp_code(
    entry_id: String,
    state: State<'_, Mutex<AppState>>,
) -> Result<Option<TotpCode>, String> {
    let id = EntryId::parse(&entry_id).ok_or_else(|| "invalid entry id".to_string())?;
    let full = lock(&state).vault.reveal_totp_full(&id).map_err(err)?;
    let Some((mut seed, algo, period, digits)) = full else { return Ok(None) };
    let config = bp_crypto::totp::TotpConfig {
        algorithm: algo
            .as_deref()
            .and_then(bp_crypto::totp::Algorithm::parse)
            .unwrap_or_default(),
        period: period.unwrap_or(bp_crypto::totp::DEFAULT_PERIOD as u32) as u64,
        digits: digits.unwrap_or(bp_crypto::totp::DEFAULT_DIGITS),
    };
    let (code, remaining_seconds, period) = bp_crypto::totp::current_with(&seed, &config);
    seed.zeroize();
    Ok(Some(TotpCode { code, remaining_seconds, period }))
}

#[tauri::command]
pub fn set_rotation_days(
    app: AppHandle,
    entry_id: String,
    days: Option<u32>,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), String> {
    let id = EntryId::parse(&entry_id).ok_or_else(|| "invalid entry id".to_string())?;
    let result = lock(&state).vault.set_rotation_days(&id, days).map_err(err);
    if result.is_ok() {
        crate::refresh_tray(&app);
    }
    result
}

#[tauri::command]
pub fn set_favorite(
    app: AppHandle,
    entry_id: String,
    favorite: bool,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), String> {
    let id = EntryId::parse(&entry_id).ok_or_else(|| "invalid entry id".to_string())?;
    let result = lock(&state).vault.set_favorite(&id, favorite).map_err(err);
    if result.is_ok() { crate::refresh_tray(&app); }
    result
}
