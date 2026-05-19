//! BoxPassword Tauri 호스트 진입점.
//!
//! 평문 비밀은 마스터 비밀번호로 잠금 해제된 동안에만 코어 메모리에 머무릅니다.
//! 트레이 아이콘에서 즐겨찾기·최근·즉시 생성 / 검색 팝오버까지 제공합니다.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

mod commands;
mod keychain;
mod state;

use std::sync::Mutex;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tauri::{
    image::Image,
    menu::{Menu, MenuBuilder, MenuItem, SubmenuBuilder},
    tray::TrayIconBuilder,
    AppHandle, Emitter, Manager, WindowEvent,
};
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut, ShortcutState};
use zeroize::Zeroize;

use crate::state::AppState;

// ---------- 트레이 아이콘 PNG 임베디드 ----------
const TRAY_UNLOCKED_PNG: &[u8] = include_bytes!("../icons/tray-unlocked.png");
const TRAY_LOCKED_PNG: &[u8] = include_bytes!("../icons/tray-locked.png");

fn decode_icon(bytes: &[u8]) -> Image<'static> {
    let img = image::load_from_memory_with_format(bytes, image::ImageFormat::Png)
        .expect("decode tray PNG")
        .to_rgba8();
    let (w, h) = img.dimensions();
    Image::new_owned(img.into_raw(), w, h)
}

// ---------- 윈도우 ----------
fn show_main_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

fn toggle_quick_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("quick") {
        if w.is_visible().unwrap_or(false) {
            let _ = w.hide();
        } else {
            let _ = w.center();
            let _ = w.show();
            let _ = w.set_focus();
        }
    }
}

// ---------- 공용 도우미 (트레이용) ----------
fn hash_text(s: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let r = h.finalize();
    let mut o = [0u8; 32];
    o.copy_from_slice(&r);
    o
}

fn copy_to_clipboard_clearing(text: String, delay_ms: u64) {
    if let Ok(mut cb) = arboard::Clipboard::new() {
        let _ = cb.set_text(text.clone());
    }
    let expected = hash_text(&text);
    let mut buf = text;
    buf.zeroize();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(delay_ms));
        if let Ok(mut cb) = arboard::Clipboard::new() {
            if let Ok(cur) = cb.get_text() {
                if hash_text(&cur) == expected {
                    let _ = cb.set_text(String::new());
                }
            }
        }
    });
}

// ---------- 트레이 액션 ----------
/// 트레이/Quick Search 액션 호출 시 vault 가 잠겨 있으면 Keychain 에서 silently 복원.
/// 복원 성공 또는 이미 unlocked 면 true.
pub fn ensure_unlocked_via_keychain(app: &AppHandle) -> bool {
    {
        let state = app.state::<Mutex<AppState>>();
        let guard = state.lock().expect("AppState mutex poisoned");
        if guard.vault.is_unlocked() {
            return true;
        }
    }
    let key = match keychain::load() {
        Ok(k) => k,
        Err(_) => return false,
    };
    let restored = {
        let state = app.state::<Mutex<AppState>>();
        let mut guard = state.lock().expect("AppState mutex poisoned");
        guard.vault.unlock_with_key(key).is_ok()
    };
    if restored {
        refresh_tray(app);
        let _ = app.emit("bp:status-changed", ());
    }
    restored
}

fn tray_copy_entry(app: &AppHandle, entry_id_str: &str) {
    let Some(id) = bp_core::EntryId::parse(entry_id_str) else { return };
    if !ensure_unlocked_via_keychain(app) {
        let _ = app.emit("bp:tray-needs-unlock", entry_id_str.to_string());
        return;
    }
    let secret_opt: Option<String> = {
        let state = app.state::<Mutex<AppState>>();
        let guard = state.lock().expect("AppState mutex poisoned");
        guard.vault.reveal_secret(&id).ok()
    };
    if let Some(secret) = secret_opt {
        copy_to_clipboard_clearing(secret, 30_000);
        let _ = app.emit("bp:clipboard-set", 30_u64);
    }
}

fn tray_generate(app: &AppHandle, kind: &str) {
    use bp_core::{GeneratorMode, PasswordPolicy};
    let policy = match kind {
        "random-20" => PasswordPolicy { length: 20, ..PasswordPolicy::default() },
        "random-32" => PasswordPolicy { length: 32, ..PasswordPolicy::default() },
        "passphrase-5" => PasswordPolicy {
            mode: GeneratorMode::Passphrase { words: 5, separator: "-".into(), capitalize: true },
            ..PasswordPolicy::default()
        },
        "passphrase-7" => PasswordPolicy {
            mode: GeneratorMode::Passphrase { words: 7, separator: "-".into(), capitalize: true },
            ..PasswordPolicy::default()
        },
        _ => return,
    };
    match bp_passgen::generate(&policy, 1) {
        Ok(mut pwds) => {
            if let Some(pw) = pwds.pop() {
                copy_to_clipboard_clearing(pw, 30_000);
                let _ = app.emit("bp:generated", 30_u64);
            }
        }
        Err(e) => tracing::warn!(error = %e, "tray generate failed"),
    }
}

// ---------- 트레이 메뉴 빌드 ----------
fn build_tray_menu(app: &AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    let (unlocked, entries) = {
        let state = app.state::<Mutex<AppState>>();
        let guard = state.lock().expect("AppState mutex poisoned");
        let u = guard.vault.is_unlocked();
        let e = if u {
            guard.vault.list_entries().unwrap_or_default()
        } else {
            Vec::new()
        };
        (u, e)
    };

    // 즐겨찾기 서브메뉴 — 클릭 즉시 패스워드 복사.
    let favorites: Vec<&bp_core::EntrySummary> =
        entries.iter().filter(|e| e.favorite).take(8).collect();
    let mut fav_sub = SubmenuBuilder::new(app, "★ 즐겨찾기");
    if !unlocked {
        fav_sub = fav_sub.text("nop-fav-locked", "잠금 해제 필요");
    } else if favorites.is_empty() {
        fav_sub = fav_sub.text("nop-fav-empty", "즐겨찾기 항목이 없습니다");
    } else {
        for e in &favorites {
            fav_sub = fav_sub.text(format!("entry-copy:{}", e.id), format!("📋 {}", e.title));
        }
    }
    let fav_submenu = fav_sub.build()?;

    // 최근 서브메뉴 — 클릭 즉시 패스워드 복사.
    let mut sorted = entries.clone();
    sorted.sort_by_key(|e| std::cmp::Reverse(e.updated_at.clone()));
    let recent: Vec<&bp_core::EntrySummary> = sorted.iter().take(8).collect();
    let mut recent_sub = SubmenuBuilder::new(app, "🕒 최근");
    if !unlocked {
        recent_sub = recent_sub.text("nop-recent-locked", "잠금 해제 필요");
    } else if recent.is_empty() {
        recent_sub = recent_sub.text("nop-recent-empty", "항목이 없습니다");
    } else {
        for e in &recent {
            recent_sub = recent_sub.text(format!("entry-copy:{}", e.id), format!("📋 {}", e.title));
        }
    }
    let recent_submenu = recent_sub.build()?;

    // 즉시 생성 서브메뉴
    let gen_submenu = SubmenuBuilder::new(app, "🎲 비밀번호 즉시 생성")
        .text("tray-gen:random-20", "랜덤 20자 → 클립보드")
        .text("tray-gen:random-32", "랜덤 32자 → 클립보드")
        .text("tray-gen:passphrase-5", "패스프레이즈 5단어 → 클립보드")
        .text("tray-gen:passphrase-7", "패스프레이즈 7단어 → 클립보드")
        .build()?;

    let lock_item = MenuItem::with_id(app, "tray-lock", "Vault 잠그기", unlocked, None::<&str>)?;

    MenuBuilder::new(app)
        .text("tray-quick", "🔍 빠른 검색…   ⌘⇧K")
        .text("tray-show", "BoxPassword 창 열기")
        .separator()
        .item(&fav_submenu)
        .item(&recent_submenu)
        .item(&gen_submenu)
        .separator()
        .item(&lock_item)
        .text("tray-clear", "클립보드 비우기")
        .separator()
        .text("tray-quit", "BoxPassword 종료")
        .build()
}

pub fn refresh_tray(app: &AppHandle) {
    let Some(tray) = app.tray_by_id("bp-tray") else { return };
    if let Ok(menu) = build_tray_menu(app) {
        let _ = tray.set_menu(Some(menu));
    }
    let unlocked = {
        let state = app.state::<Mutex<AppState>>();
        let guard = state.lock().expect("AppState mutex poisoned");
        guard.vault.is_unlocked()
    };
    let icon = if unlocked {
        decode_icon(TRAY_UNLOCKED_PNG)
    } else {
        decode_icon(TRAY_LOCKED_PNG)
    };
    let _ = tray.set_icon(Some(icon));
}

fn handle_tray_menu(app: &AppHandle, id: &str) {
    match id {
        "tray-show" => show_main_window(app),
        "tray-quick" => toggle_quick_window(app),
        "tray-lock" => {
            {
                let state = app.state::<Mutex<AppState>>();
                let mut guard = state.lock().expect("AppState mutex poisoned");
                guard.vault.lock();
            }
            refresh_tray(app);
            let _ = app.emit("bp:status-changed", ());
            show_main_window(app);
        }
        "tray-clear" => {
            if let Ok(mut cb) = arboard::Clipboard::new() {
                let _ = cb.set_text(String::new());
            }
            let _ = app.emit("bp:clipboard-cleared", ());
        }
        "tray-quit" => app.exit(0),
        id if id.starts_with("entry-copy:") => tray_copy_entry(app, &id["entry-copy:".len()..]),
        id if id.starts_with("tray-gen:") => tray_generate(app, &id["tray-gen:".len()..]),
        _ => {}
    }
}

// 빠른 검색 윈도우에서 호출할 헬퍼 커맨드.
#[tauri::command]
fn hide_quick_window(app: AppHandle) {
    if let Some(w) = app.get_webview_window("quick") {
        let _ = w.hide();
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let vault_path = state::default_vault_path();
    tracing::info!(?vault_path, "starting BoxPassword");

    let state = AppState::open(vault_path).expect("vault open failed");

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(
            tauri_plugin_global_shortcut::Builder::new()
                .with_handler(|app, shortcut, event| {
                    if event.state() != ShortcutState::Pressed {
                        return;
                    }
                    let quick =
                        Shortcut::new(Some(Modifiers::SUPER | Modifiers::SHIFT), Code::KeyK);
                    if shortcut == &quick {
                        toggle_quick_window(app);
                    }
                })
                .build(),
        )
        .manage(Mutex::new(state))
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                let label = window.label();
                if label == "main" || label == "quick" {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .setup(|app| {
            let initial_menu = build_tray_menu(app.handle())?;
            let initial_icon = decode_icon(TRAY_LOCKED_PNG);
            let _tray = TrayIconBuilder::with_id("bp-tray")
                .icon(initial_icon)
                .tooltip("BoxPassword — 클릭하여 메뉴 열기")
                .menu(&initial_menu)
                // 좌클릭과 우클릭 모두 메뉴를 띄움 (macOS 메뉴바 표준 패턴).
                .show_menu_on_left_click(true)
                .on_menu_event(|app, event| handle_tray_menu(app, event.id.as_ref()))
                .build(app)?;

            // 글로벌 단축키 등록
            let shortcut = Shortcut::new(Some(Modifiers::SUPER | Modifiers::SHIFT), Code::KeyK);
            if let Err(e) = app.global_shortcut().register(shortcut) {
                tracing::warn!(error = %e, "global shortcut register failed");
            }

            // 시작 시 Keychain 에 vault_key 가 보관돼 있으면 자동 잠금 해제.
            // 사용자가 명시적으로 enable 한 경우에만 항목이 존재함.
            if keychain::has_entry() {
                if let Ok(key) = keychain::load() {
                    let state = app.state::<Mutex<AppState>>();
                    let mut guard = state.lock().expect("AppState mutex poisoned");
                    match guard.vault.unlock_with_key(key) {
                        Ok(_) => tracing::info!("auto-unlocked from keychain"),
                        Err(e) => tracing::warn!(error = %e, "keychain key did not verify; clearing"),
                    }
                }
            }
            refresh_tray(app.handle());

            // 슬립/장시간 미사용 감지: 모놀로닉 시계가 멈춘 만큼의 갭을 신호로 활용.
            // 시스템이 잠들었다 깨면 sleep 했던 시간만큼 갭이 생긴다.
            let app_handle = app.handle().clone();
            std::thread::spawn(move || {
                let interval = Duration::from_secs(10);
                let threshold = Duration::from_secs(15);
                let mut last = std::time::Instant::now();
                loop {
                    std::thread::sleep(interval);
                    let now = std::time::Instant::now();
                    let gap = now.duration_since(last);
                    last = now;
                    if gap >= threshold {
                        tracing::info!(?gap, "system resumed from sleep");
                        let _ = app_handle.emit("bp:system-resumed", gap.as_secs());
                    }
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault_status,
            commands::initialize_vault,
            commands::unlock_vault,
            commands::lock_vault,
            commands::list_entries,
            commands::create_entry,
            commands::reveal_secret,
            commands::reveal_version_secret,
            commands::list_versions,
            commands::update_secret,
            commands::restore_version,
            commands::delete_entry,
            commands::set_favorite,
            commands::list_groups,
            commands::create_group,
            commands::rename_group,
            commands::set_group_color,
            commands::delete_group,
            commands::assign_entry_group,
            commands::copy_to_clipboard,
            commands::clear_clipboard,
            commands::generate_passwords,
            commands::estimate_strength,
            commands::analyze_health,
            commands::export_vault,
            commands::import_vault,
            commands::import_csv,
            commands::change_master_password,
            commands::keychain_has,
            commands::keychain_status,
            commands::keychain_save_current,
            commands::keychain_clear,
            commands::keychain_try_unlock,
            commands::get_entry_notes,
            commands::set_entry_notes,
            commands::set_entry_totp,
            commands::clear_entry_totp,
            commands::entry_totp_code,
            commands::set_rotation_days,
            commands::app_version,
            hide_quick_window,
        ])
        .run(tauri::generate_context!())
        .expect("error while running BoxPassword");
}
