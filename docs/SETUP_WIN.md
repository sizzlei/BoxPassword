# BoxPassword — Windows 셋업 가이드

대상: Windows 10 (1809+) / Windows 11.
PowerShell 7 또는 Windows PowerShell 5.1 어느 쪽이든 OK.

---

## 0. 한눈에 보기

| 단계 | 도구 | 확인 명령 |
|---|---|---|
| 1 | Microsoft C++ Build Tools | `cl.exe /?` |
| 2 | WebView2 Runtime | `winver` 후 시스템 설치본 확인 |
| 3 | Rust (rustup) | `rustc --version` |
| 4 | Node.js (≥ 20) | `node --version` |
| 5 | Tauri CLI v2 | `cargo tauri --version` |
| 6 | 워크스페이스 빌드 | `cargo check --workspace` |

> Linux용 cross-compile 은 본 가이드 범위 밖입니다.

---

## 1. Microsoft C++ Build Tools

Rust 가 MSVC 툴체인을 통해 네이티브 코드와 링크하므로 필요.

1. https://visualstudio.microsoft.com/visual-cpp-build-tools/ 에서 **"Build Tools for Visual Studio 2022"** 다운로드.
2. 인스톨러에서 **"Desktop development with C++"** 워크로드 선택, 기본 옵션 그대로 설치.
3. 설치 후 PowerShell 재시작 → `cl.exe /?` 가 도움말을 출력하면 OK.

## 2. WebView2 Runtime

Windows 11 은 기본 포함. Windows 10 이면 한 번 설치:
https://developer.microsoft.com/en-us/microsoft-edge/webview2/ 에서 **"Evergreen Standalone Installer"** 다운로드 → 실행.

## 3. Rust (rustup)

PowerShell 관리자 권한:

```powershell
winget install --id Rustlang.Rustup -e
# 또는: https://win.rustup.rs 에서 rustup-init.exe 다운로드 → 실행
```

설치 후 PowerShell 재시작:

```powershell
rustup default stable
rustup component add rustfmt clippy
rustc --version
```

## 4. Node.js (≥ 20)

```powershell
winget install --id OpenJS.NodeJS.LTS -e
node --version
```

## 5. Tauri CLI v2

```powershell
cargo install tauri-cli --version "^2" --locked
cargo tauri --version
```

## 6. 빌드 확인

저장소 루트에서:

```powershell
cargo check --workspace
```

dev 모드 실행:

```powershell
cd crates\bp-app
cargo tauri dev
```

빈 창에 BoxPassword 메인 화면이 떠야 정상.

---

## 릴리스 빌드

루트에서:

```powershell
.\scripts\build-release.ps1
```

산출물:

- `target\release\bundle\msi\BoxPassword_<ver>_x64_en-US.msi` — Windows Installer
- `target\release\bundle\nsis\BoxPassword_<ver>_x64-setup.exe` — NSIS Installer

설치 후 시작 메뉴에 BoxPassword 가 등록되고, 시스템 트레이 아이콘이 표시됩니다.

---

## 코드사인 (선택)

Windows SmartScreen 경고를 피하려면 EV/OV 코드사인 인증서가 필요합니다.

```powershell
$env:TAURI_SIGNING_PRIVATE_KEY = "..."  # 또는 PFX 경로 + 비밀번호
.\scripts\build-release.ps1
```

자세한 옵션은 https://v2.tauri.app/distribute/sign/windows/ 참고.

---

## 문제 해결

- `link.exe not found`: Build Tools 설치 후 PowerShell 재시작.
- WebView2 런타임 누락 에러: Evergreen Installer 재설치.
- `pwsh` 가 없으면 `powershell.exe` 로 스크립트 실행 가능.
- 트레이 아이콘이 보이지 않으면 작업 표시줄 알림 영역 설정에서 BoxPassword 표시 활성화.
