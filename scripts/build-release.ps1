# BoxPassword Windows 로컬 릴리스 빌드 스크립트.
# 코드사인 없이도 동작합니다(설치 시 SmartScreen 한 번 우회 필요).
#
# 결과물:
#   target\release\bundle\msi\BoxPassword_<ver>_x64_en-US.msi
#   target\release\bundle\nsis\BoxPassword_<ver>_x64-setup.exe

$ErrorActionPreference = "Stop"

function Section($msg) { Write-Host ""; Write-Host "== $msg ==" -ForegroundColor Cyan }
function Ok($msg) { Write-Host "  + $msg" -ForegroundColor Green }
function Warn($msg) { Write-Host "  ! $msg" -ForegroundColor Yellow }
function Fail($msg) { Write-Host "  x $msg" -ForegroundColor Red; exit 1 }

if (-not $IsWindows -and -not ($PSVersionTable.PSVersion.Major -lt 6 -and [Environment]::OSVersion.Platform -eq 'Win32NT')) {
    Fail "이 스크립트는 Windows 전용입니다."
}

$ROOT = Split-Path -Parent $PSScriptRoot
Set-Location $ROOT

Section "1/4  필수 도구 확인"
foreach ($cmd in @("cargo", "node", "npm")) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Fail "$cmd 이 PATH 에 없습니다. docs\SETUP_WIN.md 를 먼저 따라가 주세요."
    }
}
$tauriOk = $false
try { cargo tauri --version | Out-Null; $tauriOk = $true } catch { }
if (-not $tauriOk) { Fail "cargo-tauri 가 없습니다.  cargo install tauri-cli --version `"^2`" --locked" }
Ok "cargo / node / cargo-tauri OK"

Section "2/4  품질 게이트"
if (-not $env:BOXPASSWORD_SKIP_TESTS) {
    cargo test --workspace --no-fail-fast
    Ok "cargo test 통과"
} else {
    Warn "BOXPASSWORD_SKIP_TESTS 가 설정되어 테스트를 건너뜁니다."
}
cargo fmt --check
Ok "rustfmt 정렬"

Section "3/4  릴리스 빌드 (cargo tauri build)"
Set-Location (Join-Path $ROOT "crates\bp-app")
cargo tauri build
Set-Location $ROOT
Ok "빌드 완료"

Section "4/4  산출물"
$bundleDir = Join-Path $ROOT "target\release\bundle"
foreach ($sub in @("msi", "nsis")) {
    $dir = Join-Path $bundleDir $sub
    if (Test-Path $dir) {
        Get-ChildItem $dir -File | ForEach-Object { Ok ".$sub : $($_.FullName)" }
    }
}

@"

설치 시 Windows SmartScreen 경고가 뜨면:
  "추가 정보" 클릭 -> "실행" 으로 우회 가능합니다.

정식 배포(SmartScreen 신뢰 즉시 획득) 가 필요하면 EV 코드사인 인증서를 발급받아
TAURI_SIGNING_PRIVATE_KEY 환경 변수를 설정하고 다시 실행하세요.

"@ | Write-Host
