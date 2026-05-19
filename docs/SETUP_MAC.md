# BoxPassword — macOS 초기 구성 가이드

이 문서는 macOS(Apple Silicon / Intel 모두) 환경에서 BoxPassword 개발을 시작하기 위해 필요한 도구를 직접 설치·검증하는 절차입니다. 자동화가 필요하면 `scripts/setup-mac.sh`를 사용하세요.

대상 OS는 macOS 13(Ventura) 이상을 권장합니다.

---

## 0. 한눈에 보기

| 단계 | 도구 | 확인 명령 |
|---|---|---|
| 1 | Xcode Command Line Tools | `xcode-select -p` |
| 2 | Homebrew | `brew --version` |
| 3 | Rust (rustup) | `rustc --version` |
| 4 | Node.js (≥ 20) | `node --version` |
| 5 | Tauri CLI v2 | `cargo tauri --version` |
| 6 | 워크스페이스 빌드 | `cargo check --workspace` |

---

## 1. Xcode Command Line Tools

Tauri는 Rust → 네이티브 링킹 과정에서 Apple Clang 툴체인을 사용합니다.

```bash
xcode-select --install   # 이미 깔려 있으면 에러 메시지가 떠도 무시
xcode-select -p          # /Library/Developer/CommandLineTools 가 보이면 OK
```

GUI 설치창이 떠도 자동화 스크립트는 자동 폴링으로 끝까지 기다립니다.

## 2. Homebrew

Node 등 시스템 의존성을 손쉽게 관리하기 위해 Homebrew를 설치합니다.

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
# Apple Silicon 사용자는 셸 환경에 brew 경로 추가
echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
eval "$(/opt/homebrew/bin/brew shellenv)"
```

## 3. Rust (rustup)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
source "$HOME/.cargo/env"
rustup component add rustfmt clippy
rustc --version
```

저장소 루트에는 `rust-toolchain.toml`이 있어, 디렉토리에 진입하면 stable 채널이 자동 선택됩니다.

## 4. Node.js (≥ 20)

프론트엔드(웹뷰) 자산을 빌드/번들링하는 데 사용됩니다. 향후 SvelteKit이나 React 도입 시점부터 필요합니다.

```bash
brew install node
node --version
```

## 5. Tauri CLI v2

```bash
cargo install tauri-cli --version "^2" --locked
cargo tauri --version
```

## 6. 빌드 확인

루트에서 워크스페이스가 컴파일되는지 확인합니다(첫 실행은 의존성 다운로드로 다소 시간 소요).

```bash
cargo check --workspace
```

그리고 데스크톱 셸을 띄워봅니다.

```bash
cd crates/bp-app
cargo tauri dev
```

빈 창에 "pong from BoxPassword core"가 표시되면 정상입니다.

---

## 자동화 스크립트

위 1~6단계를 한 번에 실행하려면 다음을 사용하세요.

```bash
./scripts/setup-mac.sh
```

스크립트는 멱등하게 동작합니다(이미 설치된 도구는 건너뜀).

## 문제 해결

- `cargo tauri dev` 실행 시 "WebView2 not found" 류 메시지가 나오면 macOS가 아닌 환경에서 실행한 것입니다. 본 프로젝트는 macOS / Windows를 별도 빌드 경로로 다룹니다.
- Apple Silicon에서 Rosetta 미설치 메시지가 나오면 `softwareupdate --install-rosetta --agree-to-license`.
- Vault 파일은 기본적으로 `~/Library/Application Support/BoxPassword/` 아래에 저장됩니다(개발 중에는 `target/dev/` 하위로 임시 분리).
