#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
: "${OMABRIDGE_JNI_SYMBOL:?Set the consumer JNI entry point}"
[[ $OMABRIDGE_JNI_SYMBOL =~ ^Java_[A-Za-z0-9_]+$ ]] || { echo 'Invalid JNI symbol' >&2; exit 1; }
[[ -z $(git status --porcelain --untracked-files=normal) ]] || { echo 'Commit the candidate source before packaging' >&2; exit 1; }
source_commit=$(git rev-parse HEAD)
# Cargo honors this override; packaging must read the same archive location.
target_root=${CARGO_TARGET_DIR:-$root/target}
mkdir -p "$target_root"
target_root=$(realpath "$target_root")
mode=${1:-host}
features=()
flavor=production
if [[ ${OMABRIDGE_LAB_TLS:-0} == 1 ]]; then
 features=(--features lab-tls)
 flavor=lab-tls
fi
output=${2:?Pass an output directory}
mkdir -p "$output"
output=$(realpath "$output")
if [[ $mode == host ]]; then
 cargo build --locked --release -p omabridge-mobile "${features[@]}"
 cmake -S mobile-sdk/jni -B "$target_root/mobile-jni-host-$source_commit" -DCMAKE_BUILD_TYPE=Release -DBRIDGE_JNI_SYMBOL="$OMABRIDGE_JNI_SYMBOL" -DBRIDGE_ARCHIVE="$target_root/release/libomabridge_mobile.a"
 cmake --build "$target_root/mobile-jni-host-$source_commit" --parallel 2
 install -m755 "$target_root/mobile-jni-host-$source_commit"/libomabridge_jni.so "$output/"
else
 : "${ANDROID_NDK_HOME:?Set the NDK path}"
 case "$mode" in
 x86_64) triple=x86_64-linux-android; cc=x86_64-linux-android24-clang;;
 arm64-v8a) triple=aarch64-linux-android; cc=aarch64-linux-android24-clang;;
 *) echo 'Expected host, x86_64 or arm64-v8a' >&2; exit 1;;
 esac
 bin="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
 export PATH="$bin:$PATH"
 export CC="$bin/$cc" AR="$bin/llvm-ar"
 target_key=${triple//-/_}
 linker_key="CARGO_TARGET_${target_key^^}_LINKER"
 export "$linker_key=$CC"
 cargo build --locked --release -p omabridge-mobile "${features[@]}" --target "$triple"
 cmake -S mobile-sdk/jni -B "$target_root/mobile-jni-$mode-$source_commit" -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" -DANDROID_ABI="$mode" -DANDROID_PLATFORM=android-24 -DCMAKE_BUILD_TYPE=Release -DBRIDGE_JNI_SYMBOL="$OMABRIDGE_JNI_SYMBOL" -DBRIDGE_ARCHIVE="$target_root/$triple/release/libomabridge_mobile.a"
 cmake --build "$target_root/mobile-jni-$mode-$source_commit" --parallel 2
 install -m755 "$target_root/mobile-jni-$mode-$source_commit/libomabridge_jni.so" "$output/"
fi
[[ $(git rev-parse HEAD) == "$source_commit" && -z $(git status --porcelain --untracked-files=normal) ]] || { echo 'Source changed during build' >&2; exit 1; }
{ printf 'source=%s\nabi=omabridge-mobile-1\ntarget=%s\nflavor=%s\n' "$source_commit" "$mode" "$flavor"; sha256sum "$output/libomabridge_jni.so"; } > "$output/omabridge-native.properties"
