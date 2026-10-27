//! Minimal reader for the active Omarchy theme palette (no TOML dependency).
//! Prefers `colors.toml`, falls back to `alacritty.toml`; anything unparsable yields `None`.
use std::path::{Path, PathBuf};

pub type Rgb = [u8; 3];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Palette {
    pub dark: bool,
    pub background: Rgb,
    /// Slightly darker than `background`; side panels.
    pub panel: Rgb,
    /// Darkest tone; text fields and code.
    pub extreme: Rgb,
    /// Slightly lighter than `background`; buttons and groups.
    pub surface: Rgb,
    pub foreground: Rgb,
    pub muted: Rgb,
    pub accent: Rgb,
    pub selection: Rgb,
    pub error: Rgb,
}

pub fn parse_hex(value: &str) -> Option<Rgb> {
    let hex = value.strip_prefix('#')?;
    if !(hex.len() == 6 || hex.len() == 8) || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let byte = |i: usize| u8::from_str_radix(&hex[i..i + 2], 16).ok();
    Some([byte(0)?, byte(2)?, byte(4)?])
}

/// `(section, key, value)` for simple `key = "value"` lines.
fn entries(text: &str) -> Vec<(String, String, String)> {
    let mut section = String::new();
    let mut out = Vec::new();
    for line in text.lines().take(4096) {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.trim().to_owned();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.split_once('"').map(|(inner, _)| inner))
            .or_else(|| {
                value
                    .strip_prefix('\'')
                    .and_then(|v| v.split_once('\'').map(|(i, _)| i))
            })
            .unwrap_or(value);
        out.push((section.clone(), key.trim().to_owned(), value.to_owned()));
    }
    out
}

fn mix(a: Rgb, b: Rgb, t: f32) -> Rgb {
    let lerp = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    [lerp(a[0], b[0]), lerp(a[1], b[1]), lerp(a[2], b[2])]
}

fn luminance(c: Rgb) -> f32 {
    (0.2126 * c[0] as f32 + 0.7152 * c[1] as f32 + 0.0722 * c[2] as f32) / 255.0
}

fn complete(
    background: Rgb,
    foreground: Rgb,
    accent: Rgb,
    get: impl Fn(&str) -> Option<Rgb>,
    mode: Option<&str>,
) -> Palette {
    let dark = match mode {
        Some("light") => false,
        Some("dark") => true,
        _ => luminance(background) < 0.5,
    };
    let shade = if dark { [0, 0, 0] } else { [255, 255, 255] };
    Palette {
        dark,
        background,
        panel: get("dark_background").unwrap_or_else(|| mix(background, shade, 0.25)),
        extreme: get("darker_background").unwrap_or_else(|| mix(background, shade, 0.5)),
        surface: get("lighter_background").unwrap_or_else(|| mix(background, foreground, 0.08)),
        foreground,
        muted: get("muted").unwrap_or_else(|| mix(background, foreground, 0.2)),
        accent,
        selection: get("selection").unwrap_or_else(|| mix(background, accent, 0.3)),
        error: get("red").unwrap_or([0xe0, 0x5f, 0x5f]),
    }
}

/// Omarchy's `colors.toml` (top-level `background`, `foreground`, `accent`, …).
pub fn parse_colors_toml(text: &str) -> Option<Palette> {
    let entries = entries(text);
    let raw = |key: &str| {
        entries
            .iter()
            .find(|(section, k, _)| section.is_empty() && k == key)
            .map(|(_, _, v)| v.clone())
    };
    let get = |key: &str| raw(key).as_deref().and_then(parse_hex);
    let background = get("background")?;
    let foreground = get("foreground")?;
    let accent = get("accent").or_else(|| get("blue"))?;
    let mode = raw("mode");
    Some(complete(
        background,
        foreground,
        accent,
        get,
        mode.as_deref(),
    ))
}

/// Alacritty theme fallback: `[colors.primary]`, `[colors.selection]`, `[colors.normal]`.
pub fn parse_alacritty(text: &str) -> Option<Palette> {
    let entries = entries(text);
    let get_in = |section: &str, key: &str| {
        entries
            .iter()
            .find(|(s, k, _)| s == section && k == key)
            .and_then(|(_, _, v)| parse_hex(v))
    };
    let background = get_in("colors.primary", "background")?;
    let foreground = get_in("colors.primary", "foreground")?;
    let accent = get_in("colors.normal", "blue").unwrap_or(foreground);
    let get = |key: &str| match key {
        "selection" => get_in("colors.selection", "background"),
        "muted" => get_in("colors.bright", "black"),
        "red" => get_in("colors.normal", "red"),
        _ => None,
    };
    Some(complete(background, foreground, accent, get, None))
}

/// Candidate active-theme directories, most specific first.
pub fn theme_dirs() -> Vec<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute());
    let state = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| home.as_ref().map(|h| h.join(".local/state")));
    let mut dirs = Vec::new();
    if let Some(home) = &home {
        dirs.push(home.join(".config/omarchy/current/theme"));
    }
    if let Some(state) = state {
        dirs.push(state.join("omarchy/current/theme"));
    }
    dirs
}

fn read_small(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    (meta.is_file() && meta.len() <= 256 * 1024)
        .then(|| std::fs::read_to_string(path).ok())
        .flatten()
}

/// Palette and the file it came from, from the first theme directory that parses.
pub fn load_from(dirs: &[PathBuf]) -> Option<(PathBuf, Palette)> {
    dirs.iter().find_map(|dir| {
        let colors = dir.join("colors.toml");
        if let Some(palette) = read_small(&colors).as_deref().and_then(parse_colors_toml) {
            return Some((colors, palette));
        }
        let alacritty = dir.join("alacritty.toml");
        read_small(&alacritty)
            .as_deref()
            .and_then(parse_alacritty)
            .map(|palette| (alacritty, palette))
    })
}

pub fn load_current() -> Option<(PathBuf, Palette)> {
    load_from(&theme_dirs())
}

#[cfg(test)]
mod tests {
    use super::*;

    const COLORS: &str = r##"mode = "dark"

accent = "#e68e0d"
selection = "#2a2a2a"
muted = "#333333"

background = "#121212"   # trailing comment
dark_background = "#0d0d0d"
darker_background = "#090909"
lighter_background = "#1e1e1e"
foreground = "#bebebe"
red = "#D35F5F"
hyprland_active_border = "rgba(26a269ee) rgba(2ec27eee) 45deg"
"##;

    const ALACRITTY: &str = r##"[colors.primary]
background = "#fdf6e3"
foreground = "#586e75"

[colors.selection]
text = "#bebebe"
background = "#eee8d5"

[colors.normal]
black = "#073642"
red = "#dc322f"
blue = "#268bd2"
"##;

    #[test]
    fn parses_omarchy_colors_toml() {
        let palette = parse_colors_toml(COLORS).unwrap();
        assert!(palette.dark);
        assert_eq!(palette.background, [0x12, 0x12, 0x12]);
        assert_eq!(palette.panel, [0x0d, 0x0d, 0x0d]);
        assert_eq!(palette.extreme, [0x09, 0x09, 0x09]);
        assert_eq!(palette.surface, [0x1e, 0x1e, 0x1e]);
        assert_eq!(palette.foreground, [0xbe, 0xbe, 0xbe]);
        assert_eq!(palette.accent, [0xe6, 0x8e, 0x0d]);
        assert_eq!(palette.selection, [0x2a, 0x2a, 0x2a]);
        assert_eq!(palette.error, [0xd3, 0x5f, 0x5f]);
    }

    #[test]
    fn parses_alacritty_fallback_and_detects_light_mode() {
        let palette = parse_alacritty(ALACRITTY).unwrap();
        assert!(!palette.dark);
        assert_eq!(palette.background, [0xfd, 0xf6, 0xe3]);
        assert_eq!(palette.accent, [0x26, 0x8b, 0xd2]);
        assert_eq!(palette.selection, [0xee, 0xe8, 0xd5]);
        // colors.toml keys inside sections are not top-level colors.
        assert!(parse_colors_toml(ALACRITTY).is_none());
    }

    #[test]
    fn rejects_malformed_colors() {
        assert!(parse_colors_toml("background = \"#12\"\nforeground = \"#fff\"").is_none());
        assert!(parse_colors_toml("").is_none());
        assert_eq!(parse_hex("#a1b2c3ff"), Some([0xa1, 0xb2, 0xc3]));
        assert_eq!(parse_hex("a1b2c3"), None);
        assert_eq!(parse_hex("#zzzzzz"), None);
    }

    #[test]
    fn loads_first_parsable_directory() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("missing");
        let only_alacritty = dir.path().join("b");
        std::fs::create_dir_all(&only_alacritty).unwrap();
        std::fs::write(only_alacritty.join("alacritty.toml"), ALACRITTY).unwrap();
        let (source, palette) = load_from(&[empty, only_alacritty.clone()]).unwrap();
        assert_eq!(source, only_alacritty.join("alacritty.toml"));
        assert!(!palette.dark);
        std::fs::write(only_alacritty.join("colors.toml"), COLORS).unwrap();
        let (source, _) = load_from(std::slice::from_ref(&only_alacritty)).unwrap();
        assert_eq!(source, only_alacritty.join("colors.toml"));
    }
}
