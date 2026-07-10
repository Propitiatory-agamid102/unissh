//! Import of `~/.ssh/config` (a subset for the MVP, spec 10.4).
//!
//! Supported directives: `Host` (with `*`/`?` patterns), `HostName`, `Port`,
//! `User`, `IdentityFile`, `ProxyJump`. Semantics as in OpenSSH: for each key the
//! **first** value encountered among the matching blocks wins.

use crate::error::TransportError;

/// Parsed settings for a single host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostSettings {
    /// The real host name (`HostName`).
    pub hostname: Option<String>,
    /// Port (`Port`).
    pub port: Option<u16>,
    /// User (`User`).
    pub user: Option<String>,
    /// Path to the key (`IdentityFile`).
    pub identity_file: Option<String>,
    /// Chain of jump hosts (`ProxyJump`), as in the config (comma-separated).
    pub proxy_jump: Option<String>,
}

#[derive(Debug)]
struct HostBlock {
    patterns: Vec<String>,
    settings: HostSettings,
}

/// Parsed ssh-config.
#[derive(Debug, Default)]
pub struct SshConfig {
    blocks: Vec<HostBlock>,
}

impl SshConfig {
    /// Parses the config text.
    pub fn parse(text: &str) -> Result<Self, TransportError> {
        let mut blocks: Vec<HostBlock> = Vec::new();
        let mut current: Option<HostBlock> = None;

        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (keyword, rest) = split_keyword(line);
            let key = keyword.to_ascii_lowercase();

            if key == "host" {
                if let Some(b) = current.take() {
                    blocks.push(b);
                }
                let patterns = rest.split_whitespace().map(|s| s.to_string()).collect();
                current = Some(HostBlock {
                    patterns,
                    settings: HostSettings::default(),
                });
                continue;
            }

            let block = match current.as_mut() {
                Some(b) => b,
                // ignore directives outside a Host block (Match etc. are not supported)
                None => continue,
            };
            let value = rest.trim();
            match key.as_str() {
                "hostname" => block.settings.hostname = Some(value.to_string()),
                "port" => {
                    block.settings.port = Some(
                        value
                            .parse()
                            .map_err(|_| TransportError::Config(format!("bad port: {value}")))?,
                    )
                }
                "user" => block.settings.user = Some(value.to_string()),
                "identityfile" => block.settings.identity_file = Some(value.to_string()),
                "proxyjump" => block.settings.proxy_jump = Some(value.to_string()),
                _ => {} // ignore other directives
            }
        }
        if let Some(b) = current.take() {
            blocks.push(b);
        }
        Ok(SshConfig { blocks })
    }

    /// Concrete (non-pattern) host aliases in order of appearance — for importing
    /// into connection profiles. Patterns (`*`/`?`/`!`) and duplicates are skipped.
    pub fn host_aliases(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for block in &self.blocks {
            for p in &block.patterns {
                if !p.contains(['*', '?', '!']) && !out.contains(p) {
                    out.push(p.clone());
                }
            }
        }
        out
    }

    /// Resolves an alias into settings (the first value per key among the matching blocks).
    pub fn resolve(&self, alias: &str) -> HostSettings {
        let mut out = HostSettings::default();
        for block in &self.blocks {
            if block_matches(&block.patterns, alias) {
                merge(&mut out, &block.settings);
            }
        }
        out
    }
}

/// OpenSSH semantics for matching a `Host` block's pattern list against an alias:
/// the block applies ⇔ at least one NON-negative pattern matched AND NO negative
/// pattern (`!pat`) matched. Negation takes priority regardless of position.
/// Previously `!` tokens were treated as literals (never matching), because of which
/// an excluded host still received the block's settings (e.g. an unintended
/// ProxyJump) — a divergence from OpenSSH in a security-relevant directive.
fn block_matches(patterns: &[String], alias: &str) -> bool {
    let mut positive_hit = false;
    for p in patterns {
        if let Some(neg) = p.strip_prefix('!') {
            if glob_match(neg, alias) {
                return false; // explicit exclusion — the block does not apply
            }
        } else if glob_match(p, alias) {
            positive_hit = true;
        }
    }
    positive_hit
}

fn split_keyword(line: &str) -> (&str, &str) {
    // support `Key value` and `Key=value`
    if let Some(idx) = line.find(['=', ' ', '\t']) {
        let (k, v) = line.split_at(idx);
        (k.trim(), v[1..].trim_start_matches(['=', ' ', '\t']))
    } else {
        (line, "")
    }
}

fn merge(into: &mut HostSettings, from: &HostSettings) {
    if into.hostname.is_none() {
        into.hostname = from.hostname.clone();
    }
    if into.port.is_none() {
        into.port = from.port;
    }
    if into.user.is_none() {
        into.user = from.user.clone();
    }
    if into.identity_file.is_none() {
        into.identity_file = from.identity_file.clone();
    }
    if into.proxy_jump.is_none() {
        into.proxy_jump = from.proxy_jump.clone();
    }
}

/// Simple glob: `*` (any number of characters) and `?` (a single character). An
/// iterative two-pointer approach with backtracking only over the last `*` — linear,
/// without recursion and without catastrophic backtracking on patterns like `*a*a*…`.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();

    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None; // position of the last '*' in the pattern
    let mut star_ti = 0usize; // position in the text at the moment of that '*'

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if let Some(s) = star {
            // backtrack: '*' consumes one more character of the text
            pi = s + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    // the remaining tail of the pattern must consist only of '*'
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}
