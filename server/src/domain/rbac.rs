//! RBAC: 3 vault roles (viewer/editor/admin), spec §10. The source of truth is
//! the signed manifest+grant; the server resolves the author's role and enforces
//! write-accept + read-deny. The matrix — §10. Populated in Phase 6.

/// A member's role in a vault (the open column `role`). Encoding matches the core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Role {
    Viewer = 0,
    Editor = 1,
    Admin = 2,
}

impl Role {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Role::Viewer),
            1 => Some(Role::Editor),
            2 => Some(Role::Admin),
            _ => None,
        }
    }
    pub fn as_u8(self) -> u8 {
        self as u8
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Editor => "editor",
            Role::Admin => "admin",
        }
    }
}
