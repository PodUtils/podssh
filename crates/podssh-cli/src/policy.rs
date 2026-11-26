//! `--policy FILE` (T-838): the algorithm policy read before anything
//! connects. A file that cannot be read, or that does not parse, is a fault
//! of the setup (78), with its line named; a field that podssh does not
//! know is refused there, never ignored.

use std::io::Read;

use podssh_ssh::policy::{parse, Policy, MAX_BYTES};

use crate::relay_settings::Refusal;

/// The policy in the file `path`.
pub fn load(path: &str) -> Result<Policy, Refusal> {
    let refused = |why: String| Refusal::config(format!("--policy {path}: {why}"));
    let file = std::fs::File::open(path).map_err(|e| refused(podssh_ws::text::said(&e)))?;
    let mut bytes = Vec::new();
    // One byte past the bound, so that a longer file is said to be one.
    file.take(MAX_BYTES as u64 + 1).read_to_end(&mut bytes).map_err(|e| refused(podssh_ws::text::said(&e)))?;
    parse(&bytes).map_err(|e| refused(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_that_does_not_load_is_a_fault_of_the_setup_with_its_line() {
        let dir = std::env::temp_dir().join(format!("podssh-policy-load-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("p.txt");
        std::fs::write(&file, "name = \"x\"\nversion = 1\nfrobnicate = yes\n").unwrap();
        let path = file.display().to_string();
        let refusal = load(&path).unwrap_err();
        assert_eq!(refusal.code, crate::exitmap::sysexits::EX_CONFIG);
        assert!(refusal.message.contains("line 3") && refusal.message.contains("frobnicate"), "{refusal}");
        let missing = load(&dir.join("none").display().to_string()).unwrap_err();
        assert_eq!(missing.code, crate::exitmap::sysexits::EX_CONFIG);
        std::fs::write(&file, "name = \"x\"\nversion = 1\nciphers = aes128-ctr\n").unwrap();
        assert_eq!(load(&path).unwrap().ciphers, Some(vec!["aes128-ctr".to_string()]));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
