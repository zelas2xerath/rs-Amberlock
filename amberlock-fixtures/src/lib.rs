use std::{fs, path::PathBuf};
use tempfile::{TempDir, tempdir};

pub struct TempTree {
    pub root: TempDir,
    pub files: Vec<PathBuf>,
    pub dirs: Vec<PathBuf>,
}

pub fn make_small_tree() -> TempTree {
    let root = tempdir().unwrap();
    let d1 = root.path().join("d1");
    fs::create_dir(&d1).unwrap();
    let f1 = d1.join("a.txt");
    fs::write(&f1, b"hello").unwrap();
    TempTree {
        root,
        files: vec![f1],
        dirs: vec![d1],
    }
}
