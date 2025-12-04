use parking_lot::Mutex;
use std::{
    fs::File,
    io::BufReader,
    path::Path,
};

use amberlock_types::*;

pub struct NdjsonWriter {
    file: Mutex<File>,
}

impl NdjsonWriter {
    pub fn open_append<P: AsRef<Path>>(path: P) -> anyhow::Result<Self>;
    pub fn write_record<T: serde::Serialize>(&self, rec: &T) -> anyhow::Result<()>;
    pub fn flush(&self) -> anyhow::Result<()>;
}

pub struct NdjsonReader {
    file: BufReader<File>,
}

impl NdjsonReader {
    pub fn open<P: AsRef<Path>>(path: P) -> anyhow::Result<Self>;
    pub fn read_last_n(&mut self, n: usize) -> anyhow::Result<Vec<serde_json::Value>>;
    pub fn filter(
        &mut self,
        key_substr: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<serde_json::Value>>;
}

pub fn load_settings<P: AsRef<Path>>(path: P) -> anyhow::Result<Settings>;
pub fn save_settings<P: AsRef<Path>>(path: P, s: &Settings) -> anyhow::Result<()>;
