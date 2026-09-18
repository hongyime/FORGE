use crate::{model::Result, paths};
use serde::Serialize;
use std::{
    fs,
    io::{self, Write},
    path::Path,
};

pub struct Outputs {
    receipt: fs::File,
    stdout: fs::File,
    stderr: fs::File,
    pub evidence_binding: String,
}

fn exclusive(path: &Path) -> Result<fs::File> {
    paths::no_links(path)?;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "evidence: output exists or cannot be created; use a new directory".into())
}

pub fn prepare(root: &Path, evidence: &Path) -> Result<Outputs> {
    paths::no_links(root)?;
    paths::no_links(evidence)?;
    if !root.is_dir() {
        return Err("domain: repository root unavailable".into());
    }
    let root = std::path::absolute(root).map_err(|_| "domain: invalid root")?;
    let destination =
        std::path::absolute(evidence).map_err(|_| "domain: invalid evidence destination")?;
    if !destination.starts_with(root.join(".omo/evidence")) {
        return Err("evidence: must be within ROOT/.omo/evidence".into());
    }
    let relative = destination
        .strip_prefix(&root)
        .map_err(|_| "evidence: invalid binding")?
        .to_str()
        .ok_or("evidence: non-UTF8 binding")?
        .replace('\\', "/");
    for name in ["receipt.json", "stdout.txt", "stderr.txt"] {
        let path = evidence.join(name);
        paths::no_links(&path)?;
        if path
            .try_exists()
            .map_err(|_| "evidence: cannot inspect output")?
        {
            return Err("evidence: occupied run destination; use a new directory".into());
        }
    }
    fs::create_dir_all(evidence).map_err(|_| "evidence: cannot create directory")?;
    Ok(Outputs {
        receipt: exclusive(&evidence.join("receipt.json"))?,
        stdout: exclusive(&evidence.join("stdout.txt"))?,
        stderr: exclusive(&evidence.join("stderr.txt"))?,
        evidence_binding: format!("<REPOSITORY_ROOT>/{relative}"),
    })
}

impl Outputs {
    pub fn emit(&mut self, stdout: &[u8], stderr: &[u8]) -> Result<()> {
        // The same bounded bytes are saved and emitted, without a child process.
        self.stdout
            .write_all(stdout)
            .and_then(|()| self.stdout.sync_all())
            .map_err(|_| "domain: stdout artifact write failed")?;
        self.stderr
            .write_all(stderr)
            .and_then(|()| self.stderr.sync_all())
            .map_err(|_| "domain: stderr artifact write failed")?;
        let mut out = io::stdout().lock();
        let mut err = io::stderr().lock();
        out.write_all(stdout)
            .and_then(|()| out.flush())
            .map_err(|_| "domain: stdout emission failed")?;
        err.write_all(stderr)
            .and_then(|()| err.flush())
            .map_err(|_| "domain: stderr emission failed")?;
        Ok(())
    }

    pub fn finish(&mut self, receipt: &impl Serialize) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(receipt)
            .map_err(|_| "domain: receipt serialization failed")?;
        self.receipt
            .write_all(&bytes)
            .and_then(|()| self.receipt.sync_all())
            .map_err(|_| "domain: receipt write failed".into())
    }
}
