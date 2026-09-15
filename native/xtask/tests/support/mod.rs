use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

pub struct Fixture {
    pub root: PathBuf,
}
impl Fixture {
    pub fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("target/t1-fixtures")
            .join(format!(
                "{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir_all(root.parent().unwrap()).unwrap();
        std::fs::create_dir(&root).unwrap();
        Self { root }
    }
    pub fn bytes(&self, path: &str, value: &[u8]) {
        let path = self.root.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, value).unwrap();
    }
    pub fn put(&self, path: &str, value: &str) {
        self.bytes(path, value.as_bytes());
    }
    pub fn populate(&self) {
        self.put("forge/cli.py", "import pytest\nclass TestSuite:\n    @pytest.mark.parametrize('x', [1, 2])\n    async def test_async(self, x):\n        assert x\napp.add_typer(public_app, name='public')\napp.add_typer(hidden_app, hidden=True)\nfor group in groups:\n    app.add_typer(group)\n@app.command('hello')\ndef hello(): pass\n");
        self.put("test_root.py", "def test_root(): pass\n");
        self.put(
            "rust_core/src/lib.rs",
            "#[cfg(test)] mod tests { #[test] fn works() { assert_eq!(2 + 2, 4); } }\n",
        );
        self.put("forge/ui/page.test.tsx", "import { test, expect } from 'vitest'; test.each([1,2])('case %s', (x) => { expect(x).toBeTruthy(); });\n");
        self.put(".github/workflows/check.yml", "name: check\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo test\n");
        for folder in [".agents", ".claude/handoffs", ".kiro/specs", ".omo/plans"] {
            self.put(
                &format!("{folder}/tasks.md"),
                "- [ ] DO_NOT_PERSIST_TASK_TEXT\n- [x] historical assertion without receipt\n",
            );
        }
        self.put("scripts/run.ps1", "Write-Output 'fixture'\n");
        self.put("pyproject.toml", "[project.scripts]\nforge = 'forge.cli:main'\n[tool.pytest.ini_options]\ntestpaths = ['tests']\n");
    }
    pub fn inventory(&self) -> Output {
        cli(&[
            "inventory",
            "--root",
            self.root.to_str().unwrap(),
            "--output",
            self.root.join("native/migration").to_str().unwrap(),
        ])
    }
    pub fn ledgers(&self) -> String {
        [
            "capabilities.json",
            "contracts.json",
            "tests.json",
            "session-work.json",
            "baseline.json",
        ]
        .into_iter()
        .map(|name| std::fs::read_to_string(self.root.join("native/migration").join(name)).unwrap())
        .collect()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}
pub fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_forge-xtask"))
        .args(args)
        .output()
        .unwrap()
}
pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
