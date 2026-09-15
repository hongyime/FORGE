// Synthetic source is parsed as data. None of these programs are imported or run.
pub const FILES: &[(&str, &str)] = &[
    (
        "forge/cli.py",
        "import pytest\nclass TestSuite:\n    @pytest.mark.parametrize('x', [1, 2])\n    async def test_async(self, x):\n        assert x\napp.add_typer(public_app, name='public')\napp.add_typer(hidden_app, hidden=True)\nfor group in groups:\n    app.add_typer(group)\n@app.command('hello')\ndef hello(): pass\n",
    ),
    ("test_root.py", "def test_root(): pass\n"),
    (
        "rust_core/src/lib.rs",
        "#[cfg(test)] mod tests { #[test] fn works() { assert_eq!(2 + 2, 4); } }\n",
    ),
    (
        "forge/ui/page.test.tsx",
        "import { test, expect } from 'vitest'; test.each([1,2])('case %s', (x) => { expect(x).toBeTruthy(); });\n",
    ),
    (
        ".github/workflows/check.yml",
        "name: check\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo test\n",
    ),
    (
        ".agents/tasks.md",
        "- [ ] Synthetic reminder\n- [x] Unverified historical assertion\n",
    ),
    (".claude/handoffs/tasks.md", "- [ ] Synthetic reminder\n"),
    (".kiro/specs/tasks.md", "- [ ] Synthetic reminder\n"),
    (".omo/plans/tasks.md", "- [ ] Synthetic reminder\n"),
    ("scripts/run.ps1", "Write-Output 'fixture'\n"),
    (
        "pyproject.toml",
        "[project.scripts]\nforge = 'forge.cli:main'\n[tool.pytest.ini_options]\ntestpaths = ['tests']\n",
    ),
];

pub fn create(root: &std::path::Path) -> crate::model::Result<()> {
    for (path, source) in FILES {
        let file = root.join(path);
        let parent = file
            .parent()
            .ok_or_else(|| "fixture: invalid path".to_string())?;
        std::fs::create_dir_all(parent)
            .map_err(|_| "fixture: create directory failed".to_string())?;
        std::fs::write(file, source).map_err(|_| "fixture: write failed".to_string())?;
    }
    Ok(())
}
