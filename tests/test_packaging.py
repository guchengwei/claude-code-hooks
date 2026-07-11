import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins" / "coding-agent-hooks"


class PackagingTests(unittest.TestCase):
    def test_claude_marketplace_points_to_self_contained_plugin(self) -> None:
        marketplace = json.loads(
            (ROOT / ".claude-plugin" / "marketplace.json").read_text()
        )
        entry = next(
            plugin
            for plugin in marketplace["plugins"]
            if plugin["name"] == "coding-agent-hooks"
        )

        self.assertEqual(entry["source"], "./plugins/coding-agent-hooks")
        self.assertEqual(
            marketplace["$schema"],
            "https://json.schemastore.org/claude-code-marketplace.json",
        )
        manifest = json.loads(
            (PLUGIN / ".claude-plugin" / "plugin.json").read_text()
        )
        self.assertEqual(manifest["name"], entry["name"])
        self.assertTrue((PLUGIN / "hooks" / "hooks.json").is_file())
        self.assertTrue((PLUGIN / "bin" / "agent-hooks").is_file())
        hooks = json.loads((PLUGIN / "hooks" / "hooks.json").read_text())
        for event in hooks["hooks"].values():
            self.assertIn("--adapter auto", event[0]["hooks"][0]["command"])

    def test_codex_marketplace_uses_repository_identity(self) -> None:
        marketplace = json.loads(
            (ROOT / ".agents" / "plugins" / "marketplace.json").read_text()
        )
        manifest = json.loads(
            (PLUGIN / ".codex-plugin" / "plugin.json").read_text()
        )

        self.assertEqual(marketplace["name"], "coding-agent-hooks")
        self.assertEqual(
            marketplace["interface"]["displayName"], "Coding Agent Hooks"
        )
        self.assertEqual(manifest["author"]["name"], "guchengwei")
        self.assertNotIn("skills", manifest)
        entry = next(
            plugin
            for plugin in marketplace["plugins"]
            if plugin["name"] == manifest["name"]
        )
        self.assertEqual(
            entry["source"],
            {"source": "local", "path": "./plugins/coding-agent-hooks"},
        )
        self.assertEqual(
            entry["policy"],
            {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
        )
        self.assertEqual(entry["category"], "Productivity")
        self.assertTrue((PLUGIN / "hooks" / "hooks.json").is_file())
        hooks = json.loads((PLUGIN / "hooks" / "hooks.json").read_text())
        self.assertEqual(set(hooks), {"hooks"})

    def test_gemini_extension_calls_the_shared_runtime(self) -> None:
        manifest = json.loads((ROOT / "gemini-extension.json").read_text())
        hooks = json.loads((ROOT / "hooks" / "hooks.json").read_text())

        self.assertEqual(manifest["name"], "coding-agent-hooks")
        self.assertEqual(set(hooks["hooks"]), {"BeforeTool", "AfterTool"})
        for event in hooks["hooks"].values():
            command = event[0]["hooks"][0]["command"]
            self.assertIn(
                "${extensionPath}/plugins/coding-agent-hooks/bin/agent-hooks",
                command,
            )
            self.assertIn("--adapter gemini", command)

    def test_agent_package_versions_match(self) -> None:
        versions = {
            json.loads(
                (PLUGIN / ".claude-plugin" / "plugin.json").read_text()
            )["version"],
            json.loads(
                (PLUGIN / ".codex-plugin" / "plugin.json").read_text()
            )["version"],
            json.loads((ROOT / "gemini-extension.json").read_text())["version"],
        }

        self.assertEqual(versions, {"0.1.0"})

    @unittest.skipUnless(shutil.which("claude"), "Claude CLI is not installed")
    def test_claude_cli_validates_and_installs_marketplace_plugin(self) -> None:
        validation = subprocess.run(
            ["claude", "plugin", "validate", str(ROOT)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(
            validation.returncode,
            0,
            validation.stdout + validation.stderr,
        )

        with tempfile.TemporaryDirectory() as home:
            environment = os.environ.copy()
            environment["HOME"] = home
            add_marketplace = subprocess.run(
                [
                    "claude",
                    "plugin",
                    "marketplace",
                    "add",
                    "./",
                    "--scope",
                    "user",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
                env=environment,
            )
            install = subprocess.run(
                [
                    "claude",
                    "plugin",
                    "install",
                    "coding-agent-hooks@coding-agent-hooks",
                    "--scope",
                    "user",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
                env=environment,
            )
            runtime = (
                Path(home)
                / ".claude/plugins/cache/coding-agent-hooks/"
                "coding-agent-hooks/0.1.0/bin/agent-hooks"
            )
            runtime_installed = runtime.is_file()

        self.assertEqual(
            add_marketplace.returncode,
            0,
            add_marketplace.stdout + add_marketplace.stderr,
        )
        self.assertEqual(install.returncode, 0, install.stdout + install.stderr)
        self.assertTrue(runtime_installed)

    @unittest.skipUnless(shutil.which("codex"), "Codex CLI is not installed")
    def test_codex_cli_ingests_and_installs_marketplace_plugin(self) -> None:
        with tempfile.TemporaryDirectory() as codex_home:
            environment = os.environ.copy()
            environment["CODEX_HOME"] = codex_home
            add_marketplace = subprocess.run(
                [
                    "codex",
                    "plugin",
                    "marketplace",
                    "add",
                    str(ROOT),
                    "--json",
                ],
                text=True,
                capture_output=True,
                check=False,
                env=environment,
            )
            install = subprocess.run(
                [
                    "codex",
                    "plugin",
                    "add",
                    "coding-agent-hooks@coding-agent-hooks",
                    "--json",
                ],
                text=True,
                capture_output=True,
                check=False,
                env=environment,
            )
            installed_path = Path(json.loads(install.stdout)["installedPath"])
            runtime_installed = (installed_path / "bin" / "agent-hooks").is_file()
            hooks_installed = (installed_path / "hooks" / "hooks.json").is_file()

        self.assertEqual(
            add_marketplace.returncode,
            0,
            add_marketplace.stdout + add_marketplace.stderr,
        )
        self.assertEqual(install.returncode, 0, install.stdout + install.stderr)
        self.assertTrue(runtime_installed)
        self.assertTrue(hooks_installed)


if __name__ == "__main__":
    unittest.main()
