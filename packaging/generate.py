#!/usr/bin/env python3
"""Generate nfpm configs, systemd units, and install scripts from packages.yaml.

Usage: python3 generate.py [--output-dir DIR]
"""

import argparse
import json
import os
from pathlib import Path

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent

# ─── Type defaults ─────────────────────────────────────────────────────────────

TYPE_DEFAULTS = {
    "python": {
        "base_depends": ["python3", "python3-flask"],
        "exec_start": lambda name, cfg: f"python3 /opt/ark/bin/{cfg['script']}",
        "contents_src": lambda name, cfg: f"services/{name}/{cfg['script']}",
        "contents_dst": lambda name, cfg: f"/opt/ark/bin/{cfg['script']}",
        "after": ["network-online.target", "syslog.target"],
        "wants": ["network.target", "network-online.target", "syslog.target"],
        "environment": {"PYTHONUNBUFFERED": "1"},
        "restart": "on-failure",
    },
    "cpp": {
        "base_depends": [],
        "exec_start": lambda name, cfg: f"/opt/ark/bin/{cfg.get('binary', name)}",
        "contents_src": lambda name, cfg: f"build/{name}/{cfg.get('binary', name)}",
        "contents_dst": lambda name, cfg: f"/opt/ark/bin/{cfg.get('binary', name)}",
        "after": ["syslog.target", "network.target"],
        "wants": ["network.target"],
        "environment": {},
        "restart": "on-failure",
    },
    "bash": {
        "base_depends": [],
        "exec_start": lambda name, cfg: f"/opt/ark/bin/{cfg['script']}",
        "contents_src": lambda name, cfg: f"services/{name}/{cfg['script']}",
        "contents_dst": lambda name, cfg: f"/opt/ark/bin/{cfg['script']}",
        "after": ["network-online.target", "syslog.target"],
        "wants": ["network.target"],
        "environment": {},
        "restart": "on-failure",
    },
}

# ─── Manifest reading ─────────────────────────────────────────────────────────

def read_manifest(name):
    """Read a service's .manifest.json if it exists."""
    manifest_path = PROJECT_ROOT / "services" / name / f"{name}.manifest.json"
    if manifest_path.exists():
        with open(manifest_path) as f:
            return json.load(f)
    return {}


def is_system_service(name, manifest):
    """Determine if a service runs as a system (root) service."""
    return manifest.get("requires_sudo", False)

# ─── Systemd unit generation ──────────────────────────────────────────────────

def generate_systemd_unit(name, cfg, manifest):
    """Generate a systemd .service file."""
    svc_type = cfg.get("type", "custom")
    defaults = TYPE_DEFAULTS.get(svc_type, TYPE_DEFAULTS["cpp"])
    sd = cfg.get("systemd", {})
    system_svc = is_system_service(name, manifest)

    # Description: use explicit override, or derive from manifest displayName
    description = sd.get("description")
    if not description:
        display_name = manifest.get("displayName", name.replace("-", " ").title())
        description = f"ARK {display_name}"

    after_list = sd.get("after", defaults["after"])
    wants_list = sd.get("wants", defaults["wants"])

    # [Unit]
    unit_lines = [
        "[Unit]",
        f"Description={description}",
    ]

    if sd.get("condition_path_is_directory"):
        unit_lines.append(f"ConditionPathIsDirectory={sd['condition_path_is_directory']}")

    if wants_list:
        unit_lines.append(f"Wants={' '.join(wants_list)}")
    if after_list:
        unit_lines.append(f"After={' '.join(after_list)}")

    # [Service]
    svc_lines = ["", "[Service]"]

    service_type = sd.get("type", "simple")
    svc_lines.append(f"Type={service_type}")

    # Environment
    env = dict(defaults["environment"])
    env.update(sd.get("environment", {}))
    for key, val in env.items():
        svc_lines.append(f'Environment="{key}={val}"')

    # ExecStartPre
    if sd.get("exec_start_pre"):
        svc_lines.append(f"ExecStartPre={sd['exec_start_pre']}")

    # ExecStart
    exec_start = sd.get("exec_start")
    if not exec_start:
        fn = defaults.get("exec_start")
        exec_start = fn(name, cfg) if callable(fn) else fn
    svc_lines.append(f"ExecStart={exec_start}")

    # Restart
    restart = sd.get("restart", defaults["restart"])
    if restart and restart is not False:
        svc_lines.append(f"Restart={restart}")
        svc_lines.append("RestartSec=5")

    # Resource controls
    if sd.get("nice") is not None:
        svc_lines.append(f"Nice={sd['nice']}")
    if sd.get("cpu_weight") is not None:
        svc_lines.append(f"CPUWeight={sd['cpu_weight']}")
    if sd.get("kill_mode"):
        svc_lines.append(f"KillMode={sd['kill_mode']}")

    # [Install]
    wanted_by = "multi-user.target" if system_svc else "default.target"
    install_lines = ["", "[Install]", f"WantedBy={wanted_by}"]

    return "\n".join(unit_lines + svc_lines + install_lines) + "\n"

# ─── Script generation ─────────────────────────────────────────────────────────

def generate_postinst_user(name, default_enabled=True):
    enable_lines = ""
    if default_enabled:
        enable_lines = f"""    sudo -u "$SUDO_USER" XDG_RUNTIME_DIR="$RUNTIME_DIR" systemctl --user enable "{name}.service"
    sudo -u "$SUDO_USER" XDG_RUNTIME_DIR="$RUNTIME_DIR" systemctl --user restart "{name}.service"
"""
        enable_lines_no_sudo = f"""    systemctl --user enable "{name}.service"
    systemctl --user restart "{name}.service"
"""
    else:
        enable_lines = ""
        enable_lines_no_sudo = ""

    return f"""#!/bin/bash
loginctl enable-linger "${{SUDO_USER:-$USER}}" 2>/dev/null || true
if [ -n "$SUDO_USER" ]; then
    RUNTIME_DIR="/run/user/$(id -u "$SUDO_USER")"
    sudo -u "$SUDO_USER" XDG_RUNTIME_DIR="$RUNTIME_DIR" systemctl --user daemon-reload
{enable_lines}else
    systemctl --user daemon-reload
{enable_lines_no_sudo}fi
"""


def generate_prerm_user(name):
    return f"""#!/bin/bash
if [ -n "$SUDO_USER" ]; then
    RUNTIME_DIR="/run/user/$(id -u "$SUDO_USER")"
    sudo -u "$SUDO_USER" XDG_RUNTIME_DIR="$RUNTIME_DIR" systemctl --user stop "{name}.service" 2>/dev/null || true
    sudo -u "$SUDO_USER" XDG_RUNTIME_DIR="$RUNTIME_DIR" systemctl --user disable "{name}.service" 2>/dev/null || true
else
    systemctl --user stop "{name}.service" 2>/dev/null || true
    systemctl --user disable "{name}.service" 2>/dev/null || true
fi
"""


def generate_postinst_system(name, default_enabled=True):
    if default_enabled:
        return f"""#!/bin/bash
systemctl daemon-reload
systemctl enable "{name}.service"
systemctl restart "{name}.service"
"""
    else:
        return f"""#!/bin/bash
systemctl daemon-reload
"""


def generate_prerm_system(name):
    return f"""#!/bin/bash
systemctl stop "{name}.service" 2>/dev/null || true
systemctl disable "{name}.service" 2>/dev/null || true
"""

# ─── nfpm YAML generation (string-based for exact formatting) ──────────────────

def _q(s):
    """Quote a string for nfpm YAML output."""
    return f'"{s}"'


def _content_block(src, dst, mode=None, entry_type=None):
    """Format a single nfpm contents entry."""
    lines = [f"  - src: {src}", f"    dst: {dst}"]
    if mode:
        lines.append("    file_info:")
        lines.append(f"      mode: {mode}")
    if entry_type:
        lines.append(f"    type: {entry_type}")
    return "\n".join(lines)


def generate_nfpm_yaml(name, cfg, defaults_cfg, manifest):
    """Generate an nfpm YAML config string for a service package."""
    svc_type = cfg.get("type", "custom")
    type_defaults = TYPE_DEFAULTS.get(svc_type, {})
    system_svc = is_system_service(name, manifest)
    pkg_name = f"ark-{name}"

    # Header
    lines = [
        f"name: {pkg_name}",
        f'version: "${{VERSION}}"',
        f'arch: "${{ARCH}}"',
        "platform: linux",
        f'maintainer: {_q(defaults_cfg["maintainer"])}',
        f'description: {_q(cfg.get("description", manifest.get("description", "")))}',
        f'vendor: {_q(defaults_cfg["vendor"])}',
        f'homepage: {_q(defaults_cfg["homepage"])}',
        f'license: {_q(defaults_cfg["license"])}',
    ]

    # Dependencies
    base_deps = list(type_defaults.get("base_depends", []))
    extra_deps = cfg.get("depends", [])
    all_deps = base_deps + extra_deps
    if all_deps:
        lines.append("")
        lines.append("depends:")
        for dep in all_deps:
            lines.append(f"  - {dep}")

    # Contents
    content_blocks = []

    if svc_type == "custom":
        for item in cfg.get("contents", []):
            mode = item.get("mode")
            content_blocks.append(
                _content_block(f"../../{item['src']}", item["dst"],
                               mode=mode, entry_type=item.get("type")))
    else:
        fn_src = type_defaults["contents_src"]
        fn_dst = type_defaults["contents_dst"]
        content_blocks.append(
            _content_block(f"../../{fn_src(name, cfg)}", fn_dst(name, cfg), mode="0755"))

    for item in cfg.get("extra_contents", []):
        if item.get("type"):
            content_blocks.append(
                _content_block(f"../../{item['src']}", item["dst"],
                               entry_type=item["type"]))
        else:
            content_blocks.append(
                _content_block(f"../../{item['src']}", item["dst"], mode="0755"))

    # Auto-include manifest.json if it exists
    manifest_src = PROJECT_ROOT / "services" / name / f"{name}.manifest.json"
    if manifest_src.exists():
        content_blocks.append(
            _content_block(f"../../services/{name}/{name}.manifest.json",
                           f"/opt/ark/share/{name}/{name}.manifest.json"))

    # Systemd unit
    unit_dir = "/etc/systemd/system" if system_svc else "/etc/systemd/user"
    content_blocks.append(
        _content_block(f"./service-files/{name}.service",
                       f"{unit_dir}/{name}.service", entry_type="config"))

    lines.append("")
    lines.append("contents:")
    lines.append(("\n\n").join(content_blocks))

    # Scripts
    lines.append("")
    lines.append("scripts:")
    lines.append(f"  postinstall: ./scripts/postinst-{name}.sh")
    lines.append(f"  preremove: ./scripts/prerm-{name}.sh")

    return "\n".join(lines) + "\n"


def generate_nfpm_custom_yaml(pkg_name, cfg, defaults_cfg):
    """Generate an nfpm YAML config string for a custom (non-service) package."""
    lines = [
        f"name: {pkg_name}",
        f'version: "${{VERSION}}"',
        f'arch: "${{ARCH}}"',
        "platform: linux",
        f'maintainer: {_q(defaults_cfg["maintainer"])}',
        f'description: {_q(cfg.get("description", ""))}',
        f'vendor: {_q(defaults_cfg["vendor"])}',
        f'homepage: {_q(defaults_cfg["homepage"])}',
        f'license: {_q(defaults_cfg["license"])}',
    ]

    if cfg.get("depends"):
        lines.append("")
        lines.append("depends:")
        for dep in cfg["depends"]:
            lines.append(f"  - {dep}")

    if cfg.get("contents"):
        content_blocks = []
        for item in cfg["contents"]:
            content_blocks.append(
                _content_block(f"../../{item['src']}", item["dst"],
                               entry_type=item.get("type")))
        lines.append("")
        lines.append("contents:")
        lines.append(("\n\n").join(content_blocks))

    has_scripts = cfg.get("postinst") or cfg.get("prerm")
    if has_scripts:
        lines.append("")
        lines.append("scripts:")
        if cfg.get("postinst"):
            lines.append(f"  postinstall: ./scripts/postinst-{pkg_name}.sh")
        if cfg.get("prerm"):
            lines.append(f"  preremove: ./scripts/prerm-{pkg_name}.sh")

    return "\n".join(lines) + "\n"

# ─── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Generate packaging files from packages.yaml")
    parser.add_argument("--output-dir", default=str(SCRIPT_DIR / "generated"),
                        help="Output directory (default: packaging/generated/)")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)

    with open(SCRIPT_DIR / "packages.yaml") as f:
        config = yaml.safe_load(f)

    defaults_cfg = config["defaults"]
    services = config.get("services", {})
    custom_packages = config.get("custom_packages", {})

    (output_dir / "scripts").mkdir(parents=True, exist_ok=True)
    (output_dir / "service-files").mkdir(parents=True, exist_ok=True)

    generated_files = []

    # ── Generate service packages ──

    for name, cfg in services.items():
        manifest = read_manifest(name)
        system_svc = is_system_service(name, manifest)

        # Systemd unit
        unit = generate_systemd_unit(name, cfg, manifest)
        unit_path = output_dir / "service-files" / f"{name}.service"
        unit_path.write_text(unit)
        generated_files.append(str(unit_path.relative_to(output_dir)))

        # Install/remove scripts
        default_enabled = cfg.get("default_enabled", True)
        if system_svc:
            postinst = generate_postinst_system(name, default_enabled)
            prerm = generate_prerm_system(name)
        else:
            postinst = generate_postinst_user(name, default_enabled)
            prerm = generate_prerm_user(name)

        postinst_path = output_dir / "scripts" / f"postinst-{name}.sh"
        prerm_path = output_dir / "scripts" / f"prerm-{name}.sh"
        postinst_path.write_text(postinst)
        prerm_path.write_text(prerm)
        os.chmod(postinst_path, 0o755)
        os.chmod(prerm_path, 0o755)
        generated_files.extend([
            str(postinst_path.relative_to(output_dir)),
            str(prerm_path.relative_to(output_dir)),
        ])

        # nfpm config
        nfpm_yaml = generate_nfpm_yaml(name, cfg, defaults_cfg, manifest)
        nfpm_path = output_dir / f"ark-{name}.yaml"
        nfpm_path.write_text(nfpm_yaml)
        generated_files.append(str(nfpm_path.relative_to(output_dir)))

    # ── Generate custom packages ──

    for pkg_name, cfg in custom_packages.items():
        nfpm_yaml = generate_nfpm_custom_yaml(pkg_name, cfg, defaults_cfg)
        nfpm_path = output_dir / f"{pkg_name}.yaml"
        nfpm_path.write_text(nfpm_yaml)
        generated_files.append(str(nfpm_path.relative_to(output_dir)))

        if cfg.get("postinst"):
            p = output_dir / "scripts" / f"postinst-{pkg_name}.sh"
            p.write_text(cfg["postinst"])
            os.chmod(p, 0o755)
            generated_files.append(str(p.relative_to(output_dir)))
        if cfg.get("prerm"):
            p = output_dir / "scripts" / f"prerm-{pkg_name}.sh"
            p.write_text(cfg["prerm"])
            os.chmod(p, 0o755)
            generated_files.append(str(p.relative_to(output_dir)))

    print(f"Generated {len(generated_files)} files in {output_dir}/")
    for f in sorted(generated_files):
        print(f"  {f}")


if __name__ == "__main__":
    main()
