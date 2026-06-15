#!/usr/bin/env python3
"""Reconcile ARK-OS default config templates into /etc/ark-os, keeping user values.

Run from postinst. For each template in DEFAULTS_DIR:
  - seed the live config if it is absent (fresh install / brand-new file);
  - otherwise overlay the user's current values onto the NEW template so that newly
    added fields appear with their defaults, removed scalar fields drop out, and every
    field the user still has keeps their value.

The "user's current values" come from the pre-upgrade backup if present (preinst stashes
/etc/ark-os there before dpkg can touch the live files), else the live file itself.

Merge rule (see overlay()): template structure wins, user scalar/list values win, and
user-added *sub-tables* (e.g. extra mavlink-router [UdpEndpoint ...] sections) are kept —
only user-only *scalars* are pruned, since those are the removed schema fields.

.toml is handled by the `toml` lib; .ini/.conf by configparser (case-preserving, no
interpolation). Best-effort per file: a parse error seeds the template and logs a warning
rather than aborting the upgrade. Exit status is always 0.
"""
import sys
import os
import shutil
import configparser

try:
    import toml
except Exception:
    toml = None


def _ini_parser() -> configparser.ConfigParser:
    # optionxform=str: mavlink-router keys are CamelCase (TcpServerPort, FlowControl).
    # interpolation=None: values may contain '%'. strict=False: tolerate odd input.
    p = configparser.ConfigParser(interpolation=None, strict=False)
    p.optionxform = str
    return p


def load(path: str):
    """Return (kind, data) where data is a nested dict; kind in {'toml','ini'}."""
    if path.endswith('.toml'):
        if toml is None:
            raise RuntimeError('toml library unavailable')
        return 'toml', toml.load(path)
    p = _ini_parser()
    p.read(path)
    return 'ini', {s: dict(p[s]) for s in p.sections()}


def overlay(template, user):
    """Template structure with the user's value wherever a key exists in both.

    Keys only in the template (new) keep their default. User-only *scalars* are dropped
    (removed schema fields); user-only *dicts* are kept (user-added sections/tables).
    """
    if isinstance(template, dict):
        if not isinstance(user, dict):
            return template  # schema changed shape -> take the new template
        out = {}
        for k, tv in template.items():
            out[k] = overlay(tv, user[k]) if k in user else tv
        for k, uv in user.items():
            if k not in template and isinstance(uv, dict):
                out[k] = uv  # user-added section/table -> preserve
        return out
    # leaf: keep the user's scalar/list unless the schema turned it into a table
    return template if isinstance(user, dict) else user


def dump(kind: str, data: dict, path: str) -> None:
    tmp = path + '.tmp'
    if kind == 'toml':
        with open(tmp, 'w') as f:
            toml.dump(data, f)
    else:
        p = _ini_parser()
        for section, kv in data.items():
            p[section] = {k: str(v) for k, v in kv.items()}
        with open(tmp, 'w') as f:
            p.write(f)
    os.replace(tmp, path)  # atomic


def main() -> int:
    defaults_dir, user_dir, out_dir = sys.argv[1], sys.argv[2], sys.argv[3]
    os.makedirs(out_dir, exist_ok=True)
    for name in sorted(os.listdir(defaults_dir)):
        template = os.path.join(defaults_dir, name)
        if not os.path.isfile(template):
            continue
        out = os.path.join(out_dir, name)
        # user's values: pre-upgrade backup wins, else the live file, else none (seed).
        user = os.path.join(user_dir, name)
        if not os.path.isfile(user):
            user = out if os.path.isfile(out) else None
        if user is None:
            shutil.copyfile(template, out)
            print(f"  seeded  {name}")
            continue
        try:
            kind, tmpl = load(template)
            _, usr = load(user)
            dump(kind, overlay(tmpl, usr), out)
            print(f"  merged  {name}")
        except Exception as e:  # never break the upgrade over one bad file
            shutil.copyfile(template, out)
            print(f"  WARNING: merge failed for {name} ({e}); seeded default", file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
