#!/usr/bin/env python3
"""Rewrite a pre-3005 logloader.toml from its flat keys into the nested layout.

merge_configs.py takes its structure from the new template and prunes scalars the
template does not have. That is right for a removed field and wrong for a renamed
one: without this step an upgrade would silently drop upload_enabled, remote_server
and email, and a vehicle that had been uploading to a remote Flight Review would
quietly stop.

Runs from postinst, before merge_configs.py, over both the live config and the
pre-upgrade backup. Idempotent: a file that already has [upload] is left alone.
"""
import sys
import os

try:
    import toml
except Exception:
    toml = None

# Old flat key -> where it lives now.
RENAMES = {
    'local_server': ('upload', 'local', 'url'),
    'remote_server': ('upload', 'remote', 'url'),
    'email': ('upload', 'remote', 'email'),
    'upload_enabled': ('upload', 'remote', 'enabled'),
    'public_logs': ('upload', 'remote', 'public'),
    'remote_api_key': ('upload', 'remote', 'api_key'),
    'application_directory': ('data', 'directory'),
    'remote_log_directory': ('download', 'remote_directory'),
    'ftp_use_burst': ('download', 'use_burst'),
}


def migrate(path: str) -> bool:
    """Returns True when the file was rewritten."""
    if not os.path.isfile(path):
        return False

    try:
        config = toml.load(path)
    except Exception as error:
        print('migrate_logloader_config: cannot parse %s (%s), leaving it alone' % (path, error),
              file=sys.stderr)
        return False

    # Already migrated, or written against the new layout to begin with.
    if 'upload' in config or not any(key in config for key in RENAMES):
        return False

    for flat, destination in RENAMES.items():
        if flat not in config:
            continue

        value = config.pop(flat)
        table = config

        for part in destination[:-1]:
            table = table.setdefault(part, {})

        # A value already set under the new name wins; this only fills gaps.
        table.setdefault(destination[-1], value)

    # local uploads used to be implicit and always on.
    config.setdefault('upload', {}).setdefault('local', {}).setdefault('enabled', True)

    with open(path, 'w', encoding='utf-8') as handle:
        toml.dump(config, handle)

    print('migrate_logloader_config: rewrote %s in the nested layout' % path)
    return True


def main() -> int:
    if toml is None:
        print('migrate_logloader_config: toml library unavailable, skipping', file=sys.stderr)
        return 0

    for path in sys.argv[1:]:
        try:
            migrate(path)
        except Exception as error:
            # Never fail an upgrade over this; the flat keys are still read by
            # logloader itself as a fallback.
            print('migrate_logloader_config: %s: %s' % (path, error), file=sys.stderr)

    return 0


if __name__ == '__main__':
    sys.exit(main())
