# SAFE: file-permissions-world-writable — restrictive permissions used (0o640)
# Rule: FilePermissionsWorldWritable | CWE-732 | Expected: TrueNegative

import os


def write_config(path: str, content: str) -> None:
    """Write a configuration file with owner-read/write, group-read permissions."""
    with open(path, 'w') as f:
        f.write(content)

    # SAFE: 0o640 = owner rw, group r, others no access; world-writable (0o777/0o666) not used
    os.chmod(path, 0o640)


if __name__ == '__main__':
    write_config('/tmp/app-config.json', '{"debug": false}')
    print('Config written with secure permissions (0o640)')
