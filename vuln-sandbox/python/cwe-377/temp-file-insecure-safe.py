# SAFE: temp-file-insecure — tempfile.NamedTemporaryFile used for secure temp file creation
# Rule: FileTempFileInsecure | CWE-377 | Expected: TrueNegative

import tempfile
import os


def process_upload(data: bytes) -> str:
    """Write data to a secure temporary file and return its path."""
    # SAFE: NamedTemporaryFile creates a file with a random name and restricted permissions (0600)
    with tempfile.NamedTemporaryFile(delete=False, suffix='.tmp', mode='wb') as tmp:
        tmp.write(data)
        tmp_path = tmp.name

    try:
        # Process the file...
        result = f'Processed {len(data)} bytes from {os.path.basename(tmp_path)}'
    finally:
        # SAFE: always clean up the temporary file
        os.unlink(tmp_path)

    return result


if __name__ == '__main__':
    print(process_upload(b'hello world'))
