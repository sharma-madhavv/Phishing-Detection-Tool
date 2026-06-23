"""
dataset_loader.py
-------------------
Discovers and loads a phishing-email dataset from a given path, which
may be:
  - a single .eml or .msg file
  - a single .csv file (one row per email)
  - a directory containing any mix of the above (recursively)
  - a .zip archive containing any mix of the above

Returns a list of normalized email dicts ready for detector.risk_scorer.
"""

import csv
import zipfile
import tempfile
from pathlib import Path

from .email_parser import parse_eml_file, parse_msg_file, parse_csv_row

SUPPORTED_EMAIL_EXTS = {".eml", ".msg"}


def load_dataset(path):
    """
    Main entry point. Accepts a file or directory path (str or Path).
    Returns: list of normalized email dicts.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Path does not exist: {path}")

    if path.is_file():
        if path.suffix.lower() == ".zip":
            return _load_zip(path)
        return _load_single_file(path)

    if path.is_dir():
        return _load_directory(path)

    raise ValueError(f"Unsupported path type: {path}")


def _load_single_file(path):
    suffix = path.suffix.lower()
    if suffix == ".eml":
        return [parse_eml_file(path)]
    if suffix == ".msg":
        return [parse_msg_file(path)]
    if suffix == ".csv":
        return _load_csv(path)
    raise ValueError(
        f"Unsupported file type '{suffix}'. Supported: .eml, .msg, .csv, .zip, or a directory."
    )


def _load_csv(path):
    emails = []
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader):
            try:
                emails.append(parse_csv_row(row, row_index=idx, source_file=path.name))
            except Exception as e:
                print(f"  [warn] Skipped row {idx} in {path.name}: {e}")
    return emails


def _load_directory(path):
    emails = []
    errors = []

    for filepath in sorted(path.rglob("*")):
        if not filepath.is_file():
            continue
        suffix = filepath.suffix.lower()
        try:
            if suffix == ".eml":
                emails.append(parse_eml_file(filepath))
            elif suffix == ".msg":
                emails.append(parse_msg_file(filepath))
            elif suffix == ".csv":
                emails.extend(_load_csv(filepath))
            elif suffix == ".zip":
                emails.extend(_load_zip(filepath))
        except Exception as e:
            errors.append((str(filepath), str(e)))

    if errors:
        print(f"  [warn] {len(errors)} file(s) failed to parse and were skipped:")
        for fp, err in errors[:10]:
            print(f"    - {fp}: {err}")

    return emails


def _load_zip(path):
    emails = []
    with tempfile.TemporaryDirectory() as tmpdir:
        with zipfile.ZipFile(path, "r") as zf:
            zf.extractall(tmpdir)
        emails = _load_directory(Path(tmpdir))
    return emails


def load_from_bytes(filename, raw_bytes):
    """
    Used by the Streamlit UI for in-memory uploaded files (no disk path).
    Supports .eml, .msg (via temp file), and .csv.
    """
    suffix = Path(filename).suffix.lower()

    if suffix == ".eml":
        from .email_parser import parse_eml_bytes
        return [parse_eml_bytes(raw_bytes, source_file=filename)]

    if suffix == ".msg":
        with tempfile.NamedTemporaryFile(suffix=".msg", delete=False) as tmp:
            tmp.write(raw_bytes)
            tmp_path = tmp.name
        try:
            return [parse_msg_file(tmp_path)]
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    if suffix == ".csv":
        import io
        text = raw_bytes.decode("utf-8", errors="replace")
        reader = csv.DictReader(io.StringIO(text))
        emails = []
        for idx, row in enumerate(reader):
            try:
                emails.append(parse_csv_row(row, row_index=idx, source_file=filename))
            except Exception as e:
                print(f"  [warn] Skipped row {idx} in {filename}: {e}")
        return emails

    if suffix == ".zip":
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            tmp.write(raw_bytes)
            tmp_path = tmp.name
        try:
            return _load_zip(Path(tmp_path))
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    raise ValueError(f"Unsupported uploaded file type: {suffix}")
