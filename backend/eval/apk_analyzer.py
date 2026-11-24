"""apk_analyzer.py - Lightweight upload validation and ZIP integrity checks for offline evaluation."""

from __future__ import annotations

import zipfile


class APKValidationError(Exception):
    """Raised when an uploaded file violates APK integrity or safety boundaries."""
    def __init__(self, message: str, status_code: int = 422, error_code: str = "invalid_apk"):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.error_code = error_code


def validate_zip_structure(
    file_path: str,
    max_entries: int = 10_000,
    max_uncompressed_bytes: int = 300 * 1024 * 1024,
    max_compression_ratio: float = 20.0,
) -> None:
    """Inspect ZIP container before extraction to protect against zip bombs and traversal attacks."""
    # Check magic bytes at start of file
    with open(file_path, "rb") as f:
        magic = f.read(4)
        if magic != b"PK\x03\x04":
            raise APKValidationError(
                "Uploaded file is not a valid ZIP/APK archive (magic bytes mismatch).",
                status_code=422,
                error_code="invalid_zip_archive",
            )

    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            infolist = zf.infolist()
            if len(infolist) > max_entries:
                raise APKValidationError(
                    f"Archive exceeds maximum allowed entry count ({len(infolist)} > {max_entries}).",
                    status_code=422,
                    error_code="zip_entry_count_exceeded",
                )

            total_uncompressed = 0
            has_manifest = False
            has_dex = False

            for info in infolist:
                # Path traversal checks
                filename = info.filename
                if ".." in filename or filename.startswith(("/", "\\")):
                    raise APKValidationError(
                        "Archive contains illegal path traversal filenames.",
                        status_code=422,
                        error_code="path_traversal_detected",
                    )

                # Compression ratio check for individual files
                compressed = max(info.compress_size, 1)
                ratio = info.file_size / compressed
                if ratio > max_compression_ratio and info.file_size > 1_000_000:
                    raise APKValidationError(
                        f"Archive entry exhibits suspicious compression ratio ({ratio:.1f}x).",
                        status_code=422,
                        error_code="zip_bomb_ratio_exceeded",
                    )

                total_uncompressed += info.file_size
                if total_uncompressed > max_uncompressed_bytes:
                    raise APKValidationError(
                        f"Total uncompressed size exceeds limit ({total_uncompressed} > {max_uncompressed_bytes} bytes).",
                        status_code=422,
                        error_code="zip_bomb_size_exceeded",
                    )

                if filename == "AndroidManifest.xml":
                    has_manifest = True
                elif filename.startswith("classes") and filename.endswith(".dex"):
                    has_dex = True

            if not has_manifest:
                raise APKValidationError(
                    "Uploaded archive does not contain AndroidManifest.xml.",
                    status_code=422,
                    error_code="missing_android_manifest",
                )

            if not has_dex:
                raise APKValidationError(
                    "Uploaded archive does not contain any executable classes*.dex files.",
                    status_code=422,
                    error_code="missing_dex_code",
                )

    except zipfile.BadZipFile as exc:
        raise APKValidationError(
            f"Corrupt or malformed ZIP archive: {exc}",
            status_code=422,
            error_code="corrupt_zip_archive",
        ) from exc
