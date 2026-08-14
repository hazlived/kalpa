import os
import time
from typing import Dict, Tuple, List, Callable, Optional

class FileWatcherDaemon:
    """
    Background file-polling daemon for monitoring target codebase updates,
    log files, and test output changes.
    Tracks file signatures (st_mtime, st_size) per path to avoid re-reading unchanged files.
    """

    def __init__(self, watch_dir: str):
        self.watch_dir = os.path.abspath(watch_dir)
        # Signature map: file_path -> (st_mtime, st_size)
        self._file_seen_signature: Dict[str, Tuple[float, int]] = {}

    def poll_updates(self, callback: Optional[Callable[[str, str], None]] = None) -> List[str]:
        """
        Polls watch_dir for modified or new files.
        Skips re-reading if (st_mtime, st_size) signature matches _file_seen_signature.
        Returns list of updated file paths.
        """
        updated_files: List[str] = []

        if not os.path.exists(self.watch_dir):
            return updated_files

        for root, _, files in os.walk(self.watch_dir):
            for file_name in files:
                full_path = os.path.join(root, file_name)
                try:
                    stat_res = os.stat(full_path)
                    current_signature = (stat_res.st_mtime, stat_res.st_size)

                    prev_signature = self._file_seen_signature.get(full_path)
                    if prev_signature != current_signature:
                        # File is new or modified
                        self._file_seen_signature[full_path] = current_signature
                        updated_files.append(full_path)

                        if callback is not None:
                            try:
                                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                                    content = f.read()
                                callback(full_path, content)
                            except Exception:
                                pass
                except OSError:
                    continue

        return updated_files

    def reset_signatures(self):
        """Clears stored file signatures."""
        self._file_seen_signature.clear()
