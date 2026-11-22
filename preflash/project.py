"""Load an Arduino / ESP32 / PlatformIO project into memory for scanning."""
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

CODE_EXT = {".ino", ".pde", ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh"}
CONFIG_NAMES = {"platformio.ini", "sdkconfig", "sdkconfig.defaults", "partitions.csv"}
KEY_EXT = {".key", ".pem"}   # only checked for private keys
SKIP_DIRS = {".git", ".pio", "build", "node_modules", ".vscode", "__pycache__",
             "managed_components", "components", "lib_deps", ".github"}
# Third-party library folders produce noise that isn't the user's fault.
LIB_DIRS = {"libraries", "lib", "libdeps", "vendor", "third_party", "external"}
MAX_BYTES = 2_000_000


@dataclass
class SourceFile:
    path: Path              # relative to project root
    text: str
    lines: list = field(default_factory=list)
    code: str = ""          # comments blanked out, same length/line numbers
    is_config: bool = False

    def line_of(self, offset: int) -> int:
        return self.text.count("\n", 0, offset) + 1


_comment_re = re.compile(
    r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'',
    re.DOTALL,
)


def strip_comments(text: str) -> str:
    """Blank out comments but keep string literals and line numbers intact."""
    def repl(m):
        s = m.group(0)
        if s.startswith("/"):
            return re.sub(r"[^\n]", " ", s)
        return s
    return _comment_re.sub(repl, text)


def load(root: Path, include_libs: bool = False):
    root = root.resolve()
    files = []
    if root.is_file():
        candidates = [root]
        root = root.parent
    else:
        candidates = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS
                           and (include_libs or d.lower() not in LIB_DIRS)]
            for fn in filenames:
                candidates.append(Path(dirpath) / fn)
    for p in candidates:
        is_cfg = p.name in CONFIG_NAMES or p.suffix.lower() in KEY_EXT
        if p.suffix.lower() not in CODE_EXT and not is_cfg:
            continue
        try:
            if p.stat().st_size > MAX_BYTES:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        sf = SourceFile(path=p.relative_to(root), text=text,
                        lines=text.splitlines(), is_config=is_cfg)
        sf.code = text if is_cfg else strip_comments(text)
        files.append(sf)
    return root, files
