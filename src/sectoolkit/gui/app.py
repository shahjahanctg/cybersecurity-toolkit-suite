"""GUI launch point (`sec-toolkit-gui`)."""

from __future__ import annotations

import sys


def main() -> int:
    try:
        from ..gui import is_gui_available
        if not is_gui_available():
            raise ImportError
        from ..gui.dashboard import launch
        return launch()
    except ImportError:
        from ..gui import _DEPENDENCY_HINT
        print(_DEPENDENCY_HINT, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())