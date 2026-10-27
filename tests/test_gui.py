import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")


def test_gui_scan_end_to_end(tree, tmp_path):
    from PySide6.QtCore import QEventLoop, QTimer
    from PySide6.QtWidgets import QApplication

    from hashvault.ui.app import MainWindow

    _app = QApplication.instance() or QApplication([])
    win = MainWindow(str(tmp_path / "g.db"))
    assert win.start_scan(str(tree), confirm=False)
    loop = QEventLoop()
    timer = QTimer()
    timer.setInterval(50)

    def check():
        if win._thread is None:
            loop.quit()

    timer.timeout.connect(check)
    timer.start()
    QTimer.singleShot(15000, loop.quit)
    loop.exec()
    assert win.snapshots.rowCount() == 1
    assert win.files.rowCount() == 5
    assert win.dups.rowCount() == 2
    win.close()
