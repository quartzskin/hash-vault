from __future__ import annotations

import sys
import threading

from PySide6.QtCore import QObject, QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .. import scanner
from ..analysis import compare, find_duplicates
from ..db import Vault
from ..export import export_comparison, export_duplicates, export_entries


class ScanWorker(QObject):
    # own SQLite connection, since this runs on another thread
    progress = Signal(int, str)
    finished = Signal(int)
    failed = Signal(str)
    cancelled = Signal()

    def __init__(self, db_path: str, root: str):
        super().__init__()
        self.db_path, self.root = db_path, root
        self.cancel_event = threading.Event()

    def run(self) -> None:
        try:
            with Vault(self.db_path) as vault:
                snap = scanner.scan(
                    self.root,
                    vault,
                    progress=lambda n, p: self.progress.emit(n, p),
                    cancel=self.cancel_event,
                )
            self.finished.emit(snap)
        except scanner.ScanCancelled:
            self.cancelled.emit()
        except Exception as exc:
            self.failed.emit(str(exc))


def _table(headers: list[str]) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.setEditTriggers(QTableWidget.NoEditTriggers)
    t.setSelectionBehavior(QTableWidget.SelectRows)
    t.setAlternatingRowColors(True)
    t.horizontalHeader().setStretchLastSection(True)
    return t


def _fill(t: QTableWidget, rows: list[list]) -> None:
    t.setRowCount(len(rows))
    for r, row in enumerate(rows):
        for c, v in enumerate(row):
            t.setItem(r, c, QTableWidgetItem("" if v is None else str(v)))
    t.resizeColumnsToContents()


class MainWindow(QMainWindow):
    def __init__(self, db_path: str):
        super().__init__()
        self.db_path = db_path
        self.vault = Vault(db_path)
        self._thread: QThread | None = None
        self._worker: ScanWorker | None = None
        self._cmp = None
        self.setWindowTitle("Hash Vault")
        self.resize(1000, 640)

        self.btn_scan = QPushButton("Scan directory…")
        self.btn_cancel = QPushButton("Cancel scan")
        self.btn_cancel.setEnabled(False)
        self.btn_delete = QPushButton("Delete snapshot")
        self.btn_export = QPushButton("Export current view…")
        self.btn_scan.clicked.connect(self.choose_and_scan)
        self.btn_cancel.clicked.connect(self.cancel_scan)
        self.btn_delete.clicked.connect(self.delete_snapshot)
        self.btn_export.clicked.connect(self.export_current)
        bar = QHBoxLayout()
        for b in (self.btn_scan, self.btn_cancel, self.btn_delete, self.btn_export):
            bar.addWidget(b)
        bar.addStretch()

        self.snapshots = _table(["ID", "Created (UTC)", "Files", "Errors", "Root"])
        self.snapshots.setMaximumHeight(160)
        self.snapshots.itemSelectionChanged.connect(self.refresh_views)

        self.files = _table(["Path", "Size", "Status", "SHA-256", "Note"])
        self.dups = _table(["SHA-256", "Size", "Path"])

        self.combo_old, self.combo_new = QComboBox(), QComboBox()
        btn_cmp = QPushButton("Compare")
        btn_cmp.clicked.connect(self.run_compare)
        crow = QHBoxLayout()
        for w in (QLabel("Old:"), self.combo_old, QLabel("New:"), self.combo_new, btn_cmp):
            crow.addWidget(w)
        crow.addStretch()
        self.cmp_table = _table(["Change", "Path", "Old SHA-256", "New SHA-256"])
        cmp_page = QWidget()
        cl = QVBoxLayout(cmp_page)
        cl.addLayout(crow)
        cl.addWidget(self.cmp_table)

        self.tabs = QTabWidget()
        self.tabs.addTab(self.files, "Files")
        self.tabs.addTab(self.dups, "Duplicates")
        self.tabs.addTab(cmp_page, "Compare")

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.hide()
        self.status = QLabel("Ready. Scanning is read-only.")

        central = QWidget()
        lay = QVBoxLayout(central)
        lay.addLayout(bar)
        lay.addWidget(self.snapshots)
        lay.addWidget(self.tabs, 1)
        lay.addWidget(self.progress)
        lay.addWidget(self.status)
        self.setCentralWidget(central)
        self.reload_snapshots()

    def reload_snapshots(self, select_id: int | None = None) -> None:
        infos = self.vault.list_snapshots()
        _fill(
            self.snapshots,
            [[s.id, s.created_at, s.file_count, s.error_count, s.root] for s in infos],
        )
        for combo in (self.combo_old, self.combo_new):
            combo.clear()
            for s in infos:
                combo.addItem(f"#{s.id} {s.root}", s.id)
        if infos:
            self.combo_new.setCurrentIndex(len(infos) - 1)
        for r, s in enumerate(infos):
            if s.id == select_id:
                self.snapshots.selectRow(r)
        self.refresh_views()

    def selected_id(self) -> int | None:
        rows = self.snapshots.selectionModel().selectedRows()
        return int(self.snapshots.item(rows[0].row(), 0).text()) if rows else None

    def refresh_views(self) -> None:
        sid = self.selected_id()
        if sid is None:
            _fill(self.files, [])
            _fill(self.dups, [])
            return
        entries = self.vault.entries(sid)
        _fill(self.files, [[e.rel_path, e.size, e.status, e.sha256, e.error] for e in entries])
        groups = find_duplicates(entries)
        _fill(self.dups, [[h, e.size, e.rel_path] for h, g in groups.items() for e in g])

    def delete_snapshot(self) -> None:
        sid = self.selected_id()
        if sid is None:
            return
        ok = QMessageBox.question(
            self,
            "Delete snapshot",
            f"Delete snapshot #{sid} from the Hash Vault database?\nScanned files are not touched.",
        )
        if ok == QMessageBox.Yes:
            self.vault.delete_snapshot(sid)
            self.reload_snapshots()

    def choose_and_scan(self) -> None:
        root = QFileDialog.getExistingDirectory(self, "Select directory to scan")
        if root:
            self.start_scan(root)

    def start_scan(self, root: str, confirm: bool = True) -> bool:
        if self._thread is not None:
            return False
        if confirm:
            self.status.setText("Estimating size…")
            QApplication.processEvents()
            est = scanner.estimate(root)
            if est.is_large:
                ok = QMessageBox.warning(
                    self,
                    "Large directory",
                    f"{root}\n\nThis looks large ({est.describe()}).\n"
                    "Hashing reads every file and may take a long time and heavy disk I/O. "
                    "Files are never modified.\n\nScan anyway?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No,
                )
                if ok != QMessageBox.Yes:
                    self.status.setText("Scan declined.")
                    return False
        self._worker = ScanWorker(self.db_path, root)
        self._thread = QThread()
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(self.on_progress)
        self._worker.finished.connect(self.on_finished)
        self._worker.failed.connect(self.on_failed)
        self._worker.cancelled.connect(self.on_cancelled)
        self.btn_scan.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.progress.show()
        self._thread.start()
        return True

    def cancel_scan(self) -> None:
        if self._worker:
            self._worker.cancel_event.set()
            self.status.setText("Cancelling…")

    def on_progress(self, n: int, path: str) -> None:
        self.status.setText(f"{n} files — {path}")

    def _end_scan(self) -> None:
        if self._thread:
            self._thread.quit()
            self._thread.wait()
        self._thread = self._worker = None
        self.btn_scan.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.progress.hide()

    def on_finished(self, snap: int) -> None:
        self._end_scan()
        self.status.setText(f"Snapshot #{snap} saved.")
        self.reload_snapshots(select_id=snap)

    def on_failed(self, msg: str) -> None:
        self._end_scan()
        self.status.setText("Scan failed.")
        QMessageBox.critical(self, "Scan failed", msg)

    def on_cancelled(self) -> None:
        self._end_scan()
        self.status.setText("Scan cancelled; partial snapshot discarded.")

    def run_compare(self) -> None:
        old, new = self.combo_old.currentData(), self.combo_new.currentData()
        if old is None or new is None:
            return
        self._cmp = compare(self.vault.entries(old), self.vault.entries(new))
        rows = []
        for cat in ("added", "removed", "modified", "unverifiable"):
            for c in getattr(self._cmp, cat):
                rows.append(
                    [cat, c.rel_path, c.old.sha256 if c.old else "", c.new.sha256 if c.new else ""]
                )
        _fill(self.cmp_table, rows)
        c = self._cmp
        self.status.setText(
            f"added {len(c.added)}, removed {len(c.removed)}, modified {len(c.modified)}, "
            f"unchanged {len(c.unchanged)}, unverifiable {len(c.unverifiable)}"
        )

    def export_current(self) -> None:
        tab = self.tabs.currentIndex()
        sid = self.selected_id()
        if tab == 2 and self._cmp is None:
            QMessageBox.information(self, "Export", "Run a comparison first.")
            return
        if tab != 2 and sid is None:
            QMessageBox.information(self, "Export", "Select a snapshot first.")
            return
        path, flt = QFileDialog.getSaveFileName(self, "Export", "", "CSV (*.csv);;JSON (*.json)")
        if not path:
            return
        fmt = "json" if path.lower().endswith(".json") or "JSON" in flt else "csv"
        try:
            if tab == 2:
                export_comparison(self._cmp, path, fmt)
            elif tab == 1:
                export_duplicates(find_duplicates(self.vault.entries(sid)), path, fmt)
            else:
                export_entries(self.vault.entries(sid), path, fmt)
            self.status.setText(f"Exported to {path}")
        except OSError as exc:
            QMessageBox.critical(self, "Export failed", str(exc))

    def closeEvent(self, event) -> None:
        if self._worker:
            self._worker.cancel_event.set()
        if self._thread:
            self._thread.quit()
            self._thread.wait(5000)
        self.vault.close()
        super().closeEvent(event)


def run(db_path: str, argv: list[str] | None = None, quit_after_ms: int | None = None) -> int:
    app = QApplication.instance() or QApplication(argv if argv is not None else sys.argv)
    win = MainWindow(db_path)
    win.show()
    if quit_after_ms is not None:
        from PySide6.QtCore import QTimer

        QTimer.singleShot(quit_after_ms, app.quit)
    return app.exec()
