"""Member exchange dialog rendering for the existing ContainerAudit owner.

The owner admits work and executes commands; these functions keep its Tk widgets
and presentation session on the same UI thread.
"""
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional

from product_exchange import ProductExchangeSession
from transfer_member_exchange import MemberExchangeAttempt


EXCHANGE_DIALOG_DEFAULT_WIDTH = 800
EXCHANGE_DIALOG_DEFAULT_HEIGHT = 600
EXCHANGE_DIALOG_SCREEN_MARGIN = 48


def calculate_exchange_dialog_size(
    required_width: int,
    required_height: int,
    screen_width: int,
    screen_height: int,
) -> tuple[int, int]:
    """Fit the exchange dialog's natural size within the current screen."""

    available_width = max(1, int(screen_width) - (EXCHANGE_DIALOG_SCREEN_MARGIN * 2))
    available_height = max(1, int(screen_height) - (EXCHANGE_DIALOG_SCREEN_MARGIN * 2))
    width = max(EXCHANGE_DIALOG_DEFAULT_WIDTH, int(required_width))
    height = max(EXCHANGE_DIALOG_DEFAULT_HEIGHT, int(required_height))
    return min(width, available_width), min(height, available_height)


def show_exchange_dialog(self) -> None:
    if self._transfer_member_exchange_blocks_local_action("다음 스캔"):
        return
    exact_mode = self._exact_transfer_exchange_blocked()
    active_tray = bool(self.current_tray.master_label_code)
    active_transfer_exchange = bool(
        exact_mode and active_tray and self.current_tray.scanned_barcodes
    )
    if exact_mode and not active_transfer_exchange:
        if active_tray:
            messagebox.showwarning(
                "교체 대상 없음",
                "현재 이적 트레이에 제품을 한 개 이상 스캔한 뒤 교체를 시작하세요.",
            )
            return
        if self._block_unsafe_exact_exchange():
            return
    if active_tray and not active_transfer_exchange:
        messagebox.showwarning(
            "작업 중",
            "진행 중인 트레이 작업이 있습니다.\n"
            "현재 작업 방식에서는 제품 교체를 진행할 수 없습니다. 관리자에게 문의하세요.",
        )
        return
    self._invalidate_pending_scan_callbacks()
    existing_dialog = getattr(self, "exchange_dialog", None)
    if existing_dialog is not None:
        try:
            if existing_dialog.winfo_exists():
                existing_dialog.lift()
                existing_dialog.focus_force()
                self._update_action_button_states()
                return
        except tk.TclError:
            pass
        self.exchange_dialog = None

    # 교환 다이얼로그 창 생성
    exchange_dialog = tk.Toplevel(self.root)
    exchange_dialog.title(
        "현재 이적 제품 교체" if active_transfer_exchange else "개별 제품 교환"
    )
    exchange_dialog.geometry(
        f"{EXCHANGE_DIALOG_DEFAULT_WIDTH}x{EXCHANGE_DIALOG_DEFAULT_HEIGHT}"
    )
    exchange_dialog.transient(self.root)
    exchange_dialog.grab_set()

    # 메인 프레임
    main_frame = ttk.Frame(exchange_dialog, padding=20)
    main_frame.pack(fill=tk.BOTH, expand=True)
    main_frame.grid_columnconfigure(0, weight=1)
    main_frame.grid_rowconfigure(0, weight=1)
    body_host = ttk.Frame(main_frame)
    body_host.grid(row=0, column=0, sticky='nsew', pady=(0, 20))
    body = self._large_text_pane(body_host, force=True)
    body.grid_columnconfigure(0, weight=1)
    self.exchange_body = body

    # 제목
    title_label = ttk.Label(
        body,
        text="현재 이적 제품 교체" if active_transfer_exchange else "개별 제품 교환",
                           font=(self.DEFAULT_FONT, 16, 'bold'))
    title_label.grid(row=0, column=0, pady=(0, 20))

    # 수량 선택 프레임
    quantity_frame = ttk.Frame(body)
    quantity_frame.grid(row=1, column=0, sticky='ew', pady=(0, 20))

    ttk.Label(quantity_frame, text="교환할 수량:",
             font=(self.DEFAULT_FONT, 12, 'bold')).pack(side=tk.LEFT)

    self.exchange_quantity_var = tk.IntVar(value=1)
    max_quantity = min(
        2,
        len(self.current_tray.scanned_barcodes)
        if active_transfer_exchange
        else 2,
    )
    quantity_spin = ttk.Spinbox(quantity_frame, from_=1, to=max_quantity,
                               textvariable=self.exchange_quantity_var, width=5,
                               font=(self.DEFAULT_FONT, 12))
    self.exchange_quantity_spin = quantity_spin
    quantity_spin.pack(side=tk.LEFT, padx=(10, 5))

    ttk.Label(quantity_frame, text="개",
             font=(self.DEFAULT_FONT, 12)).pack(side=tk.LEFT)

    # 상태 라벨
    self.exchange_status_label = ttk.Label(body,
                                         text="교환할 수량을 선택한 후 불량품을 스캔하세요.",
                                         font=(self.DEFAULT_FONT, 12))
    self.exchange_status_label.grid(row=2, column=0, sticky='ew', pady=10)
    self._bind_label_to_container_width(self.exchange_status_label, body, padding=40)

    # 목록 프레임
    list_frame = ttk.Frame(body)
    list_frame.grid(row=3, column=0, sticky='nsew', pady=(0, 20))
    list_frame.grid_columnconfigure(0, weight=1, uniform='exchange_tables')
    list_frame.grid_columnconfigure(1, weight=1, uniform='exchange_tables')
    list_frame.grid_rowconfigure(0, weight=1)

    # 불량품 목록
    defective_frame = ttk.LabelFrame(list_frame, text="스캔된 불량품", padding=10)
    defective_frame.grid(row=0, column=0, sticky='nsew', padx=(0, 5))

    self.exchange_defective_tree = ttk.Treeview(defective_frame, columns=('no', 'barcode'), show='headings', height=2)
    self.exchange_defective_tree.heading('no', text='순번')
    self.exchange_defective_tree.heading('barcode', text='불량품 바코드')
    self.exchange_defective_tree.column('no', width=50, anchor='center')
    self.exchange_defective_tree.column('barcode', anchor='w')
    self._apply_tree_row_styles(self.exchange_defective_tree)

    # 양품 목록
    good_frame = ttk.LabelFrame(list_frame, text="스캔된 양품", padding=10)
    good_frame.grid(row=0, column=1, sticky='nsew', padx=(5, 0))

    self.exchange_good_tree = ttk.Treeview(good_frame, columns=('no', 'barcode'), show='headings', height=2)
    self.exchange_good_tree.heading('no', text='순번')
    self.exchange_good_tree.heading('barcode', text='양품 바코드')
    self.exchange_good_tree.column('no', width=50, anchor='center')
    self.exchange_good_tree.column('barcode', anchor='w')
    self._apply_tree_row_styles(self.exchange_good_tree)
    for frame, tree in ((defective_frame, self.exchange_defective_tree), (good_frame, self.exchange_good_tree)):
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(0, weight=1)
        for column in ('no', 'barcode'):
            minimum = self._tree_column_required_width(tree, column, tree.heading(column, 'text'), fallback=50)
            tree.column(column, width=minimum, minwidth=minimum, stretch=column == 'barcode')
        tree.grid(row=0, column=0, sticky='nsew')
        vertical = ttk.Scrollbar(frame, orient='vertical', command=tree.yview)
        vertical.grid(row=0, column=1, sticky='ns')
        tree.configure(yscrollcommand=vertical.set)
        horizontal = ttk.Scrollbar(frame, orient='horizontal', command=tree.xview)
        horizontal.grid(row=1, column=0, sticky='ew')
        tree.configure(xscrollcommand=horizontal.set)
        tree.update_idletasks()
        row_height = max(1, int(self.style.lookup(tree.cget('style') or 'Treeview', 'rowheight') or 20))
        heading_and_border = max(0, tree.winfo_reqheight() - 2 * row_height)
        frame.grid_rowconfigure(0, minsize=heading_and_border + 2 * row_height)
        frame.grid_rowconfigure(1, minsize=horizontal.winfo_reqheight())
    list_frame.update_idletasks()
    body.grid_rowconfigure(3, minsize=max(defective_frame.winfo_reqheight(), good_frame.winfo_reqheight()) + 20)

    # 스캔 입력 프레임
    scan_frame = ttk.Frame(main_frame)
    scan_frame.grid(row=1, column=0, sticky='ew', pady=(0, 20))

    ttk.Label(scan_frame, text="바코드 스캔:",
             font=(self.DEFAULT_FONT, 12, 'bold')).pack(side=tk.LEFT)

    self.exchange_scan_entry = ttk.Entry(scan_frame, font=(self.DEFAULT_FONT, 14), width=30)
    self.exchange_scan_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 0))
    self.exchange_scan_entry.bind('<Return>', self._on_exchange_scan)

    # 버튼 프레임
    button_frame = ttk.Frame(main_frame)
    button_frame.grid(row=2, column=0, sticky='ew')

    self.exchange_complete_button = ttk.Button(button_frame, text="교환 완료",
                                              command=self._complete_exchange,
                                              state=tk.DISABLED,
                                              style='Success.TButton')
    self.exchange_complete_button.pack(side=tk.LEFT, padx=(0, 10))

    self.exchange_cancel_button = ttk.Button(button_frame, text="취소",
                                           command=self._cancel_exchange,
                                           style='Secondary.TButton')
    self.exchange_cancel_button.pack(side=tk.LEFT, padx=(0, 10))

    # 교환 세션 초기화
    self.current_exchange_session = ProductExchangeSession()
    if active_transfer_exchange:
        self.current_exchange_session.item_code = self.current_tray.item_code
        self.current_exchange_session.item_name = self.current_tray.item_name
        self.current_exchange_session.item_spec = self.current_tray.item_spec
    self._active_transfer_exchange_mode = active_transfer_exchange
    self._active_transfer_exchange_master_label = (
        self.current_tray.master_label_code if active_transfer_exchange else ""
    )
    self._active_transfer_exchange_intent_id = ""
    self.exchange_dialog = exchange_dialog
    self._update_action_button_states()
    exchange_dialog.protocol("WM_DELETE_WINDOW", self._cancel_exchange)

    # Windows display scaling can make the natural content taller than the
    # old fixed 800x600 client area.  Size after layout so the scan input
    # and action buttons remain visible without changing exchange logic.
    exchange_dialog.update_idletasks()
    body._layout_viewport.configure(height=body.winfo_reqheight())
    exchange_dialog.update_idletasks()
    dialog_width, dialog_height = calculate_exchange_dialog_size(
        exchange_dialog.winfo_reqwidth(),
        exchange_dialog.winfo_reqheight(),
        exchange_dialog.winfo_screenwidth(),
        exchange_dialog.winfo_screenheight(),
    )
    exchange_dialog.geometry(f"{dialog_width}x{dialog_height}")
    exchange_dialog.minsize(dialog_width, dialog_height)

    # 스캔 엔트리에 포커스
    self.exchange_scan_entry.focus()



def update_exchange_display(self):
    """교환 목록 디스플레이를 업데이트합니다."""
    session = self.current_exchange_session

    # 불량품 목록 업데이트
    for item in self.exchange_defective_tree.get_children():
        self.exchange_defective_tree.delete(item)

    for i, barcode in enumerate(session.defective_barcodes):
        tag = 'even' if i % 2 == 0 else 'odd'
        self._insert_tree_row(self.exchange_defective_tree, '', 'end', values=(i+1, barcode), tags=(tag,))

    # 양품 목록 업데이트
    for item in self.exchange_good_tree.get_children():
        self.exchange_good_tree.delete(item)

    for i, barcode in enumerate(session.good_barcodes):
        tag = 'even' if i % 2 == 0 else 'odd'
        self._insert_tree_row(self.exchange_good_tree, '', 'end', values=(i+1, barcode), tags=(tag,))
    for tree in (self.exchange_defective_tree, self.exchange_good_tree):
        rows = tree.get_children()
        if rows and hasattr(tree, 'see'):
            width = self._tree_column_required_width(tree, 'barcode', tree.heading('barcode', 'text'), fallback=160)
            tree.column('barcode', width=width, minwidth=width)
            tree.see(rows[-1])
    body = getattr(self, 'exchange_body', None)
    if body is not None and body.winfo_exists():
        self.root.after_idle(body._reveal_widget, self.exchange_good_tree if session.good_barcodes else self.exchange_defective_tree)



def update_exchange_status(self):
    """교환 상태 메시지를 업데이트합니다."""
    session = self.current_exchange_session

    if session.current_step == "scan_defective":
        remaining = session.target_quantity - len(session.defective_barcodes)
        if remaining > 0:
            status = f"불량품을 스캔하세요. (남은 수량: {remaining}개)"
        else:
            status = "불량품 스캔 완료. 이제 양품을 스캔하세요."

    elif session.current_step == "scan_good":
        remaining = session.target_quantity - len(session.good_barcodes)
        if remaining > 0:
            status = f"양품을 스캔하세요. (남은 수량: {remaining}개)"
        else:
            status = "모든 스캔이 완료되었습니다. '교환 완료' 버튼을 클릭하세요."
    else:
        status = "교환할 수량을 선택한 후 불량품을 스캔하세요."

    if session.item_name:
        status = f"품목: {session.item_name} | " + status

    self.exchange_status_label.config(text=status)



def finish_central_exchange_pending(
    self,
    attempt: MemberExchangeAttempt,
) -> None:
    if hasattr(self, "exchange_complete_button"):
        self.exchange_complete_button.config(state=tk.NORMAL)
    title = (
        "중앙 교체 담당자 확인 필요"
        if attempt.status == "OPERATOR_REVIEW"
        else "중앙 교체 응답 대기"
    )
    messagebox.showerror(
        title,
        (
            "중앙 교체 결과를 자동으로 확인할 수 없습니다. "
            "현재 트레이를 유지하고 관리자에게 확인하세요."
            if attempt.status == "OPERATOR_REVIEW"
            else "중앙 교체 결과를 확인 중입니다. "
            "현재 트레이를 유지하고 잠시 후 다시 시도하세요."
        ),
    )



def finish_central_exchange_failure(
    self,
    attempt: Optional[MemberExchangeAttempt],
) -> None:
    if hasattr(self, "exchange_complete_button"):
        self.exchange_complete_button.config(state=tk.NORMAL)
    if attempt is None:
        title = "중앙 교체 차단"
        message = (
            "중앙 교체 준비 정보를 확인하지 못했습니다. "
            "현재 트레이를 유지하고 관리자에게 문의하세요."
        )
    else:
        title = "교체 반영 실패"
        message = (
            "중앙 교체는 완료됐지만 현재 트레이 상태에 반영하지 못했습니다. "
            "창을 닫지 말고 담당자에게 알리세요."
        )
    messagebox.showerror(title, message)



def finish_central_exchange_success(self) -> None:
    session = self.current_exchange_session
    session.current_step = "completed"
    messagebox.showinfo(
        "중앙 교체 완료",
        f"{len(session.exchange_pairs)}개의 제품을 원자적으로 교체했습니다.\n\n"
        f"품목: {session.item_name}\n"
        "교체 제품은 공정 불량 보류 위치로 이동했습니다.",
    )
    dialog = getattr(self, "exchange_dialog", None)
    if dialog is not None:
        try:
            dialog.destroy()
        except tk.TclError:
            pass
    self.exchange_dialog = None
    self.exchange_quantity_spin = None
    self.current_exchange_session = ProductExchangeSession()
    self._active_transfer_exchange_mode = False
    self._active_transfer_exchange_master_label = ""
    self._active_transfer_exchange_intent_id = ""
    self._update_action_button_states()
