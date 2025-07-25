import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import csv
import datetime
import os
import sys
import threading
import time
import json
import re
from typing import List, Dict, Optional, Any
from PIL import Image, ImageTk
from dataclasses import dataclass, field
import queue
import pygame
import uuid
import requests
import zipfile
import subprocess

# ####################################################################
# # 자동 업데이트 기능 (Auto-Updater Functionality)
# ####################################################################
# --- GitHub 저장소 설정 (이 부분을 실제 정보에 맞게 수정하세요) ---
REPO_OWNER = "KMTechn"      # 사용자 GitHub 아이디
REPO_NAME = "Container_Audit"  # GitHub 저장소의 실제 이름
CURRENT_VERSION = "v2.0.0"      # 현품표 로직 개선 후 버전 업데이트

def check_for_updates():
    """GitHub에서 최신 릴리스 정보를 확인하고, 업데이트가 필요하면 .zip 파일의 다운로드 URL을 반환합니다."""
    try:
        api_url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases/latest"
        print(f"업데이트 확인 URL: {api_url}")
        response = requests.get(api_url, timeout=5)
        response.raise_for_status()
        latest_release_data = response.json()
        latest_version = latest_release_data['tag_name']
        print(f"현재 버전: {CURRENT_VERSION}, 최신 버전: {latest_version}")
        if latest_version.strip().lower() > CURRENT_VERSION.strip().lower():
            print("새로운 버전이 있습니다.")
            for asset in latest_release_data['assets']:
                if asset['name'].endswith('.zip'):
                    return asset['browser_download_url'], latest_version
            print("릴리스에 .zip 파일이 없습니다.")
            return None, None
        else:
            print("프로그램이 최신 버전입니다.")
            return None, None
    except requests.exceptions.RequestException as e:
        print(f"업데이트 확인 중 오류 발생 (네트워크 문제일 수 있음): {e}")
        return None, None

def download_and_apply_update(url):
    """업데이트 .zip 파일을 다운로드하고, 압축 해제 후 적용 스크립트를 실행합니다."""
    try:
        zip_path = os.path.join(os.environ.get("TEMP", "C:\\Temp"), "update.zip")
        print(f"'{url}' 에서 새 버전을 다운로드 중...")
        response = requests.get(url, stream=True, timeout=120)
        response.raise_for_status()
        with open(zip_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print("다운로드 완료.")
        temp_update_folder = os.path.join(os.environ.get("TEMP", "C:\\Temp"), "temp_update")
        if os.path.exists(temp_update_folder):
            import shutil
            shutil.rmtree(temp_update_folder)
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_update_folder)
        print(f"'{temp_update_folder}'에 압축 해제 완료.")
        os.remove(zip_path)
        if getattr(sys, 'frozen', False):
            application_path = os.path.dirname(sys.executable)
        else:
            application_path = os.path.dirname(os.path.abspath(__file__))
        updater_script_path = os.path.join(application_path, "updater.bat")
        extracted_content = os.listdir(temp_update_folder)
        if len(extracted_content) == 1 and os.path.isdir(os.path.join(temp_update_folder, extracted_content[0])):
            new_program_folder_path = os.path.join(temp_update_folder, extracted_content[0])
        else:
            new_program_folder_path = temp_update_folder
        with open(updater_script_path, "w", encoding='utf-8') as bat_file:
            bat_file.write(f"""@echo off
chcp 65001 > nul
echo.
echo ==========================================================
echo  프로그램을 업데이트합니다. 이 창을 닫지 마세요.
echo ==========================================================
echo.
echo 잠시 후 프로그램이 자동으로 종료됩니다...
timeout /t 3 /nobreak > nul
taskkill /F /IM "{os.path.basename(sys.executable)}" > nul
echo.
echo 기존 파일을 백업하고 새 파일로 교체합니다...
xcopy "{new_program_folder_path}" "{application_path}" /E /H /C /I /Y > nul
echo.
echo 임시 업데이트 파일을 삭제합니다...
rmdir /s /q "{temp_update_folder}"
echo.
echo ========================================
echo  업데이트 완료!
echo ========================================
echo.
echo 3초 후에 프로그램을 다시 시작합니다.
timeout /t 3 /nobreak > nul
start "" "{os.path.join(application_path, os.path.basename(sys.executable))}"
del "%~f0"
            """)
        print("업데이트 적용을 위해 프로그램을 종료하고 업데이트 스크립트를 실행합니다.")
        subprocess.Popen(updater_script_path, creationflags=subprocess.CREATE_NEW_CONSOLE)
        sys.exit(0)
    except Exception as e:
        print(f"업데이트 적용 중 오류 발생: {e}")
        root_alert = tk.Tk()
        root_alert.withdraw()
        messagebox.showerror("업데이트 실패", f"업데이트 적용 중 오류가 발생했습니다.\n\n{e}\n\n프로그램을 다시 시작해주세요.", parent=root_alert)
        root_alert.destroy()

def check_and_apply_updates():
    """업데이트 확인 및 적용 프로세스를 실행하는 메인 함수"""
    print("업데이트를 확인합니다...")
    download_url, new_version = check_for_updates()
    if download_url:
        root_alert = tk.Tk()
        root_alert.withdraw()
        if messagebox.askyesno("업데이트 발견", f"새로운 버전({new_version})이 발견되었습니다.\n지금 업데이트하시겠습니까? (현재: {CURRENT_VERSION})", parent=root_alert):
            root_alert.destroy()
            download_and_apply_update(download_url)
        else:
            print("사용자가 업데이트를 거부했습니다.")
            root_alert.destroy()

# ####################################################################
# # 메인 어플리케이션
# ####################################################################
@dataclass
class TraySession:
    master_label_code: str = ""
    item_code: str = ""
    item_name: str = ""
    item_spec: str = ""
    scanned_barcodes: List[str] = field(default_factory=list)
    scan_times: List[datetime.datetime] = field(default_factory=list)
    tray_size: int = 60  # 트레이 목표 수량 (기본값 60)
    mismatch_error_count: int = 0
    total_idle_seconds: float = 0.0
    stopwatch_seconds: float = 0.0
    start_time: Optional[datetime.datetime] = None
    has_error_or_reset: bool = False
    is_test_tray: bool = False
    is_partial_submission: bool = False
    is_restored_session: bool = False # 이어하기 여부 플래그

def resource_path(relative_path: str) -> str:
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)

class BarcodeValidator:
    APP_TITLE = f"바코드 검증 시스템 ({CURRENT_VERSION})"
    DEFAULT_FONT = 'Malgun Gothic'
    TRAY_SIZE = 60 # 기본 트레이 사이즈
    SETTINGS_DIR = 'config'
    PARKED_TRAY_DIR = os.path.join(SETTINGS_DIR, 'parked_trays') # 보류된 트레이 저장 경로
    SETTINGS_FILE = 'validator_settings.json'
    IDLE_THRESHOLD_SEC = 420
    TEST_LOG_GENERATION = "TEST_GENERATE_LOG"
    TEST_UI_FILL_ONLY = "TEST_FILL_UI_ONLY"
    ITEM_CODE_LENGTH = 13
    CURRENT_TRAY_STATE_FILE = "_current_tray_state.json"
    COLOR_BG = "#F5F7FA"
    COLOR_SIDEBAR_BG = "#FFFFFF"
    COLOR_TEXT = "#343A40"
    COLOR_TEXT_SUBTLE = "#6C757D"
    COLOR_PRIMARY = "#0D6EFD"
    COLOR_SUCCESS = "#28A745"
    COLOR_DANGER = "#DC3545"
    COLOR_IDLE = "#FFC107"
    COLOR_BORDER = "#CED4DA"
    COLOR_VELVET = "#8A0707"

    def __init__(self):
        self.root = tk.Tk()
        self.root.title(self.APP_TITLE)
        self.root.state('zoomed')
        self.root.configure(bg=self.COLOR_BG)
        try:
            self.root.iconbitmap(resource_path(os.path.join('assets', 'logo.ico')))
        except Exception as e:
            print(f"아이콘 로드 실패: {e}")
        pygame.init()
        pygame.mixer.init()
        try:
            self.success_sound = pygame.mixer.Sound(resource_path('assets/success.wav'))
            self.error_sound = pygame.mixer.Sound(resource_path('assets/error.wav'))
        except pygame.error as e:
            messagebox.showwarning("사운드 파일 오류", f"사운드 파일을 로드할 수 없습니다.\n'assets' 폴더에 success.wav, error.wav 파일이 있는지 확인하세요.\n오류: {e}")
            self.success_sound = None
            self.error_sound = None
        if getattr(sys, 'frozen', False): self.application_path = os.path.dirname(sys.executable)
        else: self.application_path = os.path.dirname(os.path.abspath(__file__))
        
        self._setup_paths_and_dirs()

        self.settings = self.load_app_settings()
        self.scale_factor = self.settings.get('scale_factor', 1.0)
        self.paned_window_sash_positions: Dict[str, int] = self.settings.get('paned_window_sash_positions', {})
        self.column_widths: Dict[str, int] = self.settings.get('column_widths_validator', {})
        self.worker_name = ""
        self.completed_master_labels: set = set() # 완료된 '고유' 현품표 추적용
        self.current_tray = TraySession()
        self.items_data = self.load_items()
        self.work_summary: Dict[str, Dict[str, Any]] = {}
        self.completed_tray_times: List[float] = []
        self.total_tray_count = 0
        self.tray_last_end_time: Optional[datetime.datetime] = None
        self.info_cards: Dict[str, Dict[str, ttk.Widget]] = {}
        self.logo_photo_ref = None
        self.is_idle = False
        self.last_activity_time: Optional[datetime.datetime] = None
        self.show_tray_image_var = tk.BooleanVar(value=False)
        self.status_message_job: Optional[str] = None
        self.clock_job: Optional[str] = None
        self.stopwatch_job: Optional[str] = None
        self.idle_check_job: Optional[str] = None
        self.focus_return_job: Optional[str] = None
        self.log_queue: queue.Queue = queue.Queue()
        self.log_file_path: Optional[str] = None
        self.log_thread = threading.Thread(target=self._event_log_writer, daemon=True)
        self.log_thread.start()
        try:
            self.computer_id = hex(uuid.getnode())
        except Exception:
            import socket
            self.computer_id = socket.gethostname()
        self.CURRENT_TRAY_STATE_FILE = f"_current_tray_state_{self.computer_id}.json"
        self._setup_core_ui_structure()
        self._setup_styles()
        self.show_worker_input_screen()
        self.root.bind('<Control-MouseWheel>', self.on_ctrl_wheel)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def _setup_paths_and_dirs(self):
        """애플리케이션에서 사용하는 주요 경로와 디렉터리를 설정하고 생성합니다."""
        self.save_folder = "C:\\Sync"
        self.config_folder = os.path.join(self.application_path, self.SETTINGS_DIR)
        self.parked_trays_dir = os.path.join(self.application_path, self.PARKED_TRAY_DIR)
        os.makedirs(self.save_folder, exist_ok=True)
        os.makedirs(self.config_folder, exist_ok=True)
        os.makedirs(self.parked_trays_dir, exist_ok=True)

    def load_app_settings(self) -> Dict[str, Any]:
        path = os.path.join(self.config_folder, self.SETTINGS_FILE)
        try:
            with open(path, 'r', encoding='utf-8') as f: return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def save_settings(self):
        try:
            path = os.path.join(self.config_folder, self.SETTINGS_FILE)
            current_settings = {
                'scale_factor': self.scale_factor,
                'column_widths_validator': self.column_widths,
                'paned_window_sash_positions': self.paned_window_sash_positions,
            }
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(current_settings, f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(f"설정 저장 오류: {e}")

    def load_items(self) -> List[Dict[str, str]]:
        item_path = resource_path(os.path.join('assets', 'Item.csv'))
        encodings_to_try = ['utf-8-sig', 'cp949', 'euc-kr', 'utf-8']
        for encoding in encodings_to_try:
            try:
                with open(item_path, 'r', encoding=encoding) as file:
                    items = list(csv.DictReader(file))
                    print(f"'{os.path.basename(item_path)}' 파일을 '{encoding}' 인코딩으로 여는 데 성공했습니다.")
                    return items
            except UnicodeDecodeError:
                print(f"'{encoding}' 인코딩으로 파일 열기 실패. 다음 인코딩을 시도합니다...")
                continue
            except FileNotFoundError:
                messagebox.showerror("오류", f"필수 파일 없음: {item_path}\n'assets' 폴더에 Item.csv가 있는지 확인하세요.")
                self.root.destroy()
                return []
            except Exception as e:
                messagebox.showerror("파일 읽기 오류", f"'{item_path}' 파일을 읽는 중 예상치 못한 오류가 발생했습니다:\n{e}")
                self.root.destroy()
                return []
        messagebox.showerror("인코딩 감지 실패", f"'{os.path.basename(item_path)}' 파일의 인코딩 형식을 알 수 없습니다.\n\n파일을 Excel 등에서 'CSV UTF-8' 또는 일반 'CSV' 형식으로 저장했는지 확인해주세요.\n\n(시도한 인코딩: {', '.join(encodings_to_try)})")
        self.root.destroy()
        return []

    def _setup_core_ui_structure(self):
        status_bar = tk.Frame(self.root, bg=self.COLOR_SIDEBAR_BG, bd=1, relief=tk.SUNKEN)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_label = tk.Label(status_bar, text="준비", anchor=tk.W, bg=self.COLOR_SIDEBAR_BG, fg=self.COLOR_TEXT)
        self.status_label.pack(side=tk.LEFT, padx=10, pady=4)
        self.paned_window = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        self.left_pane = ttk.Frame(self.paned_window, style='Sidebar.TFrame')
        self.center_pane = ttk.Frame(self.paned_window, style='TFrame')
        self.right_pane = ttk.Frame(self.paned_window, style='Sidebar.TFrame')
        self.paned_window.add(self.left_pane, weight=1)
        self.paned_window.add(self.center_pane, weight=3)
        self.paned_window.add(self.right_pane, weight=1)
        self.worker_input_frame = ttk.Frame(self.root, style='TFrame')

    def _setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.apply_scaling()

    def apply_scaling(self):
        base=10; s,m,l,xl,xxl = (int(factor*self.scale_factor) for factor in [base,base+2,base+8,base+20,base+60])
        self.style.configure('TFrame', background=self.COLOR_BG)
        self.style.configure('Sidebar.TFrame', background=self.COLOR_SIDEBAR_BG)
        self.style.configure('Card.TFrame', background=self.COLOR_SIDEBAR_BG, relief='solid', borderwidth=1, bordercolor=self.COLOR_BORDER)
        self.style.configure('Idle.TFrame', background=self.COLOR_IDLE, relief='solid', borderwidth=1, bordercolor=self.COLOR_BORDER)
        self.style.configure('TLabel', background=self.COLOR_BG, foreground=self.COLOR_TEXT, font=(self.DEFAULT_FONT, m))
        self.style.configure('Sidebar.TLabel', background=self.COLOR_SIDEBAR_BG, foreground=self.COLOR_TEXT, font=(self.DEFAULT_FONT, m))
        self.style.configure('Idle.TLabel', background=self.COLOR_IDLE, foreground=self.COLOR_TEXT, font=(self.DEFAULT_FONT, m))
        self.style.configure('Subtle.TLabel', background=self.COLOR_SIDEBAR_BG, foreground=self.COLOR_TEXT_SUBTLE, font=(self.DEFAULT_FONT, s))
        self.style.configure('Idle.Subtle.TLabel', background=self.COLOR_IDLE, foreground=self.COLOR_TEXT_SUBTLE, font=(self.DEFAULT_FONT, s))
        self.style.configure('Value.TLabel', background=self.COLOR_SIDEBAR_BG, foreground=self.COLOR_TEXT, font=(self.DEFAULT_FONT, int(l * 1.2), 'bold'))
        self.style.configure('Idle.Value.TLabel', background=self.COLOR_IDLE, foreground=self.COLOR_TEXT, font=(self.DEFAULT_FONT, int(l * 1.2), 'bold'))
        self.style.configure('Title.TLabel', background=self.COLOR_BG, foreground=self.COLOR_TEXT, font=(self.DEFAULT_FONT, int(xl * 1.5), 'bold'))
        self.style.configure('ItemInfo.TLabel', background=self.COLOR_BG, foreground=self.COLOR_TEXT, font=(self.DEFAULT_FONT, l, 'bold'))
        self.style.configure('MainCounter.TLabel', background=self.COLOR_BG, foreground=self.COLOR_TEXT, font=(self.DEFAULT_FONT, xxl, 'bold'))
        self.style.configure('TButton', font=(self.DEFAULT_FONT, m, 'bold'), padding=(int(15*self.scale_factor), int(10*self.scale_factor)), borderwidth=0)
        self.style.map('TButton', background=[('!active', self.COLOR_PRIMARY), ('active', '#0B5ED7')], foreground=[('!active', 'white')])
        self.style.configure('Corner.TButton', font=(self.DEFAULT_FONT, l, 'bold'), borderwidth=0, padding=(5, 5))
        self.style.map('Corner.TButton', background=[('!active', self.COLOR_BG), ('active', self.COLOR_BORDER)], foreground=[('!active', self.COLOR_TEXT_SUBTLE), ('active', self.COLOR_TEXT)])
        self.style.configure('Secondary.TButton', font=(self.DEFAULT_FONT, s, 'bold'), borderwidth=0)
        self.style.map('Secondary.TButton', background=[('!active', self.COLOR_TEXT_SUBTLE), ('active', self.COLOR_TEXT)], foreground=[('!active', 'white')])
        self.style.configure('TCheckbutton', background=self.COLOR_SIDEBAR_BG, foreground=self.COLOR_TEXT, font=(self.DEFAULT_FONT, m))
        self.style.map('TCheckbutton', indicatorcolor=[('selected', self.COLOR_PRIMARY), ('!selected', self.COLOR_BORDER)])
        self.style.configure('VelvetCard.TFrame', background=self.COLOR_VELVET, relief='solid', borderwidth=1, bordercolor=self.COLOR_BORDER)
        self.style.configure('Velvet.Subtle.TLabel', background=self.COLOR_VELVET, foreground='white', font=(self.DEFAULT_FONT, s))
        self.style.configure('Velvet.Value.TLabel', background=self.COLOR_VELVET, foreground='white', font=(self.DEFAULT_FONT, int(l * 1.2), 'bold'))
        self.style.configure('Treeview.Heading', font=(self.DEFAULT_FONT, m, 'bold'))
        self.style.configure('Treeview', rowheight=int(25 * self.scale_factor), font=(self.DEFAULT_FONT, m))
        self.style.configure('Big.Horizontal.TProgressbar', troughcolor=self.COLOR_BORDER, background=self.COLOR_PRIMARY, thickness=int(25 * self.scale_factor))
        if hasattr(self, 'status_label'): self.status_label['font'] = (self.DEFAULT_FONT, s)

    def on_ctrl_wheel(self, event):
        self.scale_factor += 0.1 if event.delta > 0 else -0.1
        self.scale_factor = max(0.7, min(2.5, self.scale_factor))
        self.apply_scaling()
        if self.worker_name:
            self.show_validation_screen()
        else:
            self.show_worker_input_screen()

    def _clear_main_frames(self):
        if self.worker_input_frame.winfo_ismapped(): self.worker_input_frame.pack_forget()
        if self.paned_window.winfo_ismapped(): self.paned_window.pack_forget()

    def show_worker_input_screen(self):
        self._clear_main_frames()
        self.worker_input_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        for widget in self.worker_input_frame.winfo_children(): widget.destroy()
        self.worker_input_frame.grid_rowconfigure(0, weight=1)
        self.worker_input_frame.grid_columnconfigure(0, weight=1)
        center_frame = ttk.Frame(self.worker_input_frame, style='TFrame')
        center_frame.grid(row=0, column=0)
        try:
            logo_path = resource_path(os.path.join('assets', 'logo.png'))
            logo_img = Image.open(logo_path)
            max_width = 400 * self.scale_factor
            logo_img_resized = logo_img.resize((int(max_width), int(max_width * (logo_img.height / logo_img.width))), Image.Resampling.LANCZOS)
            self.logo_photo_ref = ImageTk.PhotoImage(logo_img_resized)
            ttk.Label(center_frame, image=self.logo_photo_ref, style='TLabel').pack(pady=(40, 20))
        except Exception as e:
            print(f"로고 로드 실패: {e}")
        ttk.Label(center_frame, text=self.APP_TITLE, style='Title.TLabel').pack(pady=(20, 60))
        ttk.Label(center_frame, text="작업자 이름", style='TLabel', font=(self.DEFAULT_FONT, int(12*self.scale_factor))).pack(pady=(10, 5))
        self.worker_entry = tk.Entry(center_frame, width=25, font=(self.DEFAULT_FONT, int(18*self.scale_factor), 'bold'), bd=2, relief=tk.SOLID, justify='center', highlightbackground=self.COLOR_BORDER, highlightcolor=self.COLOR_PRIMARY, highlightthickness=2)
        self.worker_entry.pack(ipady=int(12*self.scale_factor))
        self.worker_entry.bind('<Return>', self.start_work)
        self.worker_entry.focus()
        button_container = ttk.Frame(center_frame, style='TFrame')
        button_container.pack(pady=60)
        ttk.Button(button_container, text="작업 시작", command=self.start_work, style='TButton', width=20).pack(side=tk.LEFT, padx=10, ipady=int(10*self.scale_factor))

    def start_work(self, event=None):
        worker_name = self.worker_entry.get().strip()
        if not worker_name:
            messagebox.showerror("오류", "작업자 이름을 입력해주세요.")
            return
        self.worker_name = worker_name
        self._load_session_state()
        self._log_event('WORK_START', detail={'message': f"작업자 '{worker_name}'이(가) 작업을 시작했습니다."})
        self._load_current_tray_state()
        if not self.root.winfo_exists(): return
        if not self.paned_window.winfo_ismapped():
            self.show_validation_screen()

    def change_worker(self):
        msg = "작업자를 변경하시겠습니까?"
        if self.current_tray.master_label_code:
            msg += "\n\n진행 중인 작업은 다음 로그인 시 복구할 수 있도록 저장됩니다."
        if messagebox.askyesno("작업자 변경", msg):
            if self.current_tray.master_label_code:
                self._save_current_tray_state()
                self._log_event('WORK_PAUSE', detail={'message': f"Worker '{self.worker_name}' changed."})
            self._cancel_all_jobs()
            self.worker_name = ""
            self.show_worker_input_screen()

    def _load_session_state(self):
        today = datetime.date.today()
        sanitized_name = re.sub(r'[\\/*?:"<>|]', "", self.worker_name)
        self.log_file_path = os.path.join(self.save_folder, f"이적작업이벤트로그_{sanitized_name}_{today.strftime('%Y%m%d')}.csv")
        self.total_tray_count = 0
        self.completed_tray_times = []
        self.completed_master_labels.clear()
        self.work_summary = {}
        self.tray_last_end_time = None
        lookback_days = 7
        lookback_start_date = today - datetime.timedelta(days=lookback_days)
        log_file_pattern = re.compile(f"이적작업이벤트로그_{re.escape(sanitized_name)}_(\\d{{8}})\\.csv")
        all_log_files = []
        try:
            for filename in os.listdir(self.save_folder):
                match = log_file_pattern.match(filename)
                if match:
                    date_part = match.group(1)
                    try:
                        file_date = datetime.datetime.strptime(date_part, '%Y%m%d').date()
                        if file_date >= lookback_start_date:
                            all_log_files.append(os.path.join(self.save_folder, filename))
                    except ValueError: continue
        except FileNotFoundError: pass
        all_completed_sessions = []
        for log_path in sorted(all_log_files):
            if not os.path.exists(log_path): continue
            try:
                with open(log_path, 'r', encoding='utf-8-sig') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if row.get('event') == 'TRAY_COMPLETE':
                            try:
                                details = json.loads(row['details'])
                                # 고유 ID가 있는 신규 QR 현품표만 완료 목록에 추가
                                master_label = details.get('master_label_code')
                                if master_label and '|' in master_label and '=' in master_label:
                                    self.completed_master_labels.add(master_label)
                                details['timestamp'] = datetime.datetime.fromisoformat(row['timestamp'])
                                all_completed_sessions.append(details)
                            except (json.JSONDecodeError, KeyError):
                                continue
            except Exception as e:
                print(f"로그 파일 '{log_path}' 처리 중 오류: {e}")
        if not all_completed_sessions:
            if any(self.work_summary): self.show_status_message(f"금일 작업 현황을 불러왔습니다.", self.COLOR_PRIMARY)
            return
        today_sessions_list = [s for s in all_completed_sessions if s['timestamp'].date() == today]
        start_of_week = today - datetime.timedelta(days=today.weekday())
        current_week_sessions_list = [s for s in all_completed_sessions if s['timestamp'].date() >= start_of_week]
        for session in today_sessions_list:
            item_code = session.get('item_code', 'UNKNOWN')
            if item_code not in self.work_summary:
                self.work_summary[item_code] = {'name': session.get('item_name', '알 수 없음'), 'spec': session.get('spec', ''), 'count': 0, 'test_count': 0}
            if session.get('is_test_tray', False):
                self.work_summary[item_code]['test_count'] += 1
            else:
                self.work_summary[item_code]['count'] += 1
            if not session.get('is_test_tray', False) and not session.get('is_partial_submission', False):
                self.total_tray_count += 1
        clean_sessions = []
        for s in current_week_sessions_list:
            if (s.get('scan_count') == self.TRAY_SIZE and
                s.get('has_error_or_reset') == False and
                s.get('is_partial_submission') == False and
                s.get('is_restored_session') == False and
                s.get('is_test_tray') == False):
                clean_sessions.append(s)
        if clean_sessions:
            MINIMUM_REALISTIC_TIME_PER_PC = 5.0
            valid_times = []
            for s in clean_sessions:
                work_time = float(s.get('work_time_sec', 0.0))
                if work_time / self.TRAY_SIZE >= MINIMUM_REALISTIC_TIME_PER_PC:
                    valid_times.append(work_time)
            if valid_times:
                self.completed_tray_times = valid_times
        if any(self.work_summary):
            self.show_status_message(f"금일 작업 현황을 불러왔습니다. (총 {self.total_tray_count} 파렛트)", self.COLOR_PRIMARY)

    def _save_current_tray_state(self):
        if not self.current_tray.master_label_code: return
        state_path = os.path.join(self.save_folder, self.CURRENT_TRAY_STATE_FILE)
        try:
            serializable_state = {
                'worker_name': self.worker_name, 'master_label_code': self.current_tray.master_label_code, 'item_code': self.current_tray.item_code, 'item_name': self.current_tray.item_name,
                'item_spec': self.current_tray.item_spec, 'scanned_barcodes': self.current_tray.scanned_barcodes, 'scan_times': [dt.isoformat() for dt in self.current_tray.scan_times],
                'tray_size': self.current_tray.tray_size, 'mismatch_error_count': self.current_tray.mismatch_error_count, 'total_idle_seconds': self.current_tray.total_idle_seconds, 'stopwatch_seconds': self.current_tray.stopwatch_seconds,
                'start_time': self.current_tray.start_time.isoformat() if self.current_tray.start_time else None, 'has_error_or_reset': self.current_tray.has_error_or_reset, 'is_test_tray': self.current_tray.is_test_tray, 'is_partial_submission': self.current_tray.is_partial_submission
            }
            with open(state_path, 'w', encoding='utf-8') as f: json.dump(serializable_state, f, indent=4)
        except Exception as e: print(f"현재 트레이 상태 저장 실패: {e}")

    def _load_current_tray_state(self):
        state_path = os.path.join(self.save_folder, self.CURRENT_TRAY_STATE_FILE)
        if not os.path.exists(state_path): return
        try:
            with open(state_path, 'r', encoding='utf-8') as f: saved_state = json.load(f)
            saved_worker = saved_state.get('worker_name')
            if not saved_worker: self._delete_current_tray_state(); return
            if saved_worker == self.worker_name:
                msg = f"이전에 마치지 못한 트레이 작업을 이어서 시작하시겠습니까?\n\n· 품목: {saved_state.get('item_name', '알 수 없음')}\n· 스캔 수: {len(saved_state.get('scanned_barcodes', []))}개"
                if messagebox.askyesno("이전 작업 복구", msg):
                    self._restore_tray_from_state(saved_state)
                    self._log_event('TRAY_RESTORE', detail={'message': 'Same worker restored their session.'})
                else: self._delete_current_tray_state()
            else:
                msg = f"이전 작업자 '{saved_worker}'님이 마치지 않은 작업이 있습니다.\n\n이 작업을 이어서 진행하시겠습니까?"
                response = messagebox.askyesnocancel("작업 인수 확인", msg)
                if response is True:
                    self._restore_tray_from_state(saved_state)
                    self._log_event('TRAY_TAKEOVER', detail={'previous_worker': saved_worker, 'new_worker': self.worker_name, 'item_name': saved_state.get('item_name')})
                elif response is False:
                    if messagebox.askyesno("작업 삭제", "이전 작업을 영구적으로 삭제하시겠습니까?\n(이 작업은 복구할 수 없습니다.)"):
                        self._delete_current_tray_state()
                        self.show_status_message(f"'{saved_worker}'님의 이전 작업이 삭제되었습니다.", self.COLOR_DANGER)
                    else: self.worker_name = ""; self.show_worker_input_screen()
                else: self.worker_name = ""; self.show_worker_input_screen()
        except Exception as e:
            print(f"현재 트레이 상태 로드 실패: {e}")
            messagebox.showwarning("오류", f"이전 작업 상태 파일을 로드하는데 실패했습니다. ({e})")
            self._delete_current_tray_state()

    def _restore_tray_from_state(self, state: Dict[str, Any]):
        self.current_tray = TraySession(
            master_label_code=state['master_label_code'], item_code=state['item_code'], item_name=state['item_name'], item_spec=state['item_spec'], scanned_barcodes=state['scanned_barcodes'],
            scan_times=[datetime.datetime.fromisoformat(dt) for dt in state['scan_times']], tray_size=state.get('tray_size', self.TRAY_SIZE), mismatch_error_count=state['mismatch_error_count'], total_idle_seconds=state['total_idle_seconds'],
            stopwatch_seconds=state['stopwatch_seconds'], start_time=datetime.datetime.fromisoformat(state['start_time']) if state.get('start_time') else None,
            has_error_or_reset=state.get('has_error_or_reset', False), is_test_tray=state.get('is_test_tray', False), is_partial_submission=state.get('is_partial_submission', False),
            is_restored_session=True # 이어하기 플래그 설정
        )
        self.show_status_message("이전 트레이 작업을 복구했습니다.", self.COLOR_PRIMARY)

    def _delete_current_tray_state(self):
        state_path = os.path.join(self.save_folder, self.CURRENT_TRAY_STATE_FILE)
        if os.path.exists(state_path):
            try: os.remove(state_path)
            except Exception as e: print(f"임시 트레이 상태 파일 삭제 실패: {e}")

    def show_validation_screen(self):
        self._clear_main_frames()
        self.paned_window.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        for pane in [self.left_pane, self.center_pane, self.right_pane]:
            for widget in pane.winfo_children(): widget.destroy()
        self._create_left_sidebar_content(self.left_pane)
        self._create_center_content(self.center_pane)
        self._create_right_sidebar_content(self.right_pane)
        self.root.after(50, self._set_initial_sash_positions)
        self._update_clock()
        self._start_idle_checker()
        self._update_all_summaries()
        self._update_parked_trays_list()
        if self.current_tray.master_label_code:
            self._update_current_item_label()
            for i, barcode in enumerate(reversed(self.current_tray.scanned_barcodes)):
                self.scanned_listbox.insert(0, f"({len(self.current_tray.scanned_barcodes) - i}) {barcode}")
            self._update_center_display()
            self._start_stopwatch(resume=True)
        else:
            self._reset_ui_to_waiting_state()
        self.scan_entry.focus()

    def _set_initial_sash_positions(self):
        self.paned_window.update_idletasks()
        try:
            total_width = self.paned_window.winfo_width()
            if total_width <= 1:
                self.root.after(50, self._set_initial_sash_positions)
                return
            # 비율 조정: 왼쪽 20%, 중앙 60%, 오른쪽 20%
            sash_0_pos = int(total_width * 0.24)
            sash_1_pos = int(total_width * 0.76)
            self.paned_window.sashpos(0, sash_0_pos)
            self.paned_window.sashpos(1, sash_1_pos)
        except tk.TclError as e:
            print(f"Could not set initial sash position (ignorable): {e}")

    def _create_left_sidebar_content(self, parent_frame):
        parent_frame.grid_columnconfigure(0, weight=1)
        parent_frame['padding'] = (10, 10)
        top_frame = ttk.Frame(parent_frame, style='Sidebar.TFrame')
        top_frame.grid(row=0, column=0, sticky='nsew', pady=(0, 10))
        top_frame.grid_columnconfigure(0, weight=1)
        header_frame = ttk.Frame(top_frame, style='Sidebar.TFrame')
        header_frame.grid(row=0, column=0, sticky='ew', pady=(0, 20))
        header_frame.grid_columnconfigure(0, weight=1)
        worker_info_frame = ttk.Frame(header_frame, style='Sidebar.TFrame')
        worker_info_frame.grid(row=0, column=0, sticky='w')
        ttk.Label(worker_info_frame, text=f"작업자: {self.worker_name}", style='Sidebar.TLabel').pack(side=tk.LEFT)
        buttons_frame = ttk.Frame(header_frame, style='Sidebar.TFrame')
        buttons_frame.grid(row=0, column=1, sticky='e')
        ttk.Button(buttons_frame, text="작업자 변경", command=self.change_worker, style='Secondary.TButton').pack(side=tk.LEFT, padx=(0, 5))
        self.summary_title_label = ttk.Label(top_frame, text="누적 작업 현황", style='Subtle.TLabel', font=(self.DEFAULT_FONT, int(14*self.scale_factor),'bold'))
        self.summary_title_label.grid(row=1, column=0, sticky='w', pady=(0,10))
        tree_frame = ttk.Frame(top_frame)
        tree_frame.grid(row=2, column=0, sticky='nsew')
        top_frame.grid_rowconfigure(2, weight=2)
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)
        cols = ('item_name_spec', 'item_code', 'count')
        self.summary_tree = ttk.Treeview(tree_frame, columns=cols, show='headings', style='Treeview')
        self.summary_tree.heading('item_name_spec', text='품목명')
        self.summary_tree.heading('item_code', text='품목코드')
        self.summary_tree.heading('count', text='완료 수량')
        self.summary_tree.column('item_name_spec', anchor='w', stretch=tk.YES)
        self.summary_tree.column('item_code', width=120, anchor='w', stretch=tk.NO)
        self.summary_tree.column('count', width=100, anchor='center', stretch=tk.NO)
        self.summary_tree.grid(row=0, column=0, sticky='nsew')
        sb1 = ttk.Scrollbar(tree_frame, orient='vertical', command=self.summary_tree.yview)
        self.summary_tree['yscrollcommand'] = sb1.set
        sb1.grid(row=0, column=1, sticky='ns')
        self.parked_title_label = ttk.Label(top_frame, text="보류 중인 트레이 (더블클릭으로 복원)", style='Subtle.TLabel', font=(self.DEFAULT_FONT, int(12*self.scale_factor),'bold'))
        self.parked_title_label.grid(row=3, column=0, sticky='w', pady=(20,10))
        parked_tree_frame = ttk.Frame(top_frame)
        parked_tree_frame.grid(row=4, column=0, sticky='nsew')
        top_frame.grid_rowconfigure(4, weight=1)
        parked_tree_frame.grid_columnconfigure(0, weight=1)
        parked_tree_frame.grid_rowconfigure(0, weight=1)
        parked_cols = ('item_name', 'scan_count')
        self.parked_tree = ttk.Treeview(parked_tree_frame, columns=parked_cols, show='headings', style='Treeview', height=4)
        self.parked_tree.heading('item_name', text='품목명')
        self.parked_tree.heading('scan_count', text='스캔 수량')
        self.parked_tree.column('item_name', anchor='w', stretch=tk.YES)
        self.parked_tree.column('scan_count', width=100, anchor='center', stretch=tk.NO)
        self.parked_tree.grid(row=0, column=0, sticky='nsew')
        sb2 = ttk.Scrollbar(parked_tree_frame, orient='vertical', command=self.parked_tree.yview)
        self.parked_tree['yscrollcommand'] = sb2.set
        sb2.grid(row=0, column=1, sticky='ns')
        self.parked_tree.bind("<Double-1>", self.on_parked_tray_select)
        bottom_frame = ttk.Frame(parent_frame, style='Sidebar.TFrame')
        bottom_frame.grid(row=1, column=0, sticky='nsew')
        bottom_frame.grid_columnconfigure(0, weight=1)
        bottom_frame.grid_rowconfigure(1, weight=1)
        self.tray_image_checkbox = ttk.Checkbutton(bottom_frame, text="🖼️ 트레이 이미지 보기", variable=self.show_tray_image_var, command=self._update_tray_image_display, style='TCheckbutton')
        self.tray_image_checkbox.grid(row=0, column=0, sticky='w', pady=(10, 5))
        self.tray_image_label = ttk.Label(bottom_frame, background=self.COLOR_SIDEBAR_BG, anchor='center')
        self.tray_image_label.grid(row=1, column=0, sticky='nsew', pady=(0, 10))
        parent_frame.grid_rowconfigure(0, weight=3)
        parent_frame.grid_rowconfigure(1, weight=2)

    def _create_center_content(self, parent_frame):
        parent_frame.grid_rowconfigure(4, weight=1)
        parent_frame.grid_columnconfigure(0, weight=1)
        self.current_item_label = ttk.Label(parent_frame, text="", style='ItemInfo.TLabel', justify='center', anchor='center')
        self.current_item_label.grid(row=0, column=0, sticky='ew', pady=(10, 20))
        self.main_count_label = ttk.Label(parent_frame, text=f"0 / {self.TRAY_SIZE}", style='MainCounter.TLabel', anchor='center')
        self.main_count_label.grid(row=1, column=0, sticky='ew', pady=(10, 20))
        self.main_progress_bar = ttk.Progressbar(parent_frame, orient='horizontal', mode='determinate', maximum=self.TRAY_SIZE, style='Big.Horizontal.TProgressbar')
        self.main_progress_bar.grid(row=2, column=0, sticky='ew', pady=(0, 20), padx=20)
        vcmd = (self.root.register(self._validate_barcode_input), '%P')
        self.scan_entry = tk.Entry(parent_frame, justify='center', font=(self.DEFAULT_FONT, int(30*self.scale_factor), 'bold'), bd=2, relief=tk.SOLID, highlightbackground=self.COLOR_BORDER, highlightcolor=self.COLOR_PRIMARY, highlightthickness=3, validate='key', validatecommand=vcmd)
        self.scan_entry.grid(row=3, column=0, sticky='ew', ipady=int(15*self.scale_factor), padx=30)
        self.scan_entry.bind('<Return>', self.process_barcode)
        self.scanned_listbox = tk.Listbox(parent_frame, font=(self.DEFAULT_FONT, int(14*self.scale_factor)), relief='flat', bg=self.COLOR_SIDEBAR_BG, justify='center', selectbackground=self.COLOR_PRIMARY, height=8)
        self.scanned_listbox.grid(row=4, column=0, sticky='nsew', pady=(30, 0), padx=30)
        button_frame = ttk.Frame(parent_frame)
        button_frame.grid(row=5, column=0, pady=(30, 0))
        ttk.Button(button_frame, text="현재 작업 리셋", command=self.reset_current_work).pack(side=tk.LEFT, padx=10)
        self.undo_button = ttk.Button(button_frame, text="↩️ 마지막 스캔 취소", command=self.undo_last_scan, state=tk.DISABLED)
        self.undo_button.pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="⏸️ 트레이 보류", command=self.park_current_tray).pack(side=tk.LEFT, padx=10)
        self.submit_tray_button = ttk.Button(button_frame, text="✅ 트레이 제출", command=self.submit_current_tray)
        self.submit_tray_button.pack(side=tk.LEFT, padx=10)

    def _create_right_sidebar_content(self, parent_frame):
        parent_frame.grid_columnconfigure(0, weight=1)
        parent_frame['padding'] = (10, 10)
        self.date_label = ttk.Label(parent_frame, style='Sidebar.TLabel', font=(self.DEFAULT_FONT, int(18*self.scale_factor),'bold'))
        self.date_label.grid(row=0, column=0, pady=(0,5))
        self.clock_label = ttk.Label(parent_frame, style='Sidebar.TLabel', font=(self.DEFAULT_FONT, int(24*self.scale_factor),'bold'))
        self.clock_label.grid(row=1, column=0, pady=(0,20))
        self.info_cards = {
            'status': self._create_info_card(parent_frame, "⏰ 현재 작업 상태"), 'stopwatch': self._create_info_card(parent_frame, "⏱️ 현재 트레이 소요 시간"),
            'avg_time': self._create_info_card(parent_frame, "📊 평균 완료 시간"), 'best_time': self._create_info_card(parent_frame, "🥇 금주 최고 기록")
        }
        card_order = ['status', 'stopwatch', 'avg_time', 'best_time']
        for i, card_key in enumerate(card_order):
            self.info_cards[card_key]['frame'].grid(row=i + 2, column=0, sticky='ew', pady=10)
        best_time_card = self.info_cards['best_time']
        best_time_card['frame'].config(style='VelvetCard.TFrame')
        best_time_card['label'].config(style='Velvet.Subtle.TLabel')
        best_time_card['value'].config(style='Velvet.Value.TLabel')
        parent_frame.grid_rowconfigure(len(self.info_cards) + 2, weight=1)
        legend_frame = ttk.Frame(parent_frame, style='Sidebar.TFrame', padding=(0,15))
        legend_frame.grid(row=len(self.info_cards)+3, column=0, sticky='sew')
        ttk.Label(legend_frame, text="범례:", style='Subtle.TLabel').pack(anchor='w')
        ttk.Label(legend_frame, text="🟩 스캔 성공", style='Sidebar.TLabel', foreground=self.COLOR_SUCCESS).pack(anchor='w')
        ttk.Label(legend_frame, text="🟨 휴식/대기", style='Sidebar.TLabel', foreground="#B8860B").pack(anchor='w')

    def _create_info_card(self, parent: ttk.Frame, label_text: str) -> Dict[str, ttk.Widget]:
        card = ttk.Frame(parent, style='Card.TFrame', padding=20)
        label = ttk.Label(card, text=label_text, style='Subtle.TLabel')
        label.pack()
        value_label = ttk.Label(card, text="-", style='Value.TLabel')
        value_label.pack()
        return {'frame': card, 'label': label, 'value': value_label}

    def _validate_barcode_input(self, p_text: str) -> bool:
        if not p_text:
            return True
        if re.search(r'[ㄱ-ㅎㅏ-ㅣ가-힣]', p_text):
            self.show_fullscreen_warning("입력 모드 오류", "한글이 입력되었습니다. 한/영 키를 눌러주세요.", self.COLOR_DANGER)
            return False
        return True

    def _schedule_focus_return(self, delay_ms: int = 1000):
        if self.focus_return_job:
            self.root.after_cancel(self.focus_return_job)
        self.focus_return_job = self.root.after(delay_ms, self._return_focus_to_scan_entry)

    def _return_focus_to_scan_entry(self):
        try:
            if hasattr(self, 'scan_entry') and self.scan_entry.winfo_exists() and self.root.focus_get() != self.scan_entry:
                self.scan_entry.focus_set()
            self.focus_return_job = None
        except Exception as e:
            print(f"포커스 설정 오류: {e}")

    def _update_current_item_label(self, instruction: str = ""):
        if not (hasattr(self, 'current_item_label') and self.current_item_label.winfo_exists()): return
        if self.current_tray.master_label_code:
            name_part = f"현재 품목: {self.current_tray.item_name} ({self.current_tray.item_code})"
            spec_part = f" - {self.current_tray.item_spec}" if self.current_tray.item_spec else ""
            if not instruction:
                if not self.current_tray.scanned_barcodes:
                    instruction = "\n첫 번째 제품을 스캔하세요."
                else:
                    instruction = "\n다음 제품을 스캔하세요."
            self.current_item_label['text'] = f"{name_part}{spec_part}{instruction}"
            self.current_item_label['foreground'] = self.COLOR_TEXT
        else:
            self.current_item_label['text'] = "현품표 라벨을 스캔하여 작업을 시작하세요."
            self.current_item_label['foreground'] = self.COLOR_TEXT_SUBTLE
    
    def _sanitize_filename(self, filename: str) -> str:
        """문자열에서 파일명으로 사용할 수 없는 특수문자를 제거합니다."""
        return re.sub(r'[\\/*?:"<>|]', '_', filename)

    def process_barcode(self, event=None):
        barcode = self.scan_entry.get().strip()
        self.scan_entry.delete(0, tk.END)
        if not barcode: return
        self._update_last_activity_time()
        
        if barcode == self.TEST_LOG_GENERATION: self._run_test_fill_tray(save_log=True); return
        if barcode == self.TEST_UI_FILL_ONLY: self._run_test_fill_tray(save_log=False); return

        if not self.current_tray.master_label_code:
            # === 신규 QR 현품표 처리 (고유 ID가 있는 경우) ===
            if '|' in barcode and '=' in barcode:
                # 1. 완료된 현품표인지 중복 검사
                if barcode in self.completed_master_labels:
                    self.show_fullscreen_warning("현품표 중복", f"이미 완료 처리된 현품표입니다.\n(현품표: {barcode})", self.COLOR_DANGER)
                    return

                # 2. 보류된 현품표인지 검사 후 복원 제안
                sanitized_barcode = self._sanitize_filename(barcode)
                parked_filename = f"parked_qr_{self.worker_name}_{sanitized_barcode}.json"
                parked_filepath = os.path.join(self.parked_trays_dir, parked_filename)
                
                if os.path.exists(parked_filepath):
                    if messagebox.askyesno("보류 작업 발견", "이 현품표는 보류 중인 작업입니다.\n이 작업을 복원하시겠습니까?"):
                        self.restore_parked_tray(parked_filepath)
                    return

                # 3. 새로운 트레이 시작
                try:
                    qr_data = dict(pair.split('=', 1) for pair in barcode.split('|'))
                    item_code = qr_data.get('CLC')
                    tray_quantity = int(qr_data.get('QT', self.TRAY_SIZE))

                    if not item_code:
                        self.show_fullscreen_warning("QR코드 오류", "QR코드에 고객사 코드(CLC)가 없습니다.", self.COLOR_DANGER)
                        return
                    
                    matched_item = next((item for item in self.items_data if item['Item Code'] == item_code), None)
                    if not matched_item:
                        self.show_fullscreen_warning("품목 없음", f"코드 '{item_code}'에 해당하는 품목 정보를 찾을 수 없습니다.", self.COLOR_DANGER)
                        return
                    
                    self.current_tray = TraySession(
                        master_label_code=barcode,
                        item_code=item_code,
                        tray_size=tray_quantity,
                        item_name=matched_item.get('Item Name', ''),
                        item_spec=matched_item.get('Spec', '')
                    )
                    self._log_event('MASTER_LABEL_SCANNED_NEW', detail=qr_data)

                except Exception as e:
                    self.show_fullscreen_warning("QR코드 분석 오류", f"새로운 현품표 QR코드를 해석하는 중 오류가 발생했습니다.\n{e}", self.COLOR_DANGER)
                    return

            # === 기존 13자리 현품표 처리 (고유 ID가 없는 경우) ===
            else:
                if len(barcode) != self.ITEM_CODE_LENGTH:
                    self.show_fullscreen_warning("작업 시작 오류", f"잘못된 형식의 바코드입니다.\n{self.ITEM_CODE_LENGTH}자리 품목코드 또는 신규 QR을 스캔하세요.", self.COLOR_DANGER)
                    return
                
                matched_item = next((item for item in self.items_data if item['Item Code'] == barcode), None)
                if not matched_item:
                    self.show_fullscreen_warning("품목 없음", f"현품표 코드 '{barcode}'에 해당하는 품목 정보를 찾을 수 없습니다.", self.COLOR_DANGER)
                    return
                
                self.current_tray = TraySession(
                    master_label_code=barcode,
                    item_code=barcode,
                    tray_size=self.TRAY_SIZE,
                    item_name=matched_item.get('Item Name', ''),
                    item_spec=matched_item.get('Spec', '')
                )
                self._log_event('MASTER_LABEL_SCANNED_OLD', detail={'master_label_code': barcode})

            self._update_tray_image_display()
            self._update_current_item_label()
            self._update_center_display()
            self._start_stopwatch()
            self._save_current_tray_state()
            return

        # 제품 스캔 로직
        if len(barcode) <= self.ITEM_CODE_LENGTH:
            self.show_fullscreen_warning("바코드 형식 오류", f"제품 바코드는 {self.ITEM_CODE_LENGTH}자리보다 길어야 합니다.\n(스캔된 코드: {barcode})", self.COLOR_DANGER); return
        if self.current_tray.item_code not in barcode:
            self.current_tray.mismatch_error_count += 1; self.current_tray.has_error_or_reset = True
            self.show_fullscreen_warning("품목 코드 불일치!", f"제품의 품목 코드가 일치하지 않습니다.\n[기준: {self.current_tray.item_code}]", self.COLOR_DANGER)
            self._log_event('SCAN_FAIL_MISMATCH', detail={'expected': self.current_tray.item_code, 'scanned': barcode}); return
        if barcode in self.current_tray.scanned_barcodes:
            self.current_tray.mismatch_error_count += 1; self.current_tray.has_error_or_reset = True
            self.show_fullscreen_warning("바코드 중복!", f"제품 바코드 '{barcode}'는 이미 스캔되었습니다.", self.COLOR_DANGER)
            self._log_event('SCAN_FAIL_DUPLICATE', detail={'barcode': barcode}); return
        
        now = datetime.datetime.now()
        interval = (now - self.current_tray.scan_times[-1]).total_seconds() if self.current_tray.scan_times else 0.0
        self.add_scanned_barcode(barcode, now, interval)
        self._save_current_tray_state()
        
        if len(self.current_tray.scanned_barcodes) == self.current_tray.tray_size:
            self.complete_tray()

    def _run_test_fill_tray(self, save_log: bool):
        if not self.current_tray.master_label_code:
            messagebox.showwarning("테스트 모드 오류", "테스트 모드는 현품표 라벨을 스캔한 후에만 사용할 수 있습니다."); return
        self.current_tray.is_test_tray = not save_log; self.current_tray.has_error_or_reset = True
        remaining_scans = self.current_tray.tray_size - len(self.current_tray.scanned_barcodes)
        for i in range(remaining_scans):
            unique_test_barcode = f"TEST-{self.current_tray.item_code}-{datetime.datetime.now().strftime('%f')}-{i}"
            self.add_scanned_barcode(unique_test_barcode, datetime.datetime.now(), 0.1)
            self.root.update(); time.sleep(0.01)
        if len(self.current_tray.scanned_barcodes) == self.current_tray.tray_size: self.complete_tray()

    def add_scanned_barcode(self, barcode: str, scan_time: datetime.datetime, interval: float):
        if self.success_sound:
            self.success_sound.play()
        self.current_tray.scanned_barcodes.append(barcode)
        self.current_tray.scan_times.append(scan_time)
        count = len(self.current_tray.scanned_barcodes)
        self.scanned_listbox.insert(0, f"({count}) {barcode}")
        self.scanned_listbox.itemconfig(0, {'bg': self.COLOR_SUCCESS, 'fg': 'white'})
        self.root.after(400, lambda: self.scanned_listbox.winfo_exists() and self.scanned_listbox.size() > 0 and self.scanned_listbox.itemconfig(0, {'bg': self.COLOR_SIDEBAR_BG, 'fg': self.COLOR_TEXT}))
        self._update_center_display()
        self._update_current_item_label()
        self.undo_button['state'] = tk.NORMAL
        self._log_event('SCAN_OK', detail={'barcode': barcode, 'interval_sec': f"{interval:.2f}"})

    def complete_tray(self):
        self._stop_stopwatch(); self._stop_idle_checker(); self.undo_button['state'] = tk.DISABLED
        is_test = self.current_tray.is_test_tray; has_error = self.current_tray.has_error_or_reset; is_partial = self.current_tray.is_partial_submission
        is_restored = self.current_tray.is_restored_session
        master_label = self.current_tray.master_label_code
        if not is_test:
            self._log_event('TRAY_COMPLETE', detail={
                'master_label_code': master_label, 'item_code': self.current_tray.item_code, 'item_name': self.current_tray.item_name, 'scan_count': len(self.current_tray.scanned_barcodes),
                'tray_capacity': self.current_tray.tray_size, 'scanned_product_barcodes': self.current_tray.scanned_barcodes, 'work_time_sec': self.current_tray.stopwatch_seconds, 'error_count': self.current_tray.mismatch_error_count,
                'total_idle_seconds': self.current_tray.total_idle_seconds, 'has_error_or_reset': has_error, 'is_partial_submission': is_partial, 'is_restored_session': is_restored,
                'start_time': self.current_tray.start_time.isoformat() if self.current_tray.start_time else None, 'end_time': datetime.datetime.now().isoformat()
            })
            # 고유한 QR 현품표만 완료 목록에 추가하여 중복을 방지합니다.
            if '|' in master_label and '=' in master_label:
                self.completed_master_labels.add(master_label)

        item_code = self.current_tray.item_code
        if item_code not in self.work_summary: self.work_summary[item_code] = {'name': self.current_tray.item_name, 'spec': self.current_tray.item_spec, 'count': 0, 'test_count': 0}
        if is_test: self.work_summary[item_code]['test_count'] += 1; self.show_status_message(f"테스트 트레이 완료! (로그 미저장)", self.COLOR_SUCCESS)
        else:
            self.work_summary[item_code]['count'] += 1
            if not is_partial: self.total_tray_count += 1
            if not has_error and not is_partial and not is_restored and self.current_tray.stopwatch_seconds > 0: self.completed_tray_times.append(self.current_tray.stopwatch_seconds)
            if is_partial: self.show_status_message(f"'{self.current_tray.item_name}' 부분 트레이 제출 완료!", self.COLOR_PRIMARY)
            else: self.show_status_message(f"'{self.current_tray.item_name}' 1 파렛트 완료!", self.COLOR_SUCCESS)
        self.current_tray = TraySession()
        self._delete_current_tray_state()
        self.scanned_listbox.delete(0, tk.END)
        self._update_all_summaries()
        self._reset_ui_to_waiting_state()
        self.tray_last_end_time = datetime.datetime.now()

    def _reset_ui_to_waiting_state(self):
        self._update_current_item_label()
        if self.info_cards.get('stopwatch'): self.info_cards['stopwatch']['value']['text'] = "00:00"
        self._set_idle_style(is_idle=True)
        self._update_center_display()

    def undo_last_scan(self):
        self._update_last_activity_time()
        if not self.current_tray.scanned_barcodes: return
        last_barcode = self.current_tray.scanned_barcodes.pop(); self.current_tray.scan_times.pop(); self.scanned_listbox.delete(0)
        self._update_center_display()
        self._log_event('SCAN_UNDO', detail={'undone_barcode': last_barcode})
        self.show_status_message(f"'{last_barcode}' 스캔이 취소되었습니다.", self.COLOR_DANGER)
        self._update_current_item_label()
        if not self.current_tray.scanned_barcodes: self.undo_button['state'] = tk.DISABLED
        self._save_current_tray_state()
        self._schedule_focus_return()

    def reset_current_work(self):
        self._update_last_activity_time()
        if self.current_tray.master_label_code and messagebox.askyesno("확인", "현재 진행중인 작업을 초기화하시겠습니까?"):
            self._stop_stopwatch(); self._stop_idle_checker(); self.is_idle = False
            self._log_event('TRAY_RESET', detail={'master_label_code': self.current_tray.master_label_code, 'scan_count_at_reset': len(self.current_tray.scanned_barcodes)})
            self.current_tray = TraySession()
            self._delete_current_tray_state(); self.scanned_listbox.delete(0, tk.END)
            self._update_all_summaries(); self.undo_button['state'] = tk.DISABLED
            self._reset_ui_to_waiting_state()
            self._update_tray_image_display()
            self.show_status_message("현재 작업이 초기화되었습니다.", self.COLOR_DANGER)
            self._schedule_focus_return()

    def submit_current_tray(self):
        self._update_last_activity_time()
        if not self.current_tray.master_label_code or not self.current_tray.scanned_barcodes:
            self.show_status_message("제출할 스캔 내역이 없습니다.", self.COLOR_TEXT_SUBTLE); return
        if messagebox.askyesno("트레이 제출 확인", f"현재 {len(self.current_tray.scanned_barcodes)}개 스캔되었습니다.\n이 트레이를 완료로 처리하시겠습니까?"):
            self.current_tray.is_partial_submission = True
            self.complete_tray()
        self._schedule_focus_return()

    def _update_all_summaries(self):
        self._update_summary_title()
        self._update_summary_list()
        self._update_avg_time()
        self._update_best_time()
        self._update_center_display()

    def _update_summary_title(self):
        if hasattr(self, 'summary_title_label') and self.summary_title_label.winfo_exists():
            self.summary_title_label.config(text=f"금일 작업 현황 (총 {self.total_tray_count} 파렛트)")

    def _update_summary_list(self):
        if not (hasattr(self, 'summary_tree') and self.summary_tree.winfo_exists()): return
        for i in self.summary_tree.get_children(): self.summary_tree.delete(i)
        for item_code, data in sorted(self.work_summary.items()):
            count_display = f"{data.get('count', 0)} 파렛트"
            if data.get('test_count', 0) > 0: count_display += f" (테스트: {data['test_count']})"
            item_name_spec = f"{data.get('name', '')}"
            self.summary_tree.insert('', 'end', values=(item_name_spec, item_code, count_display))

    def _update_avg_time(self):
        card = self.info_cards.get('avg_time')
        if not card or not card['value'].winfo_exists(): return
        if self.completed_tray_times:
            avg = sum(self.completed_tray_times) / len(self.completed_tray_times)
            card['value']['text'] = f"{int(avg // 60):02d}:{int(avg % 60):02d}"
        else:
            card['value']['text'] = "-"

    def _update_best_time(self):
        card = self.info_cards.get('best_time')
        if not card or not card['value'].winfo_exists(): return
        if self.completed_tray_times:
            best_time = min(self.completed_tray_times)
            card['value']['text'] = f"{int(best_time // 60):02d}:{int(best_time % 60):02d}"
        else:
            card['value']['text'] = "-"

    def _update_center_display(self):
        if not (hasattr(self, 'main_count_label') and self.main_count_label.winfo_exists()): return
        count = len(self.current_tray.scanned_barcodes)
        target_size = self.current_tray.tray_size if self.current_tray.master_label_code else self.TRAY_SIZE
        self.main_count_label['text'] = f"{count} / {target_size}"
        self.main_progress_bar['maximum'] = target_size
        self.main_progress_bar['value'] = count

    def _update_clock(self):
        if not self.root.winfo_exists(): return
        now = datetime.datetime.now()
        if hasattr(self, 'date_label') and self.date_label.winfo_exists(): self.date_label['text'] = now.strftime('%Y-%m-%d')
        if hasattr(self, 'clock_label') and self.clock_label.winfo_exists(): self.clock_label['text'] = now.strftime('%H:%M:%S')
        self.clock_job = self.root.after(1000, self._update_clock)

    def _start_stopwatch(self, resume=False):
        if not resume:
            self.current_tray.stopwatch_seconds = 0
            self.current_tray.start_time = datetime.datetime.now()
        self._update_last_activity_time()
        if self.stopwatch_job: self.root.after_cancel(self.stopwatch_job)
        self._update_stopwatch()

    def _stop_stopwatch(self):
        if self.stopwatch_job: self.root.after_cancel(self.stopwatch_job); self.stopwatch_job = None

    def _update_stopwatch(self):
        if not self.root.winfo_exists() or self.is_idle: return
        mins, secs = divmod(int(self.current_tray.stopwatch_seconds), 60)
        if self.info_cards.get('stopwatch') and self.info_cards['stopwatch']['value'].winfo_exists():
            self.info_cards['stopwatch']['value']['text'] = f"{mins:02d}:{secs:02d}"
        self.current_tray.stopwatch_seconds += 1
        self.stopwatch_job = self.root.after(1000, self._update_stopwatch)

    def _start_idle_checker(self):
        self._update_last_activity_time()
        if self.idle_check_job: self.root.after_cancel(self.idle_check_job)
        self.idle_check_job = self.root.after(1000, self._check_for_idle)

    def _stop_idle_checker(self):
        if self.idle_check_job: self.root.after_cancel(self.idle_check_job); self.idle_check_job = None

    def _update_last_activity_time(self):
        self.last_activity_time = datetime.datetime.now()
        if self.is_idle:
            self._wakeup_from_idle()

    def _check_for_idle(self):
        if not self.root.winfo_exists() or self.is_idle: return
        if not self.current_tray.master_label_code:
            self.idle_check_job = self.root.after(1000, self._check_for_idle); return
        if not self.last_activity_time:
            self.idle_check_job = self.root.after(1000, self._check_for_idle); return
        time_since = (datetime.datetime.now() - self.last_activity_time).total_seconds()
        if time_since > self.IDLE_THRESHOLD_SEC:
            self.is_idle = True
            self._set_idle_style(is_idle=True)
            self._log_event('IDLE_START', detail={'threshold_sec': self.IDLE_THRESHOLD_SEC})
        else:
            self.idle_check_job = self.root.after(1000, self._check_for_idle)

    def _wakeup_from_idle(self):
        if not self.is_idle: return
        self.is_idle = False
        if self.last_activity_time:
            idle_duration = (datetime.datetime.now() - self.last_activity_time).total_seconds()
            self.current_tray.total_idle_seconds += idle_duration
            self._log_event('IDLE_END', detail={'duration_sec': f"{idle_duration:.2f}"})
        self._set_idle_style(is_idle=False)
        self._start_idle_checker()
        self._update_stopwatch()
        self.show_status_message(f"작업 재개.", self.COLOR_SUCCESS)

    def _set_idle_style(self, is_idle: bool):
        if not (hasattr(self, 'info_cards') and self.info_cards): return
        style_prefix = 'Idle.' if is_idle else ''
        card_style = f'{style_prefix}TFrame' if style_prefix else 'Card.TFrame'
        for key in ['status', 'stopwatch', 'avg_time']:
            if self.info_cards.get(key):
                card = self.info_cards[key]
                card['frame']['style'] = card_style
                card['label']['style'] = f'{style_prefix}Subtle.TLabel'
                card['value']['style'] = f'{style_prefix}Value.TLabel'
        status_widget = self.info_cards['status']['value']
        if is_idle:
            status_widget['text'] = "대기 중"; status_widget['foreground'] = self.COLOR_TEXT
            self.show_status_message(f"휴식 상태입니다. 스캔하여 작업을 재개하세요.", self.COLOR_IDLE, duration=10000)
        else:
            status_widget['text'] = "작업 중"; status_widget['foreground'] = self.COLOR_SUCCESS

    def _on_column_resize(self, event: tk.Event, tree: ttk.Treeview, name: str):
        if tree.identify_region(event.x, event.y) == "separator":
            self.root.after(10, self._save_column_widths, tree, name)
            self._schedule_focus_return()

    def _save_column_widths(self, tree: ttk.Treeview, name: str):
        for col_id in tree["columns"]: self.column_widths[f'{name}_{col_id}'] = tree.column(col_id, "width")
        self.save_settings()

    def _start_warning_beep(self):
        if self.error_sound:
            self.error_sound.play(loops=-1)

    def _stop_warning_beep(self):
        if self.error_sound:
            self.error_sound.stop()

    def show_fullscreen_warning(self, title: str, message: str, color: str):
        self._start_warning_beep()
        popup = tk.Toplevel(self.root); popup.title(title); popup.attributes('-fullscreen', True)
        popup.configure(bg=color); popup.grab_set()
        def on_popup_close():
            self._stop_warning_beep(); popup.destroy()
            self._schedule_focus_return()
        title_font = (self.DEFAULT_FONT, int(60*self.scale_factor), 'bold')
        msg_font = (self.DEFAULT_FONT, int(30*self.scale_factor), 'bold')
        tk.Label(popup, text=title, font=title_font, fg='white', bg=color).pack(pady=(100, 50), expand=True)
        tk.Label(popup, text=message, font=msg_font, fg='white', bg=color, wraplength=self.root.winfo_screenwidth() - 100, justify=tk.CENTER).pack(pady=20, expand=True)
        btn = tk.Button(popup, text="확인 (클릭)", font=msg_font, command=on_popup_close, bg='white', fg=color, relief='flat', padx=20, pady=10)
        btn.pack(pady=50, expand=True); btn.focus_set()

    def _cancel_all_jobs(self):
        if self.clock_job: self.root.after_cancel(self.clock_job); self.clock_job = None
        if self.status_message_job: self.root.after_cancel(self.status_message_job); self.status_message_job = None
        if self.stopwatch_job: self._stop_stopwatch()
        if self.idle_check_job: self._stop_idle_checker()
        if self.focus_return_job: self.root.after_cancel(self.focus_return_job); self.focus_return_job = None
        self._stop_warning_beep()

    def on_closing(self):
        if messagebox.askokcancel("종료", "프로그램을 종료하시겠습니까?"):
            if self.worker_name: self._log_event('WORK_END', detail={'message': 'User closed the program.'})
            if self.worker_name and self.current_tray.master_label_code:
                if messagebox.askyesno("작업 저장", "진행 중인 트레이를 저장하고 종료할까요?"): self._save_current_tray_state()
                else: self._delete_current_tray_state()
            else:
                self._delete_current_tray_state()
            if hasattr(self, 'paned_window') and self.paned_window.winfo_exists():
                try:
                    num_panes = len(self.paned_window.panes())
                    if num_panes > 1: self.paned_window_sash_positions = {str(i): self.paned_window.sashpos(i) for i in range(num_panes - 1)}
                except tk.TclError as e: print(f"종료 시 sash 위치 저장 오류: {e}")
            self.save_settings(); self._cancel_all_jobs(); self.log_queue.put(None)
            if self.log_thread.is_alive(): self.log_thread.join(timeout=1.0)
            pygame.quit()
            self.root.destroy()

    def _event_log_writer(self):
        while True:
            try:
                log_entry = self.log_queue.get(timeout=1.0)
                if log_entry is None: break
                if not self.log_file_path: time.sleep(0.1); self.log_queue.put(log_entry); continue
                file_exists = not os.path.exists(self.log_file_path) or os.stat(self.log_file_path).st_size == 0
                with open(self.log_file_path, 'a', newline='', encoding='utf-8-sig') as f_handle:
                    writer = csv.writer(f_handle)
                    if file_exists: writer.writerow(['timestamp', 'worker_name', 'event', 'details'])
                    writer.writerow([log_entry['timestamp'], log_entry['worker_name'], log_entry['event'], log_entry['details']])
            except queue.Empty: continue
            except Exception as e: print(f"로그 파일 쓰기 오류: {e}")

    def _log_event(self, event_type: str, detail: Optional[Dict] = None):
        if not self.worker_name: return
        log_entry = { 'timestamp': datetime.datetime.now().isoformat(), 'worker_name': self.worker_name, 'event': event_type, 'details': json.dumps(detail, ensure_ascii=False) if detail else '' }
        self.log_queue.put(log_entry)

    def show_status_message(self, message: str, color: Optional[str] = None, duration: int = 4000):
        if self.status_message_job: self.root.after_cancel(self.status_message_job)
        self.status_label['text'] = message; self.status_label['fg'] = color or self.COLOR_TEXT
        self.status_message_job = self.root.after(duration, self._reset_status_message)

    def _reset_status_message(self):
        if hasattr(self, 'status_label') and self.status_label.winfo_exists():
            self.status_label['text'] = "준비"; self.status_label['fg'] = self.COLOR_TEXT

    def _update_tray_image_display(self):
        if not (hasattr(self, 'tray_image_label') and self.tray_image_label.winfo_exists()): return
        if self.show_tray_image_var.get():
            if self.current_tray.item_code:
                item_info = next((item for item in self.items_data if item['Item Code'] == self.current_tray.item_code), None)
                if item_info and 'Tray Image' in item_info and item_info['Tray Image']:
                    try:
                        parent_frame = self.tray_image_label.master
                        max_w = parent_frame.winfo_width() - 20
                        max_h = (self.left_pane.winfo_height() // 2) - 40
                        if max_w < 20: max_w = 250
                        if max_h < 20: max_h = 250
                        img_path = resource_path(item_info['Tray Image'])
                        img = Image.open(img_path)
                        original_width, original_height = img.size
                        ratio = min(max_w / original_width, max_h / original_height)
                        new_width = int(original_width * ratio)
                        new_height = int(original_height * ratio)
                        resized_img = img.resize((new_width, new_height), Image.Resampling.LANCZOS)
                        photo = ImageTk.PhotoImage(resized_img)
                        self.tray_image_label.config(image=photo, text="")
                        self.tray_image_label.image = photo
                    except Exception as e:
                        self.tray_image_label.config(image=None, text=f"이미지 오류:\n{e}", foreground=self.COLOR_DANGER)
                else:
                    self.tray_image_label.config(image=None, text="이 품목의\n트레이 이미지가\n등록되지 않았습니다.", foreground=self.COLOR_TEXT_SUBTLE)
            else:
                self.tray_image_label.config(image=None, text="현품표를 먼저\n스캔해주세요.", foreground=self.COLOR_TEXT_SUBTLE)
        else:
            self.tray_image_label.config(image=None, text="")
            self.tray_image_label.image = None
        self._schedule_focus_return()

    # ####################################################################
    # # 트레이 보류 및 복원 기능
    # ####################################################################
    def park_current_tray(self):
        """현재 진행 중인 트레이를 보류 목록으로 이동시킵니다."""
        if not self.current_tray.master_label_code:
            self.show_status_message("보류할 작업이 없습니다.", self.COLOR_DANGER)
            return

        if not messagebox.askyesno("트레이 보류 확인", "현재 작업을 잠시 보류하고 다른 작업을 시작하시겠습니까?"):
            return

        master_label = self.current_tray.master_label_code

        # 신규 QR 현품표인 경우 (고유함)
        if '|' in master_label and '=' in master_label:
            sanitized_master_label = self._sanitize_filename(master_label)
            # 파일명에 'qr'을 붙여 구분하고, 고유한 현품표 코드를 사용
            filename = f"parked_qr_{self.worker_name}_{sanitized_master_label}.json"
        # 기존 13자리 현품표인 경우 (고유하지 않음)
        else:
            # 고유하지 않으므로, 파일명에 품목코드와 함께 고유 UUID를 추가
            filename = f"parked_legacy_{self.worker_name}_{master_label}_{uuid.uuid4().hex[:8]}.json"
        
        filepath = os.path.join(self.parked_trays_dir, filename)

        try:
            serializable_state = {
                'worker_name': self.worker_name, 'master_label_code': self.current_tray.master_label_code,
                'item_code': self.current_tray.item_code, 'item_name': self.current_tray.item_name,
                'item_spec': self.current_tray.item_spec, 'scanned_barcodes': self.current_tray.scanned_barcodes,
                'scan_times': [dt.isoformat() for dt in self.current_tray.scan_times],
                'tray_size': self.current_tray.tray_size, 'mismatch_error_count': self.current_tray.mismatch_error_count,
                'total_idle_seconds': self.current_tray.total_idle_seconds,
                'stopwatch_seconds': self.current_tray.stopwatch_seconds,
                'start_time': self.current_tray.start_time.isoformat() if self.current_tray.start_time else None,
                'has_error_or_reset': self.current_tray.has_error_or_reset,
                'is_test_tray': self.current_tray.is_test_tray,
                'is_partial_submission': self.current_tray.is_partial_submission
            }
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(serializable_state, f, indent=4, ensure_ascii=False)

            self._log_event('TRAY_PARKED', detail={'item_name': self.current_tray.item_name, 'scan_count': len(self.current_tray.scanned_barcodes)})

            self.current_tray = TraySession()
            self._delete_current_tray_state()
            self.scanned_listbox.delete(0, tk.END)
            self._reset_ui_to_waiting_state()
            self._update_all_summaries()

            self._update_parked_trays_list()
            self.show_status_message("작업을 보류 처리했습니다. 새 현품표를 스캔하세요.", self.COLOR_PRIMARY)

        except Exception as e:
            messagebox.showerror("오류", f"작업 보류 중 오류가 발생했습니다: {e}")

    def _update_parked_trays_list(self):
        """parked_trays 폴더를 읽어 UI 목록을 갱신합니다."""
        if not hasattr(self, 'parked_tree'): return

        for i in self.parked_tree.get_children():
            self.parked_tree.delete(i)

        if not os.path.exists(self.parked_trays_dir): return

        try:
            # 'parked_'로 시작하고 현재 작업자 이름이 포함된 모든 .json 파일을 가져옴
            parked_files = [
                f for f in os.listdir(self.parked_trays_dir) 
                if f.endswith(".json") and f.startswith("parked_") and f"_{self.worker_name}_" in f
            ]
            for filename in sorted(parked_files):
                filepath = os.path.join(self.parked_trays_dir, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        item_name = data.get('item_name', '알 수 없음')
                        scan_count = len(data.get('scanned_barcodes', []))
                        self.parked_tree.insert('', 'end', values=(item_name, f"{scan_count} 개"), iid=filepath)
                except (json.JSONDecodeError, FileNotFoundError):
                    continue
        except Exception as e:
            print(f"보류 목록 갱신 중 오류: {e}")

    def on_parked_tray_select(self, event):
        """보류 목록에서 트레이를 더블 클릭했을 때 실행됩니다."""
        selected_item_iid = self.parked_tree.focus()
        if not selected_item_iid: return
        filepath = selected_item_iid
        self.restore_parked_tray(filepath)

    def restore_parked_tray(self, filepath: str):
        """파일 경로를 받아 보류된 트레이를 복원합니다."""
        if self.current_tray.master_label_code:
            res = messagebox.askyesnocancel("작업 전환 확인", "현재 진행 중인 작업이 있습니다. 이 작업을 보류하고 선택한 작업을 불러오시겠습니까?\n\n('아니오'를 누르면 현재 작업은 삭제됩니다.)")
            if res is True:
                self.park_current_tray()
            elif res is None: # Cancel
                return

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                saved_state = json.load(f)

            self._restore_tray_from_state(saved_state)
            os.remove(filepath)

            self.show_validation_screen()

            self._log_event('TRAY_RESTORED_FROM_PARK', detail={'item_name': self.current_tray.item_name})
            self.show_status_message(f"'{self.current_tray.item_name}' 작업을 다시 시작합니다.", self.COLOR_SUCCESS)

        except FileNotFoundError:
              messagebox.showwarning("복원 실패", "선택한 보류 작업 파일을 찾을 수 없습니다. 목록을 갱신합니다.")
              self._update_parked_trays_list()
        except Exception as e:
            messagebox.showerror("오류", f"작업 복원 중 오류가 발생했습니다: {e}")

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    check_and_apply_updates()
    app = BarcodeValidator()
    app.run()