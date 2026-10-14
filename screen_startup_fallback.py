"""Observe one shell attempt and prove that it has released its startup resources."""
from contextlib import contextmanager
import threading
import time


class ScreenStartupUnavailable(RuntimeError):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class ScreenLaunchAttempt:
    def __init__(self):
        self.bridge = None
        self.startup_observer = None
        self.app = None
        self.owner_thread = None
        self.owner_finished = threading.Event()
        self.owner_returned = False
        self.instance_released = False
        self.bridge_construction_started = False
        self.windows = []
        self.native_hosts = []
        self.closing_waits = []
        self.webview = None
        self.initial_windows = ()
        self.shown_once = threading.Event()
        self.servers = []
        self.server_threads = []
        self.server_created = threading.Event()
        self.server_construction_started = False
        self.server_construction_completed = False

    def record_startup(self, event, **fields):
        observer = self.startup_observer
        if callable(observer):
            try:
                observer(event, **fields)
            except Exception:
                pass

    def enter_owner(self, bridge):
        self.bridge = bridge
        self.owner_thread = threading.current_thread()

    def enter_app(self, app):
        self.app = app

    def owner_completed(self):
        self.owner_returned = True

    def release_instance(self):
        self.instance_released = True

    def surface_was_seen(self):
        if self.bridge is not None and getattr(self.bridge, '_view_count', 0) > 0:
            self.shown_once.set()
        for window in self.windows:
            if window.events.shown.is_set():
                self.shown_once.set()
        return self.shown_once.is_set()

    @contextmanager
    def observe_host(self, host):
        # Importing the package creates no native form. The backend still starts
        # through the unchanged v3.16 host, after the app's startup checks.
        import webview
        self.webview = webview
        self.initial_windows = tuple(webview.windows)
        replacements = []

        def replace(owner, name, wrapper):
            original = getattr(owner, name)
            replacements.append((owner, name, original))
            setattr(owner, name, wrapper(original))

        def bridge_factory(original):
            def create(*args, **kwargs):
                self.bridge_construction_started = True
                self.bridge = original(*args, **kwargs)
                return self.bridge
            return create

        def window_factory(original):
            def create(*args, **kwargs):
                window = original(*args, **kwargs)
                self.windows.append(window)
                window.events.shown += self.shown_once.set
                from runtime_entry import set_gui_state
                window.events.shown += lambda: set_gui_state("running")
                return window
            return create

        def native_factory(original):
            def create(*args, **kwargs):
                native = original(*args, **kwargs)
                self.native_hosts.append(native)
                return native
            return create

        def closing_factory(original):
            def create(*args, **kwargs):
                closing = original(*args, **kwargs)
                self.closing_waits.append(closing)
                return closing
            return create

        def server_factory(original):
            def create(*args, **kwargs):
                server = original(*args, **kwargs)
                self.servers.append(server)
                self.server_created.set()
                return server
            return create

        def global_server_factory(original):
            def create(*args, **kwargs):
                self.server_construction_started = True
                result = original(*args, **kwargs)
                self.server_threads.append(result[-1].thread)
                self.server_construction_completed = True
                return result
            return create

        def start_factory(original):
            def start(*args, **kwargs):
                began = time.monotonic()
                self.record_startup("WEBVIEW_START_ENTER")
                try:
                    result = original(*args, **kwargs)
                except BaseException as error:
                    self.record_startup("WEBVIEW_START_ERROR", error=error,
                                        elapsed_ms=int((time.monotonic() - began) * 1000),
                                        ready=bool(getattr(self.bridge, "_startup_ready", False)),
                                        cause=getattr(self.bridge, "_startup_cause", None))
                    raise
                self.record_startup("WEBVIEW_START_RETURN", elapsed_ms=int((time.monotonic() - began) * 1000),
                                    ready=bool(getattr(self.bridge, "_startup_ready", False)),
                                    cause=getattr(self.bridge, "_startup_cause", None))
                return result
            return start

        original_threading = getattr(host, 'threading', None)
        if original_threading is not None:
            attempt = self
            class ObservedThreads:
                def __getattr__(self, name):
                    return getattr(original_threading, name)

                def Thread(self, *args, **kwargs):
                    thread = original_threading.Thread(*args, **kwargs)
                    if kwargs.get('name') == 'app-owner':
                        attempt.owner_thread = thread
                    return thread
            replacements.append((host, 'threading', original_threading))
            host.threading = ObservedThreads()
        try:
            if hasattr(host, 'Bridge'):
                replace(host, 'Bridge', bridge_factory)
            if hasattr(webview, 'start'):
                replace(webview, 'start', start_factory)
            if hasattr(webview, 'create_window'):
                replace(webview, 'create_window', window_factory)
            if hasattr(host, 'NativeHost'):
                replace(host, 'NativeHost', native_factory)
            if hasattr(host, 'ClosingWait'):
                replace(host, 'ClosingWait', closing_factory)
            http = getattr(webview, 'http', None)
            if http is not None and hasattr(http, 'make_server'):
                replace(http, 'make_server', server_factory)
                replace(http, 'start_global_server', global_server_factory)
            yield
        finally:
            for owner, name, original in reversed(replacements):
                setattr(owner, name, original)

    @staticmethod
    def _bounded_close(action, seconds=5):
        finished = threading.Event()
        errors = []
        def close():
            try:
                action()
            except BaseException:
                errors.append(True)
            finally:
                finished.set()
        thread = threading.Thread(target=close, name='screen-startup-cleanup', daemon=True)
        thread.start()
        thread.join(seconds)
        return finished.is_set() and not thread.is_alive() and not errors

    def _close_http(self):
        if self.server_construction_started and not self.server_construction_completed:
            return False
        if any(thread.is_alive() for thread in self.server_threads) and not self.servers:
            if not self.server_created.wait(1):
                return False
        for server in self.servers:
            if not self._bounded_close(lambda server=server: (server.shutdown(), server.server_close())):
                return False
        for thread in self.server_threads:
            thread.join(2)
            if thread.is_alive():
                return False
        return True

    @staticmethod
    def _forms(window):
        gui = getattr(window, 'gui', None)
        if gui is None:
            return None  # pywebview has not initialized a native backend.
        views = getattr(gui, 'BrowserView', None)
        instances = getattr(views, 'instances', None)
        return instances if isinstance(instances, dict) else False

    def _close_forms(self):
        if self.webview is None:
            return not self.windows
        if self.initial_windows:
            return False  # The attempt cannot claim somebody else's surface.
        if any(window not in self.windows for window in self.webview.windows):
            return False
        for window in self.windows:
            forms = self._forms(window)
            if forms is False:
                return False
            if forms is None:
                if window in self.webview.windows:
                    self.webview.windows.remove(window)
                continue
            if window.uid in forms:
                if not self._bounded_close(window.destroy):
                    return False
                if not window.events.closed.wait(2) or window.uid in forms:
                    return False
            if window in self.webview.windows:
                self.webview.windows.remove(window)
        # A closing banner is only possible after visibility; keep this extra
        # check so a future host change cannot turn an unknown form into proof.
        return all(getattr(native, '_closing_banner', None) is None for native in self.native_hosts)

    def cleanup_before_fallback(self):
        if self.surface_was_seen():
            return False
        for closing in self.closing_waits:
            closing.close()  # Suppress a closing prompt during pre-visible cleanup.
        for native in self.native_hosts:
            native.close()
        if not self._close_http():
            return False
        if self.bridge_construction_started and self.bridge is None:
            return False
        if self.bridge is not None:
            if not self._bounded_close(self.bridge.close):
                return False
            publisher = getattr(self.bridge, '_publisher', None)
            if not getattr(self.bridge, '_closed', False) or publisher is None or publisher.is_alive():
                return False
        owner = self.owner_thread
        if owner is not None:
            if owner is not threading.current_thread():
                owner.join(10)
                if owner.is_alive():
                    return False
            if not self.owner_finished.is_set() or not self.owner_returned or not self.instance_released:
                return False
            if self.app is None or not getattr(self.app, '_application_close_complete', False):
                return False
            if not getattr(self.app, '_loop_cleanup_finished', False):
                return False
        if not self._close_forms():
            return False
        return not self.surface_was_seen()
