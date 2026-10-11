"""Keep real update-mutex calls in a test-only Windows namespace."""
import ctypes


def isolate_update_mutex_names(monkeypatch=None):
    native = ctypes.WinDLL

    class CreateTestMutex:
        def __init__(self, function):
            object.__setattr__(self, 'function', function)

        def __setattr__(self, name, value):
            setattr(self.function, name, value)

        def __call__(self, attributes, name, flags, access):
            name = name.replace('Global\\KMTech.ContainerAudit.Update.',
                                'Local\\KMTech.Test.ContainerAudit.Update.', 1)
            return self.function(attributes, name, flags, access)

    class Kernel:
        def __init__(self, library):
            self.library = library
            self.CreateMutexExW = CreateTestMutex(library.CreateMutexExW)

        def __getattr__(self, name):
            return getattr(self.library, name)

    def isolated(name, *args, **kwargs):
        library = native(name, *args, **kwargs)
        return Kernel(library) if str(name).lower() == 'kernel32' else library

    if monkeypatch is None:
        ctypes.WinDLL = isolated
    else:
        monkeypatch.setattr(ctypes, 'WinDLL', isolated)
