import os


# Automated GUI/contract runs must never reach the operator's audio device.
os.environ.setdefault("SDL_AUDIODRIVER", "dummy")
os.environ.setdefault("PYGAME_HIDE_SUPPORT_PROMPT", "1")
os.environ.setdefault("KMTECH_TEST_SILENT_AUDIO", "1")
