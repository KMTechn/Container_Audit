"""Evaluate executable spec configuration without running a compiler/freezer."""
from pathlib import Path
import runpy
from types import SimpleNamespace


def evaluate_spec(path: Path):
    observed = {}

    def analysis(scripts, **options):
        observed['analysis'] = dict(scripts=scripts, **options)
        return SimpleNamespace(pure=[], scripts=scripts, binaries=options['binaries'], datas=options['datas'])

    def exe(*args, **options):
        observed['exe'] = dict(options)
        return object()

    def collect(*args, **options):
        observed['collect'] = dict(options)
        return object()

    runpy.run_path(str(path), init_globals={'Analysis': analysis, 'PYZ': lambda pure: object(), 'EXE': exe, 'COLLECT': collect})
    return observed
