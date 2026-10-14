"""Run source-release metadata checks against an exact, clean test snapshot."""
from pathlib import Path
import shutil
import subprocess


def candidate_source_snapshot(repo, destination):
    repo=Path(repo).resolve();destination=Path(destination).resolve()
    assert not destination.exists()
    flags=getattr(subprocess,'CREATE_NO_WINDOW',0)
    def git(*arguments,cwd=None):
        result=subprocess.run(['git',*arguments],cwd=cwd,capture_output=True,check=True,
                              creationflags=flags)
        return result.stdout
    git('-c','core.autocrlf=false','clone','--no-hardlinks','--no-checkout','--quiet',
        str(repo),str(destination))
    git('-C',str(destination),'checkout','--detach','--quiet','HEAD')
    names=git('-C',str(repo),'ls-files','-z').decode().split('\0')
    for name in filter(None,names):
        source=repo/name;target=destination/name
        assert source.resolve().is_relative_to(repo) and target.resolve().is_relative_to(destination)
        if source.is_file():
            target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
        elif target.exists():
            target.unlink()
    git('-C',str(destination),'add','--all')
    git('-C',str(destination),'-c','user.name=Candidate fixture',
        '-c','user.email=candidate-fixture@invalid','commit','--quiet','--allow-empty',
        '-m','Exact candidate source for runtime metadata')
    assert not git('-C',str(destination),'status','--porcelain').strip()
    return destination
