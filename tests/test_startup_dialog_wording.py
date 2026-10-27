"""The five startup notices retain diagnostics and use field wording."""
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import Container_Audit as ca
from tests.test_startup_notice_stop import notice, invoke


@pytest.mark.parametrize('mode,title,message', [
    ('instance-lock', '이적을 시작하지 못했습니다',
     '이 PC에서 이적 프로그램을 안전하게 시작하지 못했습니다 — 다시 켜 보고, 또 나오면 현장 관리자에게 알리세요'),
    ('onboarding', '이적 첫 설정을 마치지 못했습니다',
     '이 PC 사용자의 첫 설정을 마치지 못했습니다 — 인터넷 연결을 확인하고 다시 켜 보고, 또 나오면 현장 관리자에게 알리세요'),
    ('missing', '이적을 시작하지 못했습니다',
     '품목 정보 파일이 없어 이적을 시작하지 못했습니다 — 현장 관리자에게 알리세요'),
    ('read', '이적을 시작하지 못했습니다',
     '품목 정보를 읽지 못해 이적을 시작하지 못했습니다 — 다시 켜 보고, 또 나오면 현장 관리자에게 알리세요'),
    ('encoding', '이적을 시작하지 못했습니다',
     '품목 정보 파일의 글자가 깨져 이적을 시작하지 못했습니다 — 현장 관리자에게 알리세요(파일: Item.csv)'),
])
def test_five_startup_dialogs(notice, monkeypatch, tmp_path, mode, title, message):
    notice.tk.publish = None
    notice.tk.manual = True
    if mode == 'instance-lock':
        invoke(mode, monkeypatch, tmp_path)
    elif mode == 'onboarding':
        ca._show_first_run_onboarding_error(ca.CurrentUserOnboardingError(
            'SETUP_FAILED', report_path=tmp_path / 'report.json', status='SETUP_FAILED'))
    else:
        error = {'missing': FileNotFoundError('absent'), 'read': OSError('disk error'),
                 'encoding': UnicodeDecodeError('utf-8', b'\xff', 0, 1, 'invalid')}[mode]
        monkeypatch.setattr(ca, 'get_verified_catalog_snapshot', lambda _path: None)
        monkeypatch.setattr(ca, 'requires_verified_catalog_snapshot', lambda _path: False)
        monkeypatch.setattr(ca, 'resource_path', lambda _path: str(tmp_path / 'Item.csv'))
        monkeypatch.delenv(ca.ACTIVE_PATH_ENV, raising=False)
        monkeypatch.setattr(ca, 'open', Mock(side_effect=error), raising=False)
        app = ca.ContainerAudit.__new__(ca.ContainerAudit)
        app.root = SimpleNamespace(destroy=Mock())
        assert app.load_items() == []
        app.root.destroy.assert_called_once()
    assert notice.tk.roots[-1].caption == title
    assert notice.tk.labels[-1].decode('utf-8') == message
    assert not notice.native


def test_onboarding_support_output_keeps_original_wording(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(ca, '_startup_refusal', lambda *_args: False)
    shown = Mock()
    monkeypatch.setattr(ca, '_show_visible_startup_notice', shown)
    report = tmp_path / 'report.json'
    ca._show_first_run_onboarding_error(ca.CurrentUserOnboardingError(
        'SETUP_FAILED', report_path=report, status='SETUP_FAILED'))
    output = capsys.readouterr()
    assert ('이 사용자 계정의 이적 검사 초기 설정을 완료하지 못했습니다.\n\n'
            '네트워크 연결을 확인한 뒤 다시 실행하세요. 계속 실패하면 오류 보고서 경로를 '
            'IT 담당자에게 전달하세요.') in output.err
    assert f'보고서: {report}' in output.err
    assert str(report) not in shown.call_args.args[1]
