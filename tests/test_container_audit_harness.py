import container_audit_test_harness as harness


def test_parse_internal_test_command_generates_logs():
    command = harness.parse_internal_test_command("TEST_LOG_25")

    assert command is not None
    assert command.action == "generate_test_logs"
    assert command.count == 25


def test_parse_internal_test_command_creates_parked_trays():
    command = harness.parse_internal_test_command("_CREATE_PARKED_TRAYS_AAA2270730100_3_")

    assert command is not None
    assert command.action == "create_parked_trays"
    assert command.item_code == "AAA2270730100"
    assert command.count == 3


def test_parse_internal_test_command_reports_bad_parked_command():
    command = harness.parse_internal_test_command("_CREATE_PARKED_TRAYS_BAD")

    assert command is not None
    assert command.action == "error"
    assert "형식" in command.error_message


def test_parse_internal_test_command_rejects_zero_parked_trays():
    command = harness.parse_internal_test_command("_CREATE_PARKED_TRAYS_AAA2270730100_0_")

    assert command is not None
    assert command.action == "error"
    assert "1 이상" in command.error_message


def test_parse_internal_test_command_detects_auto_test():
    command = harness.parse_internal_test_command("_RUN_AUTO_TEST_")

    assert command is not None
    assert command.action == "run_auto_test"
