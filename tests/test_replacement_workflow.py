import replacement_workflow


def test_compare_replacement_quantities_rejects_item_code_mismatch():
    decision = replacement_workflow.compare_replacement_quantities(
        {
            "master_label_code": "PHS=1|CLC=AAA2270730100|QT=1",
            "item_code": "AAA2270730100",
            "product_barcodes": ["AAA2270730100-001"],
        },
        {"CLC": "BBB2270730100", "QT": "1"},
    )

    assert decision.action == replacement_workflow.REPLACEMENT_REJECT_ITEM_CODE
    assert decision.expected_item_code == "AAA2270730100"
    assert decision.new_item_code == "BBB2270730100"


def test_compare_replacement_quantities_rejects_original_master_label_item_code_mismatch():
    decision = replacement_workflow.compare_replacement_quantities(
        {
            "master_label_code": "PHS=1|CLC=BBB2270730100|QT=1",
            "item_code": "AAA2270730100",
            "product_barcodes": ["AAA2270730100-001"],
        },
        {"CLC": "AAA2270730100", "QT": "1"},
    )

    assert decision.action == replacement_workflow.REPLACEMENT_REJECT_ITEM_CODE
    assert decision.expected_item_code == "AAA2270730100"
    assert decision.new_item_code == "AAA2270730100"
    assert decision.old_label_item_code == "BBB2270730100"


def test_compare_replacement_quantities_uses_old_label_item_code_when_completion_item_code_missing():
    decision = replacement_workflow.compare_replacement_quantities(
        {
            "master_label_code": "PHS=1|CLC=AAA2270730100|QT=1",
            "product_barcodes": ["AAA2270730100-001"],
            "quantity_basis": "PRODUCT_BARCODE",
        },
        {"CLC": "BBB2270730100", "QT": "1"},
    )

    assert decision.action == replacement_workflow.REPLACEMENT_REJECT_ITEM_CODE
    assert decision.expected_item_code == "AAA2270730100"
    assert decision.new_item_code == "BBB2270730100"
    assert decision.old_label_item_code == "AAA2270730100"


def test_compare_replacement_quantities_uses_partial_product_barcode_quantity():
    decision = replacement_workflow.compare_replacement_quantities(
        {
            "master_label_code": "PHS=1|CLC=AAA2270730100|QT=60",
            "item_code": "AAA2270730100",
            "product_barcodes": ["AAA2270730100-001", "AAA2270730100-002"],
            "is_partial_submission": True,
            "quantity_basis": "PRODUCT_BARCODE",
        },
        {"CLC": "AAA2270730100", "QT": "2"},
    )

    assert decision.action == replacement_workflow.REPLACEMENT_FINALIZE
    assert decision.old_qty == 2
    assert decision.new_qty == 2


def test_compare_replacement_quantities_routes_additional_and_removed_items():
    add_decision = replacement_workflow.compare_replacement_quantities(
        {
            "master_label_code": "PHS=1|CLC=AAA2270730100|QT=1",
            "item_code": "AAA2270730100",
            "product_barcodes": ["AAA2270730100-001"],
        },
        {"CLC": "AAA2270730100", "QT": "2"},
    )
    remove_decision = replacement_workflow.compare_replacement_quantities(
        {
            "master_label_code": "PHS=1|CLC=AAA2270730100|QT=2",
            "item_code": "AAA2270730100",
            "product_barcodes": ["AAA2270730100-001", "AAA2270730100-002"],
        },
        {"CLC": "AAA2270730100", "QT": "1"},
    )

    assert add_decision.action == replacement_workflow.REPLACEMENT_AWAIT_ADDITIONAL
    assert add_decision.items_needed == 1
    assert remove_decision.action == replacement_workflow.REPLACEMENT_AWAIT_REMOVED
    assert remove_decision.items_to_remove_count == 1


def test_compare_replacement_quantities_uses_barcode_count_before_full_tray_qr_quantity():
    decision = replacement_workflow.compare_replacement_quantities(
        {
            "master_label_code": "PHS=1|CLC=AAA2270730100|QT=2",
            "item_code": "AAA2270730100",
            "product_barcodes": ["AAA2270730100-001"],
        },
        {"CLC": "AAA2270730100", "QT": "2"},
    )

    assert decision.action == replacement_workflow.REPLACEMENT_AWAIT_ADDITIONAL
    assert decision.old_qty == 1
    assert decision.new_qty == 2
    assert decision.items_needed == 1


def test_compare_replacement_quantities_rejects_invalid_new_quantity():
    decision = replacement_workflow.compare_replacement_quantities(
        {
            "master_label_code": "PHS=1|CLC=AAA2270730100|QT=2",
            "item_code": "AAA2270730100",
            "product_barcodes": ["AAA2270730100-001", "AAA2270730100-002"],
        },
        {"CLC": "AAA2270730100", "QT": "0"},
    )

    assert decision.action == replacement_workflow.REPLACEMENT_REJECT_NEW_QTY


def test_compare_replacement_quantities_rejects_unknown_old_quantity():
    decision = replacement_workflow.compare_replacement_quantities(
        {
            "master_label_code": "OLD-LABEL-WITHOUT-QTY",
            "item_code": "AAA2270730100",
            "product_barcodes": [],
        },
        {"CLC": "AAA2270730100", "QT": "60"},
    )

    assert decision.action == replacement_workflow.REPLACEMENT_REJECT_OLD_QTY
    assert decision.old_qty is None
    assert decision.new_qty == 60


def test_compare_replacement_quantities_rejects_conflicting_original_barcode_aliases():
    decision = replacement_workflow.compare_replacement_quantities(
        {
            "master_label_code": "PHS=1|CLC=AAA2270730100|QT=2",
            "item_code": "AAA2270730100",
            "product_barcodes": ["AAA2270730100-001"],
            "scanned_product_barcodes": ["AAA2270730100-002"],
        },
        {"CLC": "AAA2270730100", "QT": "2"},
    )

    assert decision.action == replacement_workflow.REPLACEMENT_REJECT_OLD_QTY
    assert decision.old_qty is None
    assert decision.new_qty == 2


def test_compare_replacement_quantities_rejects_malformed_original_barcode_aliases():
    decision = replacement_workflow.compare_replacement_quantities(
        {
            "master_label_code": "PHS=1|CLC=AAA2270730100|QT=2",
            "item_code": "AAA2270730100",
            "product_barcodes": ["AAA2270730100-001", 2],
        },
        {"CLC": "AAA2270730100", "QT": "2"},
    )

    assert decision.action == replacement_workflow.REPLACEMENT_REJECT_OLD_QTY
    assert decision.old_qty is None
    assert decision.new_qty == 2


def test_compare_replacement_quantities_rejects_duplicate_original_barcodes():
    decision = replacement_workflow.compare_replacement_quantities(
        {
            "master_label_code": "PHS=1|CLC=AAA2270730100|QT=2",
            "item_code": "AAA2270730100",
            "product_barcodes": ["AAA2270730100-001", "AAA2270730100-001"],
        },
        {"CLC": "AAA2270730100", "QT": "2"},
    )

    assert decision.action == replacement_workflow.REPLACEMENT_REJECT_OLD_QTY
    assert decision.old_qty is None
    assert decision.new_qty == 2


def test_compare_replacement_quantities_rejects_malformed_partial_flag():
    decision = replacement_workflow.compare_replacement_quantities(
        {
            "master_label_code": "PHS=1|CLC=AAA2270730100|QT=60",
            "item_code": "AAA2270730100",
            "product_barcodes": ["AAA2270730100-001", "AAA2270730100-002"],
            "is_partial_submission": "false",
        },
        {"CLC": "AAA2270730100", "QT": "2"},
    )

    assert decision.action == replacement_workflow.REPLACEMENT_REJECT_OLD_QTY
    assert decision.old_qty is None
    assert decision.new_qty == 2


def test_compare_replacement_quantities_uses_full_completion_barcode_count_when_qr_quantity_is_missing():
    decision = replacement_workflow.compare_replacement_quantities(
        {
            "master_label_code": "OLD-LABEL-WITHOUT-QTY",
            "item_code": "AAA2270730100",
            "product_barcodes": ["AAA2270730100-001", "AAA2270730100-002"],
        },
        {"CLC": "AAA2270730100", "QT": "2"},
    )

    assert decision.action == replacement_workflow.REPLACEMENT_FINALIZE
    assert decision.old_qty == 2
