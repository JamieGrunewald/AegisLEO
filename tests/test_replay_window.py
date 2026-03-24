from groundstation.replay_window import ReplayWindow


def test_first_packet_is_accepted():
    rw = ReplayWindow(window_size=8)
    assert rw.accept(0) is True
    assert rw.max_seq == 0


def test_strictly_increasing_sequences_are_accepted():
    rw = ReplayWindow(window_size=8)
    assert rw.accept(10) is True
    assert rw.accept(11) is True
    assert rw.accept(12) is True
    assert rw.max_seq == 12


def test_duplicate_is_rejected():
    rw = ReplayWindow(window_size=8)
    assert rw.accept(5) is True
    assert rw.accept(5) is False


def test_out_of_order_within_window_is_accepted_once():
    rw = ReplayWindow(window_size=8)
    assert rw.accept(10) is True
    assert rw.accept(12) is True
    assert rw.accept(11) is True
    assert rw.accept(11) is False


def test_too_old_packet_is_rejected():
    rw = ReplayWindow(window_size=4)
    assert rw.accept(10) is True
    assert rw.accept(11) is True
    assert rw.accept(12) is True
    assert rw.accept(13) is True

    # Window is now [10..13]
    assert rw.accept(9) is False


def test_large_forward_jump_resets_window_history():
    rw = ReplayWindow(window_size=8)
    assert rw.accept(1) is True
    assert rw.accept(2) is True
    assert rw.accept(50) is True

    state = rw.debug_state()
    assert state["max_seq"] == 50

    # 50 already seen
    assert rw.accept(50) is False

    # Very old packets are out
    assert rw.accept(2) is False


def test_check_reports_reason_without_mutating_state():
    rw = ReplayWindow(window_size=8)

    first = rw.check(7)
    assert first.accepted is True
    assert first.reason == "first_packet"
    assert rw.max_seq == -1

    assert rw.accept(7) is True

    dup = rw.check(7)
    assert dup.accepted is False
    assert dup.reason == "duplicate"
    assert rw.max_seq == 7