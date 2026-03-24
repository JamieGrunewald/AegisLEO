from models.runtime_detector import RuntimeDetector


def test_runtime_detector_accepts_nominal_frame():
    detector = RuntimeDetector()

    frame = {
        "sequence": 10,
        "apid": 100,
        "payload": {
            "temp_c": 22.5,
            "bus_v": 5.02,
            "bus_i": 0.41,
            "state": "NOMINAL",
        },
    }

    result = detector.detect(frame)

    assert result.is_anomalous is False
    assert result.score == 0.0
    assert result.reasons == []


def test_runtime_detector_flags_bad_voltage():
    detector = RuntimeDetector()

    frame = {
        "sequence": 11,
        "apid": 100,
        "payload": {
            "temp_c": 22.5,
            "bus_v": 6.4,
            "bus_i": 0.41,
            "state": "NOMINAL",
        },
    }

    result = detector.detect(frame)

    assert result.is_anomalous is True
    assert "bus_voltage_out_of_range" in result.reasons