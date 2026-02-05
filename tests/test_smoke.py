from alen.doctor import run_doctor

def test_doctor_runs():
    assert run_doctor() == 0
