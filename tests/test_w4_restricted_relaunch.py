"""W4 (0.3.87, design Rev 2, auditor GO fc9cc0cf W4-1..W4-4): decision table, backoff, supervision order. Windows calls are NOT run here
(spike + PB-W on 160); everything decidable runs through the `Api` seam with a fake."""
import pytest

from meshembed_node import restricted_relaunch as R
from meshembed_node.admin_token import ADMINS_ENABLED, INTEGRITY_HIGH, OK, COULD_NOT_CHECK

pytestmark = pytest.mark.unit
WIN = "win32"


@pytest.fixture(autouse=True)
def _reset_fallback_code():
    R._fallback_code = None
    yield
    R._fallback_code = None


@pytest.mark.parametrize("code,argv,paused,platform,want", [
    (ADMINS_ENABLED, [], False, WIN, True),
    (INTEGRITY_HIGH, [], False, WIN, True),
    (OK, [], False, WIN, False),
    (COULD_NOT_CHECK, [], False, WIN, False),
    (None, [], False, WIN, False),
    (ADMINS_ENABLED, [R.CHILD_FLAG], False, WIN, False),     # the flag, not the token, stops recursion
    (ADMINS_ENABLED, [], True, WIN, False),                  # paused: nothing spawned
    (ADMINS_ENABLED, [], False, "linux", False),
    (ADMINS_ENABLED, [], False, "darwin", False),
])
def test_decision_table(code, argv, paused, platform, want):
    assert R.should_relaunch(code, argv, paused, platform) is want


def test_backoff_schedule_1_5_30_then_doubling_capped_6h():
    assert [R.backoff_delay_s(n) for n in (1, 2, 3)] == [60, 300, 1800]
    assert R.backoff_delay_s(4) == 3600 and R.backoff_delay_s(5) == 7200
    assert R.backoff_delay_s(20) == R.BACKOFF_CAP_S == 6 * 3600
    assert R.backoff_delay_s(0) == 0


def test_a_clean_10_minute_run_resets_n_and_a_short_run_counts():
    s = R.State(n=3)
    R.record_child_run(s, 600, 1000.0)
    assert s.n == 0 and s.first_ok
    R.record_child_run(s, 30, 2000.0)
    assert s.n == 1 and s.at == 2000.0


def test_admin_fallback_only_before_the_first_success():
    assert R.admin_fallback_allowed(R.State()) is True
    assert R.admin_fallback_allowed(R.State(first_ok=True)) is False


def test_state_json_roundtrip_and_garbage_is_a_fresh_state():
    s = R.State(n=2, at=5.0, first_ok=True)
    assert R.State.from_json(s.to_json()) == s
    assert R.State.from_json("not json") == R.State()


class FakeApi(R.Api):
    def __init__(self, start_errors=(), exit_codes=(0,), state=None, pause_after=None):
        super().__init__()
        self.start_errors = list(start_errors)
        self.exit_codes = list(exit_codes)
        self.state = state or R.State()
        self.pause_after = pause_after
        self.waits = 0

    def prepare_parent(self):
        self.calls.append("prepare")

    def start_child(self):
        self.calls.append("start")
        if self.start_errors:
            raise self.start_errors.pop(0)
        return object()

    def wait_child(self, child):
        self.calls.append("wait")
        self.waits += 1
        return self.exit_codes.pop(0)

    def read_state(self):
        return R.State(self.state.n, self.state.at, self.state.first_ok)

    def write_state(self, state):
        self.calls.append("write_state")
        self.state = state

    def paused(self):
        return self.pause_after is not None and self.waits >= self.pause_after


def _clock():
    t = [1000.0]
    return (lambda: t[0]), (lambda s: t.__setitem__(0, t[0] + s)), t


def test_a_parent_side_failure_before_the_first_success_runs_in_process_as_0_3_86():
    api = FakeApi(start_errors=[R.RelaunchFailed("CreateRestrictedToken", 5)])
    now, sleep, _ = _clock()
    assert R.supervise(api, lambda: 42, now, sleep) == 42
    assert api.calls == ["prepare", "start"]


def test_a_parent_side_failure_after_the_first_success_never_runs_in_process():
    api = FakeApi(start_errors=[R.RelaunchFailed("CreateProcessAsUserW", 5)], exit_codes=[0],
                  state=R.State(n=0, at=0.0, first_ok=True))
    now, sleep, _ = _clock()
    ran = []
    assert R.supervise(api, lambda: ran.append(1) or 99, now, sleep, max_loops=3) == 0      # 2nd loop: child ok -> exit 0
    assert ran == []                                                                         # the admin daemon NEVER ran
    assert api.calls[:3] == ["prepare", "start", "write_state"]                             # backoff recorded, not fallback


def test_a_child_death_backs_off_and_restarts_the_child_never_the_admin_daemon():
    api = FakeApi(exit_codes=[1, 1, 0])
    now, sleep, t = _clock()
    slept = []
    ran = []
    assert R.supervise(api, lambda: ran.append(1) or 99, now, lambda s: (slept.append(s), sleep(s)), max_loops=6) == 0
    assert ran == [] and api.calls.count("start") == 3
    assert slept and slept[0] == pytest.approx(60, abs=1) and slept[1] == pytest.approx(300, abs=1)


def test_paused_before_start_exits_0_and_spawns_nothing():
    api = FakeApi(pause_after=0)
    now, sleep, _ = _clock()
    assert R.supervise(api, lambda: 1, now, sleep) == 0
    assert api.calls == []


def test_start_order_is_prepare_then_start_then_wait():
    api = FakeApi(exit_codes=[0])
    now, sleep, _ = _clock()
    R.supervise(api, lambda: 1, now, sleep)
    assert api.calls[:3] == ["prepare", "start", "wait"]


def test_maybe_relaunch_none_unless_windows_parent_with_admin_token():
    called = []
    kw = dict(api_factory=lambda: called.append(1) or FakeApi(exit_codes=[0]), run_in_process=lambda: 7)
    assert R.maybe_relaunch([], platform="linux", check=lambda: ADMINS_ENABLED, **kw) is None
    assert R.maybe_relaunch([R.CHILD_FLAG], platform=WIN, check=lambda: ADMINS_ENABLED, **kw) is None
    assert R.maybe_relaunch([], platform=WIN, check=lambda: OK, **kw) is None
    assert called == []


def test_mutation_the_child_flag_check_is_what_prevents_recursion():
    """Drop the flag check and the child (same admin-looking decision inputs) would relaunch again: prove the check is load-bearing."""
    assert R.should_relaunch(ADMINS_ENABLED, [R.CHILD_FLAG], False, WIN) is False
    assert R.should_relaunch(ADMINS_ENABLED, [], False, WIN) is True        # same inputs minus the flag -> relaunch
    src = open(R.__file__, encoding="utf-8").read()
    assert "if CHILD_FLAG in argv:" in src


# ---- W4-Q2 (auditor GO 09:29:27Z): own key + closed tuple; garbage never reported verbatim; admin_token keeps its 4 codes ----
def test_q2_the_relaunch_codes_are_a_separate_tuple_and_admin_token_keeps_its_four():
    from meshembed_node import admin_token as AT
    assert R.HW_KEY == "admin_relaunch" and R.HW_KEY != "admin_token"
    assert AT.CODES == ("ok", "admins_enabled", "integrity_high", "could_not_check")
    assert R.RELAUNCH_FAILED not in AT.CODES and R.RELAUNCH_BACKOFF not in AT.CODES


@pytest.mark.parametrize("raw,want", [
    ("restricted_ok", "restricted_ok"),
    ("relaunch_backoff", "relaunch_backoff"),
    ("relaunch_failed", "relaunch_failed"),
    ("relaunch_failed:CreateRestrictedToken:5", "relaunch_failed"),          # the detail stays in the local log
    ("could_not_check", "could_not_check"),
    ("C:\\Users\\x\\secret.txt", "could_not_check"),                         # a path
    ("Traceback (most recent call last)", "could_not_check"),                # an exception string
    ("restricted_ok:extra", "could_not_check"),
    ("RESTRICTED_OK", "could_not_check"),
    ("", "could_not_check"), (None, "could_not_check"), (5, "could_not_check"), (["restricted_ok"], "could_not_check"),
])
def test_q2_the_child_reports_only_a_value_of_the_tuple(raw, want):
    got = R.reportable(raw)
    assert got == want and got in R.CODES


# ---- S2-c / S2-d (auditor 09:57:06Z): the lock SDDL and the atomic, verified state dir ----
def test_s2c_the_parent_process_sddl_limits_the_owner_to_read_control():
    assert R.PARENT_PROCESS_SDDL == "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;RC;;;OW)"
    assert "(A;;RC;;;OW)" in R.PARENT_PROCESS_SDDL and "GA;;;OW" not in R.PARENT_PROCESS_SDDL
    assert R.PARENT_PROCESS_SDDL.startswith("D:P")                       # protected: no inheritance


@pytest.mark.parametrize("exists,owner,sddl,want", [
    (False, None, None, "create"),
    (True, "S-1-5-18", R.STATE_DIR_SDDL, "ok"),
    (True, "S-1-5-32-544", R.STATE_DIR_SDDL, "ok"),
    (True, "S-1-5-21-1-2-3-1001", R.STATE_DIR_SDDL, "refused:state_dir_owner"),     # pre-created by the node user
    (True, None, R.STATE_DIR_SDDL, "refused:state_dir_owner"),
    (True, "S-1-5-18", "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;S-1-5-21-1-2-3-1001)", "refused:state_dir_acl"),
    (True, "S-1-5-32-544", None, "refused:state_dir_acl"),
])
def test_s2d_an_existing_state_dir_is_accepted_only_with_a_trusted_owner_and_the_exact_dacl(exists, owner, sddl, want):
    assert R.state_dir_decision(exists, owner, sddl) == want


def test_s2d_the_state_dir_sddl_names_only_system_and_administrators():
    assert R.STATE_DIR_SDDL == "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    assert "WD" not in R.STATE_DIR_SDDL and "BU" not in R.STATE_DIR_SDDL and "AU" not in R.STATE_DIR_SDDL


# ---- auditor 10:15:14Z product note: the child's TokenDefaultDacl is SYSTEM + the node user, never Administrators ----
def test_child_default_dacl_is_system_plus_the_user_and_never_administrators():
    sddl = R.child_default_dacl_sddl("S-1-5-21-1-2-3-1001")
    assert sddl == "D:(A;;GA;;;SY)(A;;GA;;;S-1-5-21-1-2-3-1001)"
    assert "BA" not in sddl and "S-1-5-32-544" not in sddl


@pytest.mark.parametrize("bad", ["S-1-5-18", "S-1-5-32-544", "BA", "", None, "S-1-5-21-1-2-3-1001)(A;;GA;;;WD"])
def test_child_default_dacl_refuses_anything_but_an_account_sid(bad):
    with pytest.raises(ValueError):
        R.child_default_dacl_sddl(bad)


# ---- wiring: the child's command line, its closed report value, the parser flags, the worker key ----
def test_child_cmdline_carries_the_flag_and_only_a_closed_code():
    cmd = R.child_cmdline("C:\\Python312\\pythonw.exe", "restricted_ok")
    assert cmd.endswith("-m meshembed_node run --restricted-child --admin-relaunch=restricted_ok")
    assert "--admin-relaunch=could_not_check" in R.child_cmdline("p.exe", "C:\\evil path")          # anything outside the tuple is replaced
    assert " " not in R.child_cmdline("p.exe", "x y").split("--admin-relaunch=")[1]


def test_child_report_validates_what_the_parent_passed():
    f = R.CHILD_FLAG
    assert R.child_report([]) is None and R.child_report(["run"]) is None                        # not a restricted child: no key sent at all
    assert R.child_report([f, "--admin-relaunch=restricted_ok"]) == "restricted_ok"
    assert R.child_report([f, "--admin-relaunch=relaunch_backoff"]) == "relaunch_backoff"
    assert R.child_report([f, "--admin-relaunch=garbage C:\\x"]) == "could_not_check"
    assert R.child_report([f]) == "could_not_check"


def test_state_dir_dacl_comparison_ignores_ace_order_only():
    swapped = "D:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)"
    assert R.state_dir_decision(True, "S-1-5-18", swapped) == "ok"
    assert R.state_dir_decision(True, "S-1-5-18", "D:AI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)") == "refused:state_dir_acl"      # different flags


def test_main_wires_the_relaunch_after_the_pause_check_and_registers_the_hidden_flags():
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "meshembed_node" / "__main__.py").read_text(encoding="utf-8")
    assert src.index('_pause.enforce("start")\n\n    def _in_process') < src.index("_relaunch.maybe_relaunch(sys.argv")
    assert '"--restricted-child"' in src and '"--admin-relaunch"' in src and "argparse.SUPPRESS" in src


def test_worker_reports_the_relaunch_value_under_its_own_key_never_in_admin_token():
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "meshembed_node" / "worker.py").read_text(encoding="utf-8")
    assert "hw[_rr.HW_KEY] = _rrc" in src and 'hw["admin_token"] = _atc' in src and "_rr.HW_KEY" in src
    assert 'hw["admin_token"] = _rrc' not in src


# ---- auditor 10:36:09Z early read of #221: W4-A (no crash of the parent), W4-B (first_ok only after a >= 10 min run), W4-C (fallback reports), W4-E ----
class BoomApi(FakeApi):
    def __init__(self, start_exc=None, write_exc=None, **kw):
        super().__init__(**kw)
        self.start_exc, self.write_exc = start_exc, write_exc

    def start_child(self):
        self.calls.append("start")
        if self.start_exc is not None:
            raise self.start_exc
        return object()

    def write_state(self, state):
        if self.write_exc is not None:
            raise self.write_exc
        super().write_state(state)


@pytest.mark.parametrize("exc", [TypeError("argtypes"), OSError("boom"), ValueError("x")])
def test_wa_any_exception_in_start_is_a_parent_side_failure_not_a_crash(exc):
    api = BoomApi(start_exc=exc)
    now, sleep, _ = _clock()
    R._fallback_code = None
    assert R.supervise(api, lambda: 42, now, sleep) == 42          # before the first success: the in-process fallback, no exception escapes
    assert R._fallback_code == R.RELAUNCH_FAILED
    R._fallback_code = None


def test_wa_after_a_first_success_an_exception_backs_off_and_never_runs_in_process():
    api = BoomApi(start_exc=OSError("boom"), exit_codes=[0], state=R.State(first_ok=True))
    now, sleep, _ = _clock()
    ran = []
    # the first loop raises (backoff recorded), the second also raises: bound the loops; the admin daemon must never run
    assert R.supervise(api, lambda: ran.append(1) or 9, now, sleep, max_loops=3) == 1
    assert ran == []


def test_wa_a_state_write_error_never_escapes():
    api = BoomApi(write_exc=R.RelaunchFailed("refused:state_dir_owner", 0), exit_codes=[0])
    now, sleep, _ = _clock()
    assert R.supervise(api, lambda: 1, now, sleep) == 0            # the child ended cleanly; the write error was logged, not raised


def test_wb_first_ok_only_after_a_ten_minute_run():
    s = R.State()
    R.record_child_run(s, 2, 100.0)
    assert s.first_ok is False and s.n == 1                        # a 2-second death is NOT a first success
    R.record_child_run(s, R.CLEAN_RUN_RESET_S, 200.0)
    assert s.first_ok is True and s.n == 0


def test_wc_the_in_process_fallback_reports_relaunch_failed_and_a_normal_start_reports_nothing():
    R._fallback_code = None
    assert R.child_report(["run"]) is None
    R._fallback_code = R.RELAUNCH_FAILED
    assert R.child_report(["run"]) == "relaunch_failed" and R.child_report(["run"]) in R.CODES
    R._fallback_code = None


def test_we_the_module_docstring_no_longer_says_the_codes_join_admin_token():
    assert "added to the admin_token vocabulary" not in (R.__doc__ or "")


# ---- auditor 10:46:30Z: W4-F (a failing state write must not reset the backoff), W4-G (wait_child errors) ----
class AlwaysFailWriteApi(FakeApi):
    def write_state(self, state):
        raise R.RelaunchFailed("refused:state_dir_owner", 0)


def test_wf_when_every_state_write_fails_the_backoff_still_follows_60_300_1800():
    api = AlwaysFailWriteApi(exit_codes=[1, 1, 1, 1])
    now, sleep, t = _clock()
    slept = []
    R.supervise(api, lambda: 99, now, lambda s: (slept.append(round(s)), sleep(s)), max_loops=4)
    assert slept[:3] == [60, 300, 1800]
    assert api.calls.count("start") == 4 and "write_state" not in api.calls      # the failing writes never reset n


class WaitBoomApi(FakeApi):
    def wait_child(self, child):
        self.calls.append("wait")
        raise OSError("ctypes")


def test_wg_a_wait_child_error_is_a_child_death_not_a_crash():
    api = WaitBoomApi()
    now, sleep, _ = _clock()
    ran = []
    assert R.supervise(api, lambda: ran.append(1) or 9, now, sleep, max_loops=2) == 1       # bounded; no exception escapes
    assert ran == [] and api.calls.count("start") >= 1


# ---- auditor 14:54:54Z W4-H: a child exit 3 (self-update applied / owner restart) is passed on to the task, never a death ----
def test_wh_child_exit_3_makes_the_parent_exit_3_at_once_with_no_backoff_and_no_state_write():
    api = FakeApi(exit_codes=[3, 0])
    now, sleep, _ = _clock()
    slept = []
    ran = []
    assert R.supervise(api, lambda: ran.append(1) or 9, now, lambda s: slept.append(s), max_loops=5) == 3
    assert slept == [] and ran == []                                   # no sleep, never the admin daemon
    assert api.calls.count("start") == 1 and "write_state" not in api.calls     # not counted as a death, nothing persisted
    assert api.state.n == 0


def test_wh_other_nonzero_codes_are_still_deaths():
    api = FakeApi(exit_codes=[1, 0])
    now, sleep, _ = _clock()
    assert R.supervise(api, lambda: 9, now, sleep, max_loops=4) == 0
    assert api.calls.count("start") == 2 and "write_state" in api.calls


def test_wh_the_constant_matches_the_worker_exit_sites():
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "meshembed_node" / "worker.py").read_text(encoding="utf-8")
    assert R.RELAUNCH_ME_EXIT == 3 and "_sys.exit(3)" in src and "_exit(3)" in src
