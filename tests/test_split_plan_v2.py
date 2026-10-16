"""Plan v2 on the NODE verifier: the identical endpoint case list as the backend
(backend/tests/test_split_plan_v2.py) and v1 refused -- the no-mixing property on both sides."""
import copy
import json
from pathlib import Path

import pytest

from meshembed_node import split_plan_verify as V

pytestmark = pytest.mark.unit
GOLD = json.loads((Path(__file__).parent / "fixtures" / "split_plan_golden.json").read_text())

ENDPOINT_CASES = [
    (None, True), ("93.184.216.34:51820", True), ("192.168.30.151:51820", True), ("172.16.0.5:51820", True),
    ("93.184.216.34:51821", False), ("93.184.216.34", False), ("10.44.0.5:51820", False),
    ("127.0.0.1:51820", False), ("169.254.1.1:51820", False), ("224.0.0.1:51820", False),
    ("0.0.0.0:51820", False), ("198.51.100.7:51820", False),
    ("[::1]:51820", False), ("093.184.216.34:51820", False), (51820, False), ("a.b.c.d:51820", False),
]


def test_the_case_list_is_identical_to_the_backends():
    import ast
    backend = Path(__file__).resolve().parents[2] / "backend" / "tests" / "test_split_plan_v2.py"
    if not backend.exists():
        pytest.skip("no backend tree here (the published node-agent repository / a release branch)")
    src = backend.read_text()
    tree = ast.parse(src)
    cases = next(ast.literal_eval(n.value) for n in tree.body
                   if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "ENDPOINT_CASES")
    assert cases == ENDPOINT_CASES


@pytest.mark.parametrize("ep,ok", ENDPOINT_CASES)
def test_endpoint_rule(ep, ok):
    assert V.endpoint_ok(ep) is ok


def _body(**kw):
    b = copy.deepcopy(GOLD["envelope"]["plan"])
    b.update(kw)
    return b


def test_a_v1_plan_is_refused_by_a_v2_node():
    with pytest.raises(V.PlanRejected, match="plan_schema_header"):
        V.validate_body(_body(v=1))


def test_a_v1_shaped_member_list_is_refused():
    b = _body()
    for m in b["members"]:
        m.pop("endpoint")
    with pytest.raises(V.PlanRejected, match="plan_schema_member_keys"):
        V.validate_body(b)
