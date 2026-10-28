"""M8 evaluator (auditor A8: T1-T9 + K1-K8). Every input here is what a hostile document could make the model write."""
import json
import subprocess
import sys

import pytest

from meshembed_node import tools_eval as E


def ev(name, args, block=None):
    return E.evaluate(name, E.parse_arguments(name, json.dumps(args)), block)


def calc(expr):
    return ev("calc", {"expression": expr})


# --- K1: closed schemas -------------------------------------------------------------------------------------------
@pytest.mark.parametrize("name,raw,code", [
    ("python", '{"expression": "1"}', "unknown_tool"),
    (None, "{}", "unknown_tool"),
    ("calc", "[1, 2]", "bad_arguments"),
    ("calc", "{not json", "bad_arguments"),
    ("calc", "{}", "missing_argument"),
    ("calc", '{"expression": "1", "x": 1}', "unexpected_argument"),
    ("calc", '{"expression": 1}', "bad_argument_type"),
    ("calc", '{"expression": true}', "bad_argument_type"),
    ("table", '{"op": "sum", "table": true}', "bad_argument_type"),
    ("table", '{"op": "sum", "table": 1.5}', "bad_argument_type"),
    ("dates", '{"op": "weekday", "date": "2026-10-23", "n": "3"}', "bad_argument_type"),
    ("calc", json.dumps({"expression": "1+" * 3000}), "arguments_too_large"),
    ("calc", "[" * 3000, "bad_arguments"),            # nesting: RecursionError in json, caught
])
def test_k1_closed_schema(name, raw, code):
    with pytest.raises(E.ToolError) as ei:
        E.parse_arguments(name, raw)
    assert ei.value.code == code


# --- K2: calc -----------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("expr,want", [
    ("1 + 2 * 3", "7"),
    ("(1 + 2) * 3", "9"),
    ("10 / 4", "2.5"),
    ("0.1 + 0.2", "0.3"),                                # Decimal, not float
    ("-3 + +5", "2"),
    ("--2", "2"),
    ("15%", "0.15"),
    ("200 * 21%", "42.00"),
    ("round(2.675, 2)", "2.68"),                         # half-up (EUR), float would give 2.67
    ("round(2.5)", "3"),
    ("round(-2.5)", "-3"),
    ("round(1250.40 * 3 * 1.21, 2)", "4538.95"),
    ("sum(1, 2, 3.5)", "6.5"),
    ("sum([1, 2], 3)", "6"),
    ("avg(1, 2)", "1.5"),
    ("min(3, -1, 2)", "-1"),
    ("max([4, 9, 2])", "9"),
    ("abs(-7.25)", "7.25"),
    ("3 × 4 − 1", "11"),
    ("12 ÷ 4", "3"),
    (".5 * 2", "1.0"),
    ("ROUND(1.005, 2)", "1.01"),
])
def test_calc_values(expr, want):
    assert calc(expr) == {"result": want}


@pytest.mark.parametrize("expr,code", [
    ("", "bad_expression"),
    ("1 +", "bad_expression"),
    ("(1 + 2", "bad_expression"),
    ("1 2", "bad_expression"),
    ("2 ** 10", "bad_expression"),                        # no power operator (K2)
    ("2 ^ 10", "bad_expression"),
    ("1e10", "unknown_function"),                         # no exponent literals
    ("__import__('os')", "bad_expression"),
    ("eval(1)", "unknown_function"),
    ("pow(2, 3)", "unknown_function"),
    ("1; 2", "bad_expression"),
    ("1 / 0", "division_by_zero"),
    ("1 / (2 - 2)", "division_by_zero"),
    ("round(1, 11)", "bad_function_arguments"),           # n 0..10 (K2: a huge n makes quantize allocate)
    ("round(1, 99999999)", "bad_function_arguments"),
    ("round(1, -1)", "bad_function_arguments"),
    ("round(1, 1.5)", "bad_function_arguments"),
    ("round([1, 2])", "bad_function_arguments"),
    ("abs(1, 2)", "bad_function_arguments"),
    ("1 + [2]", "bad_expression"),
    ("9" * 41, "number_too_long"),
    ("1" * 31, "result_too_large"),                       # every value bounded, literals included
    ("100000000000000000 * 100000000000000000", "result_too_large"),   # an intermediate over 1e30
    ("(100000000000000000 * 100000000000000000) / 1000000000", "result_too_large"),
    ("1+" * 150 + "1", "expression_too_complex"),         # AST node cap
    ("(" * 40 + "1" + ")" * 40, "expression_too_deep"),
    ("-" * 40 + "1", "expression_too_deep"),
    ("sum(" + ",".join(["1"] * 101) + ")", "list_too_long"),
    ("1 + " * 200 + "1", "expression_too_long"),
    ("1" * 10 + "+" + "x" * 600, "expression_too_long"),
    ("１ + 1", "bad_expression"),                     # full-width digit: not an ASCII number
    ("1 + ١", "bad_expression"),                     # Arabic-Indic digit
])
def test_calc_errors(expr, code):
    assert calc(expr) == {"error": code}


def test_calc_long_chain_under_caps_is_fine():
    assert calc("+".join(["1"] * 100)) == {"result": "100"}


def test_calc_tiny_values_do_not_explode():
    out = calc("1 / 3 / 1000000000000000000000000000000")
    assert "error" not in out and len(out["result"]) <= E.RESULT_MAX_CHARS


# --- K3: table ----------------------------------------------------------------------------------------------------
T = "item,units,price,region\nA,3,10.50,north\nB,2,4.25,south\nC,,7,north\nD,5,1,south\n"


@pytest.mark.parametrize("args,want", [
    ({"op": "sum", "column": "units"}, "10"),
    ({"op": "avg", "column": "units"}, "3." + "3" * 49),                     # prec 50
    ({"op": "count"}, "4"),
    ({"op": "count", "column": "units"}, "3"),
    ({"op": "max", "column": "price"}, "10.50"),
    ({"op": "min", "column": "price"}, "1"),
    ({"op": "argmax", "column": "price", "label": "item"}, json.dumps({"value": "10.50", "label": "A"})),
    ({"op": "argmin", "column": "units", "label": "item"}, json.dumps({"value": "2", "label": "B"})),
    ({"op": "sum_product", "column": "units", "column2": "price"}, "45.00"),
    ({"op": "sum", "column": "units", "where": [{"column": "region", "cmp": "=", "value": "north"}]}, "3"),
    ({"op": "sum", "column": "units", "where": [{"column": "region", "cmp": "!=", "value": "north"}]}, "7"),
    ({"op": "count", "where": [{"column": "price", "cmp": ">", "value": 5}]}, "2"),
    ({"op": "count", "where": [{"column": "price", "cmp": "<=", "value": "4.25"}]}, "2"),
    ({"op": "sum", "column": "units", "where": [{"column": "region", "cmp": "=", "value": "south"},
                                                {"column": "price", "cmp": ">=", "value": 2}]}, "2"),
])
def test_table_values(args, want):
    assert ev("table", args, T) == {"result": want}


def test_table_semicolon_and_decimal_comma():
    t = "item;amount\nA;1,50\nB;2,25\n"
    assert ev("table", {"op": "sum", "column": "amount", "delimiter": ";", "decimal": ","}, t) == {"result": "3.75"}
    # the separator is the one the call names, never guessed: "1,50" read with "." is not a number
    assert ev("table", {"op": "sum", "column": "amount", "delimiter": ";"}, t) == {"error": "not_a_number"}


@pytest.mark.parametrize("args,block,code", [
    ({"op": "sum", "column": "units"}, None, "no_table"),
    ({"op": "sum", "column": "nope"}, T, "unknown_column"),
    ({"op": "sum"}, T, "missing_argument"),
    ({"op": "sum", "column": "item"}, T, "not_a_number"),
    ({"op": "argmax", "column": "units"}, T, "missing_argument"),
    ({"op": "median", "column": "units"}, T, "bad_argument_value"),
    ({"op": "sum", "column": "units", "delimiter": "|"}, T, "bad_argument_value"),
    ({"op": "sum", "column": "units", "decimal": ","}, T, "bad_argument_value"),    # "," with "," delimiter
    ({"op": "sum", "column": "units", "where": [{"column": "x", "cmp": "=", "value": "a"}]}, T, "unknown_column"),
    ({"op": "sum", "column": "units", "where": [{"column": "item", "cmp": "~", "value": "a"}]}, T,
     "bad_argument_value"),
    ({"op": "sum", "column": "units", "where": [{"column": "item", "cmp": "=", "value": "a", "x": 1}]}, T,
     "bad_argument_value"),
    ({"op": "sum", "column": "units", "where": [{"column": "item", "cmp": "=", "value": True}]}, T,
     "bad_argument_value"),
    ({"op": "sum", "column": "units", "where": [{"column": "item", "cmp": "=", "value": "a"}] * 5}, T,
     "bad_argument_value"),
    ({"op": "sum", "column": "units", "where": [{"column": "region", "cmp": "=", "value": "west"}]}, T, "no_rows"),
])
def test_table_errors(args, block, code):
    assert ev("table", args, block) == {"error": code}


@pytest.mark.parametrize("block,code", [               # the B5 negative / fuzz set: each ends in a closed code
    ('a,b\n"1,2\n', "bad_table"),                         # unterminated quote
    ('a,b\n"1"x,2\n', "bad_table"),                       # text after a closing quote (strict)
    ("a,b\n1,2,3\n", "bad_table"),                        # ragged row
    ("a,b\n1\n", "bad_table"),
    ("a,a\n1,2\n", "bad_table"),                          # duplicate header
    (",b\n1,2\n", "bad_table"),                           # empty header
    ("a,b\n1,\x002\n", "bad_table"),                      # NUL byte
    ("a,b\n1,\udcff\n", "bad_table"),                     # a lone surrogate (an undecodable byte)
    ("a,b\n" + "x" * (E.TABLE_MAX_CELL + 1) + ",1\n", "bad_table"),          # huge field
    ("a,b\n" + "1,2\n" * (E.TABLE_MAX_ROWS + 2), "table_too_large"),
    (",".join(f"c{i}" for i in range(E.TABLE_MAX_COLS + 1)) + "\n", "table_too_large"),
    ("a\n" + "1\n" * (E.TABLE_MAX_BYTES // 2 + 1), "table_too_large"),
    ("", "bad_table"),
    ("\n\n\n", "bad_table"),
])
def test_table_fuzz_set(block, code):
    assert ev("table", {"op": "sum", "column": "b"}, block) == {"error": code}


@pytest.mark.parametrize("cell", ["1,000", "1e3", "EUR 5", "5 EUR", "0x10", "1_000", "--1", "1.2.3", "５", "5.",
                                  "NaN", "inf", "٥"])
def test_table_strict_numbers(cell):
    assert ev("table", {"op": "sum", "column": "b"}, f"a,b\nx,\"{cell}\"\n") == {"error": "not_a_number"}


def test_table_cells_are_data_not_formulas():
    out = ev("table", {"op": "argmax", "column": "b", "label": "a"}, 'a,b\n"=HYPERLINK(""x"")",3\n')
    assert out == {"result": json.dumps({"value": "3", "label": '=HYPERLINK("x")'})}


def test_table_crlf_and_blank_lines():
    assert ev("table", {"op": "sum", "column": "b"}, "a,b\r\n\r\nx,1\r\ny,2\r\n") == {"result": "3"}


# --- K4: dates ----------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("args,want", [
    ({"op": "weekday", "date": "2026-10-23"}, "Friday"),
    ({"op": "add_days", "date": "2026-02-27", "n": 2}, "2026-03-01"),
    ({"op": "add_days", "date": "2026-03-01", "n": -1}, "2026-02-28"),
    ({"op": "days_between", "date": "2026-01-01", "date2": "2026-12-31"}, "364"),
    ({"op": "days_between", "date": "2026-12-31", "date2": "2026-01-01"}, "-364"),
    ({"op": "add_business_days", "date": "2026-10-23", "n": 1}, "2026-10-26"),             # Fri + 1 = Mon
    ({"op": "add_business_days", "date": "2026-10-23", "n": 0}, "2026-10-23"),
    ({"op": "add_business_days", "date": "2026-10-26", "n": -1}, "2026-10-23"),
    ({"op": "add_business_days", "date": "2026-12-23", "n": 3, "holidays": ["2026-12-25", "2026-12-24"]},
     "2026-12-30"),
    ({"op": "business_days_between", "date": "2026-10-23", "date2": "2026-10-30"}, "5"),
    ({"op": "business_days_between", "date": "2026-10-30", "date2": "2026-10-23"}, "-5"),
    ({"op": "add_business_days", "date": "2026-01-01", "n": 3650}, "2039-12-29"),
])
def test_dates_values(args, want):
    assert ev("dates", args) == {"result": want}


@pytest.mark.parametrize("args,code", [
    ({"op": "weekday", "date": "23/10/2026"}, "bad_date"),
    ({"op": "weekday", "date": "2026-02-30"}, "bad_date"),
    ({"op": "weekday", "date": "2026-1-01"}, "bad_date"),
    ({"op": "weekday", "date": "２026-01-01"}, "bad_date"),
    ({"op": "weekday", "date": "1899-12-31"}, "date_out_of_range"),
    ({"op": "add_days", "date": "2199-12-31", "n": 1}, "date_out_of_range"),
    ({"op": "add_days", "date": "2026-01-01", "n": 3651}, "bad_argument_value"),
    ({"op": "add_days", "date": "2026-01-01"}, "missing_argument"),
    ({"op": "days_between", "date": "2026-01-01"}, "missing_argument"),
    ({"op": "easter", "date": "2026-01-01"}, "bad_argument_value"),
    ({"op": "add_business_days", "date": "2026-01-01", "n": 1, "holidays": ["2026-01-02"] * 101},
     "too_many_holidays"),
    ({"op": "add_business_days", "date": "2026-01-01", "n": 1, "holidays": ["tomorrow"]}, "bad_date"),
    ({"op": "add_business_days", "date": "2026-01-01", "n": 1, "holidays": [20260102]}, "bad_date"),
    ({"op": "business_days_between", "date": "1900-01-01", "date2": "2199-01-01"}, "date_out_of_range"),
])
def test_dates_errors(args, code):
    assert ev("dates", args) == {"error": code}


# --- results bounded (K6), never a trace (T7) ---------------------------------------------------------------------
def test_results_are_bounded_and_closed():
    label = "x" * 900
    out = ev("table", {"op": "argmax", "column": "b", "label": "a"}, f"a,b\n{label},1\n")
    assert len(out["result"]) <= E.RESULT_MAX_CHARS
    assert set(E.evaluate("calc", {"expression": None})) == {"error"}       # a bug path: closed code
    assert E.evaluate("calc", {"expression": None})["error"] in E.CODES


# --- K5: the child process ----------------------------------------------------------------------------------------
def _child(payload: bytes, timeout=10):
    return subprocess.run([sys.executable, "-I", str(E.__file__)], input=payload, capture_output=True,
                          timeout=timeout, cwd="/")


def test_child_round_trip_and_revalidates():
    p = _child(json.dumps({"tool": "calc", "args": {"expression": "2*21"}}).encode())
    assert p.returncode == 0 and json.loads(p.stdout) == {"result": "42"}
    p = _child(json.dumps({"tool": "calc", "args": {"expression": "1", "evil": 1}}).encode())
    assert json.loads(p.stdout) == {"error": "unexpected_argument"}
    p = _child(json.dumps({"tool": "shell", "args": {}}).encode())
    assert json.loads(p.stdout) == {"error": "unknown_tool"}
    p = _child(b"\xff\xfe not json")
    assert json.loads(p.stdout) == {"error": "tool_failed"}
    p = _child(b"x" * (E.CHILD_INPUT_MAX + 10))
    assert json.loads(p.stdout) == {"error": "arguments_too_large"}


def test_child_sets_its_limits_before_reading():
    code = ("import resource, sys; sys.argv=['x']; import importlib.util as u;"
            f"s=u.spec_from_file_location('te', {str(E.__file__)!r}); m=u.module_from_spec(s); s.loader.exec_module(m);"
            "m._limit_self(); g=resource.getrlimit;"
            "print(g(resource.RLIMIT_CPU), g(resource.RLIMIT_AS), g(resource.RLIMIT_FSIZE), g(resource.RLIMIT_NPROC),"
            "g(resource.RLIMIT_NOFILE), g(resource.RLIMIT_CORE))")
    p = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=10)
    assert p.stdout.strip() == ("(2, 2) (536870912, 536870912) (0, 0) (0, 0) (8, 8) (0, 0)"), p.stderr


def test_child_imports_stdlib_only():
    src = open(E.__file__).read()
    imports = {ln.split()[1].split(".")[0] for ln in src.splitlines() if ln.startswith(("import ", "from "))}
    assert imports <= {"__future__", "csv", "io", "json", "os", "sys", "datetime", "decimal", "typing"}
    assert "import resource" in src and "import ctypes" in src     # inside _limit_self / _seccomp_self only


# --- auditor 07:30Z FIX 2: seccomp in the child -------------------------------------------------------------------
_SANDBOXED = ("import importlib.util as u, sys; s = u.spec_from_file_location('te', sys.argv[1]);"
              "m = u.module_from_spec(s); s.loader.exec_module(m); m._limit_self(); m._seccomp_self();"
              "sys.stdout.write('sandboxed\\n'); sys.stdout.flush();")


def _sandboxed(code, *args):
    return subprocess.run([sys.executable, "-I", "-c", _SANDBOXED + code, str(E.__file__), *args],
                          capture_output=True, text=True, timeout=10)


def test_child_cannot_read_the_node_key(tmp_path):
    key = tmp_path / ".env"
    key.write_text("MESHEMBED_NODE_API_KEY=msh_node_SECRET\n")
    key.chmod(0o600)                                          # readable by this uid, as the daemon's .env is
    p = _sandboxed("print(open(sys.argv[2]).read())", str(key))
    assert p.stdout == "sandboxed\n" and "SECRET" not in p.stdout + p.stderr
    assert p.returncode == -31                                # SIGSYS: killed on the open()


@pytest.mark.parametrize("code", [
    "import socket; socket.socket()",
    "import os; os.execv('/bin/true', ['true'])",
    "import os; os.write(5, b'x')",                           # write on an fd other than 1/2
    "import os; os.read(1, 1)",                               # read on an fd other than 0
    "import os; os.getpid(); os.kill(1, 0)",
])
def test_child_is_killed_on_any_other_syscall(code):
    p = _sandboxed(code)
    assert p.stdout == "sandboxed\n" and p.returncode == -31


def test_bpf_program_shape():
    for machine, (arch, nr) in E._ARCH.items():
        prog = E._bpf(arch, nr)
        assert prog[0] == (0x20, 0, 0, 4) and prog[1][3] == arch          # architecture checked first
        assert prog[-1] == (0x06, 0, 0, 0x80000000)                      # default: KILL_PROCESS
        assert set(nr) == set(E.SECCOMP_PLAIN) | {"read", "write"}


def test_child_fails_closed_without_seccomp(monkeypatch):
    monkeypatch.setattr(E, "_ARCH", {})
    with pytest.raises(OSError):
        E._seccomp_self()


@pytest.mark.parametrize("raw", ['{"expression": NaN}', '{"expression": Infinity}', '{"op": "x", "n": -Infinity}'])
def test_nan_and_infinity_are_refused(raw):
    with pytest.raises(E.ToolError) as ei:
        E.parse_arguments("calc", raw)
    assert ei.value.code == "bad_arguments"
