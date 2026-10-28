"""M8 (auditor A8 design GO 2026-10-23 05:43Z; build requirements T1-T9 + K1-K8): the evaluator of the three
built-in tools the serving model may call -- calc, table, dates. OUR code computes; the model only names the
operation and its arguments.

Every argument is MODEL OUTPUT, and the model reads the customer's document, so every argument is hostile (T1):
  - closed tool schemas: exactly calc / table / dates, fixed argument names and types; anything else is a closed
    error code, never "best effort" (K1);
  - no eval / exec / ast: calc is a hand-written tokenizer + recursive-descent parser into a small AST, evaluated in
    Decimal under an explicit context (K2);
  - table reads only a CSV block of the SAME request with stdlib csv, bounded (K3);
  - dates use the stdlib only, bounded ranges and a bounded loop (K4);
  - errors are closed codes (CODES); results are bounded in size (K6).

Isolation (K5, T6): every call runs in a CHILD process (`python -I <this file>`), which sets RLIMIT_CPU / AS / FSIZE /
NOFILE / NPROC / CORE before it reads its input, and the parent kills it on a wall-clock limit. On top of that the code
is bounded by construction: every loop runs over a capped input. The child has no filesystem, network or subprocess
use by construction (stdlib arithmetic, csv, datetime only).

This file imports the standard library ONLY: it runs as a standalone script, with no package import.
"""
from __future__ import annotations

import csv
import io
import json
import os
import sys
from datetime import date, timedelta
from decimal import (ROUND_HALF_UP, Context, Decimal, DivisionByZero, InvalidOperation, Overflow,
                     localcontext)
from typing import Any, Dict, List, Optional, Tuple

TOOLS = ("calc", "table", "dates")
CODES = frozenset({
    "unknown_tool", "bad_arguments", "missing_argument", "unexpected_argument", "bad_argument_type",
    "bad_argument_value", "arguments_too_large",
    "bad_expression", "expression_too_long", "expression_too_deep", "expression_too_complex", "number_too_long",
    "unknown_function", "bad_function_arguments", "list_too_long", "division_by_zero", "invalid_operation",
    "result_too_large",
    "no_table", "bad_table", "table_too_large", "unknown_column", "not_a_number", "no_rows",
    "bad_date", "date_out_of_range", "too_many_holidays",
    "tool_timeout", "tool_failed", "result_too_long", "too_many_calls",
})

# --- limits (K2-K6) -------------------------------------------------------------------------------------------------
MAX_ARGS_BYTES = 4096                # the JSON arguments string the model wrote
CALC_MAX_CHARS = 512
CALC_MAX_DEPTH = 32                  # parenthesis / function nesting
CALC_MAX_NODES = 200                 # AST nodes (numbers + operations + calls); a VAT chain is ~20
CALC_MAX_DIGITS = 40                 # digits per numeric literal
LIST_MAX = 100                       # arguments of min / max / sum / avg (calc); tables use the row cap
ROUND_MAX_N = 10
MAGNITUDE = Decimal("1e30")          # |every intermediate| <= 1e30
TABLE_MAX_BYTES = 256 * 1024
TABLE_MAX_ROWS = 5000
TABLE_MAX_COLS = 50
TABLE_MAX_CELL = 1024
TABLE_MAX_WHERE = 4
TABLE_MAX_BLOCKS = 8
DATE_MIN, DATE_MAX = date(1900, 1, 1), date(2199, 12, 31)
DATES_MAX_N = 3650
DATES_MAX_HOLIDAYS = 100             # stricter than K4's 366: 100 ISO dates fit the 4 KiB argument cap
RESULT_MAX_CHARS = 1024              # what goes back into the model's context
LABEL_MAX_CHARS = 200


def _ctx() -> Context:
    # K2: precision capped, exponent range capped, traps on (an exception, never a silent Infinity/NaN)
    return Context(prec=50, Emax=60, Emin=-60, rounding=ROUND_HALF_UP,
                   traps=[InvalidOperation, DivisionByZero, Overflow])


class ToolError(Exception):
    def __init__(self, code: str):
        assert code in CODES, code
        super().__init__(code)
        self.code = code


# --- K1: closed schemas -------------------------------------------------------------------------------------------
# name -> {arg: (types, required)}
_STR, _INT, _NUM, _LIST = (str,), (int,), (int, float, str), (list,)
SCHEMAS: Dict[str, Dict[str, Tuple[tuple, bool]]] = {
    "calc": {"expression": (_STR, True)},
    "table": {"op": (_STR, True), "column": (_STR, False), "column2": (_STR, False), "label": (_STR, False),
              "where": (_LIST, False), "table": (_INT, False), "delimiter": (_STR, False), "decimal": (_STR, False)},
    "dates": {"op": (_STR, True), "date": (_STR, False), "date2": (_STR, False), "n": (_INT, False),
              "holidays": (_LIST, False)},
}
TABLE_OPS = ("sum", "avg", "count", "min", "max", "argmin", "argmax", "sum_product")
TABLE_CMPS = ("=", "!=", "<", "<=", ">", ">=")
DATES_OPS = ("add_days", "add_business_days", "days_between", "business_days_between", "weekday")
DELIMITERS = {",": ",", ";": ";", "tab": "\t"}
DECIMALS = (".", ",")


def _typed(v: Any, types: tuple) -> bool:
    if isinstance(v, bool):
        return False
    return isinstance(v, types)


def _no_constant(name: str) -> Any:
    raise ValueError("NaN/Infinity are not JSON numbers here")


def parse_arguments(name: Any, raw: Any) -> Dict[str, Any]:
    """The tool name + the model's JSON arguments string -> a validated dict, or ToolError (K1)."""
    if not isinstance(name, str) or name not in SCHEMAS:
        raise ToolError("unknown_tool")
    if isinstance(raw, str):
        if len(raw.encode("utf-8", "surrogatepass")) > MAX_ARGS_BYTES:
            raise ToolError("arguments_too_large")
        try:
            args = json.loads(raw, parse_constant=_no_constant) if raw.strip() else {}
        except (ValueError, RecursionError):
            raise ToolError("bad_arguments")
    elif isinstance(raw, dict):
        if len(json.dumps(raw, default=str)) > MAX_ARGS_BYTES:
            raise ToolError("arguments_too_large")
        args = raw
    else:
        raise ToolError("bad_arguments")
    if not isinstance(args, dict):
        raise ToolError("bad_arguments")
    schema = SCHEMAS[name]
    for k in args:
        if k not in schema:
            raise ToolError("unexpected_argument")
    for k, (types, required) in schema.items():
        if k not in args:
            if required:
                raise ToolError("missing_argument")
            continue
        if not _typed(args[k], types):
            raise ToolError("bad_argument_type")
    return args


# --- calc (K2, T2) ------------------------------------------------------------------------------------------------
FUNCS = ("round", "min", "max", "sum", "avg", "abs")
_OPS = {"+", "-", "*", "/", "(", ")", ",", "%", "[", "]"}
_ALIASES = {"×": "*", "÷": "/", "−": "-"}       # x sign, division sign, minus sign


def _tokens(s: str) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    i, n = 0, len(s)
    while i < n:
        c = _ALIASES.get(s[i], s[i])
        if c in " \t":
            i += 1
        elif c.isdigit() and c.isascii() or (c == "." and i + 1 < n and s[i + 1].isascii() and s[i + 1].isdigit()):
            j = i
            while j < n and s[j].isascii() and s[j].isdigit():
                j += 1
            if j < n and s[j] == ".":
                j += 1
                while j < n and s[j].isascii() and s[j].isdigit():
                    j += 1
            lit = s[i:j]
            if sum(ch.isdigit() for ch in lit) > CALC_MAX_DIGITS:
                raise ToolError("number_too_long")
            out.append(("num", lit))
            i = j
        elif c.isascii() and c.isalpha():
            j = i
            while j < n and s[j].isascii() and s[j].isalpha():
                j += 1
            word = s[i:j].lower()
            if word not in FUNCS:
                raise ToolError("unknown_function")
            out.append(("fn", word))
            i = j
        elif c in _OPS:
            out.append(("op", c))
            i += 1
        else:
            raise ToolError("bad_expression")
    return out


class _Parser:
    """expr := term (('+'|'-') term)* ; term := unary (('*'|'/') unary)* ; unary := ('+'|'-') unary | postfix ;
    postfix := primary '%'? ; primary := NUMBER | '(' expr ')' | FUNC '(' arglist ')' ;
    arglist := item (',' item)* ; item := expr | '[' expr (',' expr)* ']'   (no power operator: K2)"""

    def __init__(self, toks: List[Tuple[str, str]]):
        self.t, self.i, self.nodes, self.depth = toks, 0, 0, 0

    def _peek(self) -> Optional[Tuple[str, str]]:
        return self.t[self.i] if self.i < len(self.t) else None

    def _eat(self, kind: str, val: Optional[str] = None) -> Tuple[str, str]:
        p = self._peek()
        if p is None or p[0] != kind or (val is not None and p[1] != val):
            raise ToolError("bad_expression")
        self.i += 1
        return p

    def _node(self, n: tuple) -> tuple:
        self.nodes += 1
        if self.nodes > CALC_MAX_NODES:
            raise ToolError("expression_too_complex")
        return n

    def _enter(self) -> None:
        self.depth += 1
        if self.depth > CALC_MAX_DEPTH:
            raise ToolError("expression_too_deep")

    def parse(self) -> tuple:
        if not self.t:
            raise ToolError("bad_expression")
        e = self.expr()
        if self._peek() is not None:
            raise ToolError("bad_expression")
        return e

    def expr(self) -> tuple:
        left = self.term()
        while self._peek() in (("op", "+"), ("op", "-")):
            op = self._eat("op")[1]
            left = self._node((op, left, self.term()))
        return left

    def term(self) -> tuple:
        left = self.unary()
        while self._peek() in (("op", "*"), ("op", "/")):
            op = self._eat("op")[1]
            left = self._node((op, left, self.unary()))
        return left

    def unary(self) -> tuple:
        if self._peek() in (("op", "+"), ("op", "-")):
            op = self._eat("op")[1]
            self._enter()
            try:
                return self._node(("neg" if op == "-" else "pos", self.unary()))
            finally:
                self.depth -= 1
        return self.postfix()

    def postfix(self) -> tuple:
        p = self.primary()
        if self._peek() == ("op", "%"):
            self._eat("op", "%")
            p = self._node(("pct", p))
        return p

    def primary(self) -> tuple:
        p = self._peek()
        if p is None:
            raise ToolError("bad_expression")
        if p[0] == "num":
            self.i += 1
            return self._node(("num", p[1]))
        if p == ("op", "("):
            self._eat("op", "(")
            self._enter()
            try:
                e = self.expr()
            finally:
                self.depth -= 1
            self._eat("op", ")")
            return e
        if p[0] == "fn":
            self.i += 1
            self._eat("op", "(")
            self._enter()
            try:
                args = self.arglist()
            finally:
                self.depth -= 1
            self._eat("op", ")")
            return self._node(("call", p[1], args))
        raise ToolError("bad_expression")

    def arglist(self) -> List[tuple]:
        args = [self.item()]
        while self._peek() == ("op", ","):
            self._eat("op", ",")
            args.append(self.item())
            if len(args) > LIST_MAX:
                raise ToolError("list_too_long")
        return args

    def item(self) -> tuple:
        if self._peek() == ("op", "["):
            self._eat("op", "[")
            xs = [self.expr()]
            while self._peek() == ("op", ","):
                self._eat("op", ",")
                xs.append(self.expr())
                if len(xs) > LIST_MAX:
                    raise ToolError("list_too_long")
            self._eat("op", "]")
            return self._node(("list", xs))
        return self.expr()


def _bound(x: Decimal) -> Decimal:
    if not x.is_finite() or abs(x) > MAGNITUDE:
        raise ToolError("result_too_large")
    return x


def _flat(vals: List[Any]) -> List[Decimal]:
    out: List[Decimal] = []
    for v in vals:
        out.extend(v if isinstance(v, list) else [v])
    if not out or len(out) > LIST_MAX:
        raise ToolError("bad_function_arguments" if not out else "list_too_long")
    return out


def _eval(n: tuple, ctx: Context) -> Any:
    k = n[0]
    if k == "num":
        return _bound(ctx.create_decimal(n[1]))
    if k == "list":
        return [_scalar(_eval(x, ctx)) for x in n[1]]
    if k == "neg":
        return _bound(ctx.minus(_scalar(_eval(n[1], ctx))))
    if k == "pos":
        return _scalar(_eval(n[1], ctx))
    if k == "pct":
        return _bound(ctx.divide(_scalar(_eval(n[1], ctx)), Decimal(100)))
    if k in ("+", "-", "*", "/"):
        a, b = _scalar(_eval(n[1], ctx)), _scalar(_eval(n[2], ctx))
        if k == "/" and b == 0:
            raise ToolError("division_by_zero")
        f = {"+": ctx.add, "-": ctx.subtract, "*": ctx.multiply, "/": ctx.divide}[k]
        return _bound(f(a, b))
    if k == "call":
        name, args = n[1], [_eval(a, ctx) for a in n[2]]
        if name == "round":
            if len(args) not in (1, 2) or any(isinstance(a, list) for a in args):
                raise ToolError("bad_function_arguments")
            places = args[1] if len(args) == 2 else Decimal(0)
            if places != places.to_integral_value() or not 0 <= places <= ROUND_MAX_N:
                raise ToolError("bad_function_arguments")
            return _bound(args[0].quantize(Decimal(1).scaleb(-int(places)), rounding=ROUND_HALF_UP, context=ctx))
        if name == "abs":
            if len(args) != 1 or isinstance(args[0], list):
                raise ToolError("bad_function_arguments")
            return _bound(ctx.abs(args[0]))
        xs = _flat(args)
        if name == "min":
            return min(xs)
        if name == "max":
            return max(xs)
        total = Decimal(0)
        for x in xs:
            total = _bound(ctx.add(total, x))
        return total if name == "sum" else _bound(ctx.divide(total, Decimal(len(xs))))
    raise ToolError("bad_expression")


def _scalar(v: Any) -> Decimal:
    if isinstance(v, list):
        raise ToolError("bad_function_arguments")
    return v


def calc(expression: str) -> str:
    if len(expression) > CALC_MAX_CHARS:
        raise ToolError("expression_too_long")
    tree = _Parser(_tokens(expression)).parse()
    ctx = _ctx()
    with localcontext(ctx):
        try:
            v = _scalar(_eval(tree, ctx))
        except DivisionByZero:
            raise ToolError("division_by_zero")
        except Overflow:
            raise ToolError("result_too_large")
        except InvalidOperation:
            raise ToolError("invalid_operation")
    return format(v, "f")


# --- table (K3, T3) -----------------------------------------------------------------------------------------------
def _number(cell: str, dec: str) -> Optional[Decimal]:
    """Strict: [sign] digits [dec digits], surrounding spaces allowed; no thousands separator, no exponent, no
    currency sign. The decimal separator is the one the CALL names ('.' unless decimal=','), never guessed.
    Empty -> None (skipped)."""
    s = cell.strip()
    if not s:
        return None
    body = s[1:] if s[0] in "+-" else s
    whole, sep, frac = body.partition(dec)
    ok = (whole.isascii() and whole.isdigit() or (not whole and sep and frac)) \
        and (not sep or (frac.isascii() and frac.isdigit()))
    if not ok or len(whole) + len(frac) > CALC_MAX_DIGITS:
        raise ToolError("not_a_number")
    return Decimal(("-" if s[0] == "-" else "") + (whole or "0") + ("." + frac if sep else ""))


def _rows(block: str, delimiter: str) -> Tuple[List[str], List[List[str]]]:
    if len(block.encode("utf-8", "surrogatepass")) > TABLE_MAX_BYTES:
        raise ToolError("table_too_large")
    try:
        block.encode("utf-8")
    except UnicodeEncodeError:
        raise ToolError("bad_table")                     # lone surrogates: not text we parse
    if "\x00" in block:
        raise ToolError("bad_table")
    csv.field_size_limit(TABLE_MAX_CELL)
    try:
        rows = []
        for r in csv.reader(io.StringIO(block, newline=""), delimiter=delimiter, strict=True):
            if len(rows) > TABLE_MAX_ROWS:
                raise ToolError("table_too_large")
            if not r or all(not c.strip() for c in r):
                continue                                 # blank line
            rows.append(r)
    except csv.Error:
        raise ToolError("bad_table")
    if not rows:
        raise ToolError("bad_table")
    header = [h.strip() for h in rows[0]]
    if len(header) > TABLE_MAX_COLS:
        raise ToolError("table_too_large")
    if any(not h for h in header) or len(set(header)) != len(header):
        raise ToolError("bad_table")
    data = rows[1:]
    if any(len(r) != len(header) for r in data):
        raise ToolError("bad_table")                     # ragged rows: never padded or guessed
    return header, data


def _col(header: List[str], name: Optional[str]) -> int:
    if name is None:
        raise ToolError("missing_argument")
    try:
        return header.index(name.strip())
    except ValueError:
        raise ToolError("unknown_column")


def _match(row: List[str], header: List[str], conds: List[Dict[str, Any]], dec: str) -> bool:
    for c in conds:
        cell = row[_col(header, c["column"])]
        cmp, val = c["cmp"], c["value"]
        if cmp in ("=", "!=") and isinstance(val, str):
            hit = cell.strip() == val.strip()          # exact string equality: no pattern, no regex (K3)
            if hit != (cmp == "="):
                return False
            continue
        x = _number(cell, dec)
        y = _number(str(val), ".") if not isinstance(val, str) else _number(val, dec)
        if x is None or y is None:
            return False
        ok = {"=": x == y, "!=": x != y, "<": x < y, "<=": x <= y, ">": x > y, ">=": x >= y}[cmp]
        if not ok:
            return False
    return True


def _where(raw: Any) -> List[Dict[str, Any]]:
    if raw is None:
        return []
    if len(raw) > TABLE_MAX_WHERE:
        raise ToolError("bad_argument_value")
    out = []
    for c in raw:
        if not isinstance(c, dict) or set(c) != {"column", "cmp", "value"}:
            raise ToolError("bad_argument_value")
        if not isinstance(c["column"], str) or c["cmp"] not in TABLE_CMPS \
                or isinstance(c["value"], bool) or not isinstance(c["value"], (str, int, float)):
            raise ToolError("bad_argument_value")
        if isinstance(c["value"], str) and len(c["value"]) > TABLE_MAX_CELL:
            raise ToolError("bad_argument_value")
        out.append(c)
    return out


def table(args: Dict[str, Any], block: Optional[str]) -> str:
    op = args["op"]
    if op not in TABLE_OPS:
        raise ToolError("bad_argument_value")
    delimiter = DELIMITERS.get(args.get("delimiter", ","))
    dec = args.get("decimal", ".")
    if delimiter is None or dec not in DECIMALS or (dec == "," and delimiter == ","):
        raise ToolError("bad_argument_value")
    if block is None:
        raise ToolError("no_table")
    header, data = _rows(block, delimiter)
    conds = _where(args.get("where"))
    for c in conds:
        _col(header, c["column"])                        # unknown filter column: an error, not "no match"
    rows = [r for r in data if _match(r, header, conds, dec)]
    if op == "count":
        if "column" in args:
            i = _col(header, args["column"])
            return str(sum(1 for r in rows if r[i].strip()))
        return str(len(rows))
    i = _col(header, args.get("column"))
    ctx = _ctx()
    with localcontext(ctx):
        try:
            if op == "sum_product":
                j = _col(header, args.get("column2"))
                total = Decimal(0)
                for r in rows:
                    a, b = _number(r[i], dec), _number(r[j], dec)
                    if a is not None and b is not None:
                        total = _bound(ctx.add(total, _bound(ctx.multiply(a, b))))
                return format(total, "f")
            vals = [(v, r) for r in rows for v in [_number(r[i], dec)] if v is not None]
            if not vals:
                raise ToolError("no_rows")
            if op == "sum" or op == "avg":
                total = Decimal(0)
                for v, _ in vals:
                    total = _bound(ctx.add(total, v))
                return format(total if op == "sum" else _bound(ctx.divide(total, Decimal(len(vals)))), "f")
            pick = (min if op in ("min", "argmin") else max)(vals, key=lambda t: t[0])
            if op in ("min", "max"):
                return format(pick[0], "f")
            li = _col(header, args.get("label"))
            return json.dumps({"value": format(pick[0], "f"), "label": pick[1][li].strip()[:LABEL_MAX_CHARS]},
                              ensure_ascii=False)
        except (DivisionByZero, Overflow, InvalidOperation):
            raise ToolError("result_too_large")


# --- dates (K4, T4) -----------------------------------------------------------------------------------------------
WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")


def _iso(s: Any) -> date:
    if not isinstance(s, str) or len(s) != 10 or s[4] != "-" or s[7] != "-" \
            or not (s[:4] + s[5:7] + s[8:]).isascii() or not (s[:4] + s[5:7] + s[8:]).isdigit():
        raise ToolError("bad_date")
    try:
        d = date(int(s[:4]), int(s[5:7]), int(s[8:]))
    except ValueError:
        raise ToolError("bad_date")
    if not DATE_MIN <= d <= DATE_MAX:
        raise ToolError("date_out_of_range")
    return d


def _holidays(raw: Any) -> frozenset:
    if raw is None:
        return frozenset()
    if len(raw) > DATES_MAX_HOLIDAYS:
        raise ToolError("too_many_holidays")
    return frozenset(_iso(h) for h in raw)


def _shift(d: date, days: int) -> date:
    try:
        out = d + timedelta(days=days)
    except OverflowError:
        raise ToolError("date_out_of_range")
    if not DATE_MIN <= out <= DATE_MAX:
        raise ToolError("date_out_of_range")
    return out


def dates(args: Dict[str, Any]) -> str:
    op = args["op"]
    if op not in DATES_OPS:
        raise ToolError("bad_argument_value")
    need = {"add_days": ("date", "n"), "add_business_days": ("date", "n"), "days_between": ("date", "date2"),
            "business_days_between": ("date", "date2"), "weekday": ("date",)}[op]
    for k in need:
        if k not in args:
            raise ToolError("missing_argument")
    d = _iso(args["date"])
    hol = _holidays(args.get("holidays"))
    if op == "weekday":
        return WEEKDAYS[d.weekday()]
    if op == "days_between":
        return str((_iso(args["date2"]) - d).days)
    if op == "business_days_between":
        d2 = _iso(args["date2"])
        lo, hi, sign = (d, d2, 1) if d <= d2 else (d2, d, -1)
        span = (hi - lo).days
        if span > DATES_MAX_N * 2:
            raise ToolError("date_out_of_range")
        n = 0
        for k in range(1, span + 1):                     # bounded: span <= 7300 days
            x = lo + timedelta(days=k)
            if x.weekday() < 5 and x not in hol:
                n += 1
        return str(sign * n)
    n = args["n"]
    if not -DATES_MAX_N <= n <= DATES_MAX_N:
        raise ToolError("bad_argument_value")
    if op == "add_days":
        return _shift(d, n).isoformat()
    step, left, x = (1 if n >= 0 else -1), abs(n), d
    for _ in range(DATES_MAX_N * 2 + DATES_MAX_HOLIDAYS + 7):   # bounded: n business days need < 1.4 n + holidays
        if left == 0:
            return x.isoformat()
        x = _shift(x, step)
        if x.weekday() < 5 and x not in hol:
            left -= 1
    raise ToolError("date_out_of_range")


# --- one call -------------------------------------------------------------------------------------------------------
def evaluate(name: str, args: Dict[str, Any], block: Optional[str] = None) -> Dict[str, str]:
    """{"result": str} or {"error": code}; args already passed parse_arguments. Never raises."""
    try:
        if name == "calc":
            out = calc(args["expression"])
        elif name == "table":
            out = table(args, block)
        elif name == "dates":
            out = dates(args)
        else:
            raise ToolError("unknown_tool")
    except ToolError as e:
        return {"error": e.code}
    except (RecursionError, MemoryError):
        return {"error": "expression_too_complex"}
    except Exception:                                    # a bug of ours: a closed code, never a trace (T7)
        return {"error": "tool_failed"}
    if len(out) > RESULT_MAX_CHARS:
        return {"error": "result_too_long"}
    return {"result": out}


# --- child entry (K5) -----------------------------------------------------------------------------------------------
CHILD_CPU_S = 2
CHILD_AS_BYTES = 512 * 1024 * 1024
CHILD_INPUT_MAX = TABLE_MAX_BYTES * 4 + MAX_ARGS_BYTES + 1024


def _limit_self() -> None:
    import resource
    for lim, val in ((resource.RLIMIT_CPU, CHILD_CPU_S), (resource.RLIMIT_AS, CHILD_AS_BYTES),
                     (resource.RLIMIT_FSIZE, 0), (resource.RLIMIT_CORE, 0), (resource.RLIMIT_NPROC, 0),
                     (resource.RLIMIT_NOFILE, 8)):
        resource.setrlimit(lim, (val, val))


# --- seccomp (auditor 07:30Z FIX 2) ---------------------------------------------------------------------------------
# The child runs as the node daemon's uid (which can read the node key). The rlimits bound CPU and memory but not the
# filesystem, and the hostile input reaches CPython's C code (json, csv, decimal). So before it reads input the child
# installs a seccomp filter: read on fd 0, write on fds 1-2, memory management, exit -- and the process is KILLED on
# any other system call (open, socket, execve, ...). No new privileges. Unknown architecture or no seccomp = no
# evaluation (fail closed).
_ARCH = {"x86_64": (0xC000003E, {"read": 0, "write": 1, "mmap": 9, "munmap": 11, "brk": 12, "rt_sigreturn": 15,
                                 "mremap": 25, "madvise": 28, "exit": 60, "exit_group": 231}),
         "aarch64": (0xC00000B7, {"read": 63, "write": 64, "mmap": 222, "munmap": 215, "brk": 214,
                                  "rt_sigreturn": 139, "mremap": 216, "madvise": 233, "exit": 93, "exit_group": 94})}
SECCOMP_PLAIN = ("mmap", "munmap", "brk", "mremap", "madvise", "rt_sigreturn", "exit", "exit_group")


def _bpf(arch_id: int, nr: Dict[str, int]) -> List[Tuple[int, int, int, int]]:
    """The filter as (code, jt, jf, k). Labels resolved here; every jump is forward and < 256."""
    LD, JEQ, RET = 0x20, 0x15, 0x06                  # BPF_LD|W|ABS, BPF_JMP|JEQ|K, BPF_RET|K
    ALLOW, KILL = 0x7FFF0000, 0x80000000             # SECCOMP_RET_ALLOW, SECCOMP_RET_KILL_PROCESS
    ins: List[list] = [[LD, 0, 0, 4], [JEQ, 0, "KILL", arch_id], [LD, 0, 0, 0]]
    ins += [[JEQ, "ALLOW", 0, nr[n]] for n in SECCOMP_PLAIN]
    ins += [[JEQ, "READ", 0, nr["read"]], [JEQ, "WRITE", 0, nr["write"]], [RET, 0, 0, KILL]]
    labels = {"READ": len(ins)}
    ins += [[LD, 0, 0, 16], [JEQ, "ALLOW", "KILL", 0]]                       # args[0] (fd) == 0
    labels["WRITE"] = len(ins)
    ins += [[LD, 0, 0, 16], [JEQ, "ALLOW", 0, 1], [JEQ, "ALLOW", "KILL", 2]]   # fd 1 or 2
    labels["ALLOW"] = len(ins)
    ins.append([RET, 0, 0, ALLOW])
    labels["KILL"] = len(ins)                        # BPF jumps only forward: the shared kill is last
    ins.append([RET, 0, 0, KILL])
    out = []
    for i, (code, jt, jf, k) in enumerate(ins):
        jt = labels[jt] - i - 1 if isinstance(jt, str) else jt
        jf = labels[jf] - i - 1 if isinstance(jf, str) else jf
        assert 0 <= jt < 256 and 0 <= jf < 256
        out.append((code, jt, jf, k))
    return out


def _seccomp_self() -> None:
    import ctypes
    import platform
    arch = _ARCH.get(platform.machine())
    if arch is None:
        raise OSError("seccomp: unsupported architecture")
    prog = _bpf(*arch)

    class Filter(ctypes.Structure):
        _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8), ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32)]

    class Prog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_uint16), ("filter", ctypes.POINTER(Filter))]
    arr = (Filter * len(prog))(*[Filter(*x) for x in prog])
    fprog = Prog(len(prog), arr)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:              # PR_SET_NO_NEW_PRIVS
        raise OSError("seccomp: no_new_privs refused")
    if libc.prctl(22, 2, ctypes.byref(fprog), 0, 0) != 0:      # PR_SET_SECCOMP, SECCOMP_MODE_FILTER
        raise OSError("seccomp: filter refused")


def main() -> int:
    _limit_self()                                        # BEFORE any input is read
    try:
        _seccomp_self()
    except Exception:
        sys.stdout.write(json.dumps({"error": "tool_failed"}))   # fail closed: no sandbox, no evaluation
        sys.stdout.flush()
        os._exit(0)
    raw = sys.stdin.buffer.read(CHILD_INPUT_MAX + 1)
    if len(raw) > CHILD_INPUT_MAX:
        out = {"error": "arguments_too_large"}
    else:
        try:
            req = json.loads(raw.decode("utf-8", "surrogatepass"), parse_constant=_no_constant)
            block = req.get("block")
            args = parse_arguments(req.get("tool"), req.get("args"))     # again here: the child is the boundary
            out = evaluate(req["tool"], args, block if isinstance(block, str) else None)
        except ToolError as e:
            out = {"error": e.code}
        except Exception:
            out = {"error": "tool_failed"}
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()
    os._exit(0)                                          # no interpreter teardown under the filter


if __name__ == "__main__":
    main()
