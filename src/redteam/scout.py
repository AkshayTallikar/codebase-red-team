"""Static source scout: exploit leads from a target's source, read with `ast` and never run.

The scout walks every route (a function decorated with `@<app>.<method>("<path>")`) and runs
one rule per vulnerability class. Each rule yields a `Hypothesis` with concrete probes. Nothing
is executed, imported or compiled: a hypothesis is a lead, and only the oracle decides what lands.
"""

from __future__ import annotations

import ast
import dataclasses
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from redteam.models import Probe
from redteam.targets.base import Target

MAX_PROBES = 8
HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete"})
PRIVILEGED_FIELDS = frozenset({"role", "is_admin", "admin", "permissions", "owner_id", "balance"})
SQLI_VALUES = ("' OR 1=1 --", "' or 1=1 --", "%' OR '1'='1' --")
CRASH_VALUES = ("0", "abc", "-1")
IDOR_IDS = ("1", "2", "3", "4", "5")
TRAVERSAL_PREFIXES = ("../", "....//", "..//", "./../")
FALLBACK_TRAVERSAL = "../../etc/passwd"
SAFE_HEADERS = frozenset({"x-token", "authorization"})
FILE_NAME = re.compile(r"[\w.-]+\.(?:txt|env|cfg|ini|json|key|pem|db)")
INTERNAL_HOST = re.compile(
    r"localhost|[a-z0-9-]+(?:\.[a-z0-9-]+)*\.internal|(?:127|10)(?:\.\d{1,3}){3}"
    r"|169\.254(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2}"
)
PUBLIC_WORD = re.compile(r"\bpublic\b")
COMPOUND_STATEMENTS = (
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ClassDef,
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.With,
    ast.AsyncWith,
    ast.Try,
    ast.TryStar,
    ast.Match,
)


@dataclass(frozen=True)
class Hypothesis:
    """A static lead: a route, a vulnerability class, the suspicious line and its probes."""

    vuln_class: str
    endpoint: str
    line: int
    evidence: str
    reason: str
    probes: tuple[Probe, ...]

    @property
    def key(self) -> str:
        """Same shape as `Finding.key`."""
        return f"{self.vuln_class}:{self.endpoint}"

    def to_dict(self) -> dict[str, object]:
        """Plain data for the CLI's JSON output."""
        return {
            "key": self.key,
            "vuln_class": self.vuln_class,
            "endpoint": self.endpoint,
            "line": self.line,
            "evidence": self.evidence,
            "reason": self.reason,
            "probes": [probe.to_dict() for probe in self.probes],
        }


# --- parsed shape of the source ----------------------------------------------------------


@dataclass(frozen=True)
class _Param:
    """A route or dependency parameter. kind is dep, body, path, query or request."""

    name: str
    kind: str
    annotation: str
    dependency: str = ""
    safe_int: bool = False


@dataclass(frozen=True)
class _Route:
    method: str
    path: str
    func: ast.FunctionDef | ast.AsyncFunctionDef
    params: tuple[_Param, ...]

    @property
    def endpoint(self) -> str:
        return f"{self.method} {self.path}"

    def named(self, *kinds: str) -> list[_Param]:
        return [param for param in self.params if param.kind in kinds]


@dataclass(frozen=True)
class _Context:
    """Facts about the scanned source and its hints, shared by every route."""

    lines: tuple[str, ...]
    functions: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef]
    aliases: Mapping[str, str]
    models: frozenset[str]
    file_names: tuple[str, ...]
    internal_hosts: tuple[str, ...]
    compared: Mapping[str, tuple[str, ...]]


@dataclass
class _Scan:
    """One route with its body nodes, local assignments and the request values that reach them."""

    route: _Route
    ctx: _Context
    nodes: list[ast.AST]
    assignments: dict[str, list[ast.AST]]
    origins: dict[str, frozenset[str]]

    def origins_of(self, expr: ast.AST) -> frozenset[str]:
        """Names of the path and query parameters that the expression depends on."""
        found: set[str] = set()
        for node in ast.walk(expr):
            if isinstance(node, ast.Name):
                found |= self.origins.get(node.id, frozenset())
        return frozenset(found)

    def calls(self, callee: str | None = None) -> list[ast.Call]:
        """Calls in the route body, optionally only those whose last name is `callee`."""
        return [
            node
            for node in self.nodes
            if isinstance(node, ast.Call) and (callee is None or _callee(node) == callee)
        ]


@dataclass(frozen=True)
class _Hit:
    line: int
    reason: str
    probes: tuple[Probe, ...]


@dataclass(frozen=True)
class _Lead:
    vuln_class: str
    line: int
    reason: str
    probes: tuple[Probe, ...]


# --- small AST helpers -------------------------------------------------------------------


def _callee(call: ast.Call) -> str:
    """The last name of a call: `f` for f(...), `execute` for conn.execute(...)."""
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return ""


def _names(node: ast.AST | None) -> set[str]:
    if node is None:
        return set()
    return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}


def _contains(expr: ast.AST, target: ast.AST) -> bool:
    return any(node is target for node in ast.walk(expr))


def _str_value(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _depends_target(node: ast.AST | None) -> str:
    """The dependency function named by a Depends(fn) call, or an empty string."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        if node.func.id == "Depends" and node.args and isinstance(node.args[0], ast.Name):
            return node.args[0].id
    return ""


def _assign_pairs(func: ast.AST) -> list[tuple[ast.AST, ast.AST]]:
    """(target, value) pairs for every assignment, loop and walrus under `func`."""
    pairs: list[tuple[ast.AST, ast.AST]] = []
    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            pairs.extend((target, node.value) for target in node.targets)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and node.value is not None:
            pairs.append((node.target, node.value))
        elif isinstance(node, ast.For):
            pairs.append((node.target, node.iter))
        elif isinstance(node, ast.NamedExpr):
            pairs.append((node.target, node.value))
    return pairs


# --- parsing the source ------------------------------------------------------------------


def _aliases(tree: ast.Module) -> dict[str, str]:
    """Module or closure aliases such as `User = Annotated[dict, Depends(current_user)]`."""
    found: dict[str, str] = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1):
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue
        for sub in ast.walk(node.value):
            dependency = _depends_target(sub)
            if dependency:
                found[target.id] = dependency
                break
    return found


def _models(tree: ast.Module) -> frozenset[str]:
    """Classes in the source that derive from BaseModel (request bodies)."""
    return frozenset(
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
        and any("BaseModel" in ast.unparse(base) for base in node.bases)
    )


def _functions(tree: ast.Module) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    return {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _route_path(decorator: ast.expr) -> tuple[str, str] | None:
    """(METHOD, path) for `@x.get("/path")`-style decorators, else None."""
    if not (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute)):
        return None
    if decorator.func.attr not in HTTP_METHODS or not decorator.args:
        return None
    path = _str_value(decorator.args[0])
    if path is None:
        return None
    return decorator.func.attr.upper(), path


def _args_with_defaults(args: ast.arguments) -> list[tuple[ast.arg, ast.expr | None]]:
    positional = [*args.posonlyargs, *args.args]
    defaults: list[ast.expr | None] = [None] * (len(positional) - len(args.defaults))
    defaults.extend(args.defaults)
    pairs = list(zip(positional, defaults, strict=True))
    pairs.extend(zip(args.kwonlyargs, args.kw_defaults, strict=True))
    return pairs


def _is_safe_int(annotation: ast.expr | None) -> bool:
    """True for Annotated[int, Query(ge=n)] with n >= 1, the only bounded integer we accept."""
    if not (
        isinstance(annotation, ast.Subscript)
        and isinstance(annotation.value, ast.Name)
        and annotation.value.id == "Annotated"
    ):
        return False
    elts = annotation.slice.elts if isinstance(annotation.slice, ast.Tuple) else []
    if len(elts) < 2 or not (isinstance(elts[0], ast.Name) and elts[0].id == "int"):
        return False
    for node in ast.walk(elts[1]):
        if not (isinstance(node, ast.Call) and _callee(node) == "Query"):
            continue
        for keyword in node.keywords:
            value = keyword.value
            if keyword.arg == "ge" and isinstance(value, ast.Constant):
                if isinstance(value.value, int) and value.value >= 1:
                    return True
    return False


def _classify(
    arg: ast.arg,
    default: ast.expr | None,
    path: str,
    aliases: Mapping[str, str],
    models: frozenset[str],
) -> _Param:
    """Sort one route argument into dependency, body, request, path or query."""
    annotation = arg.annotation
    text = ast.unparse(annotation) if annotation is not None else ""
    names = _names(annotation)
    dependency = ""
    if isinstance(annotation, ast.Name) and annotation.id in aliases:
        dependency = aliases[annotation.id]
    if annotation is not None:
        dependency = dependency or next(
            (dep for dep in map(_depends_target, ast.walk(annotation)) if dep), ""
        )
    dependency = dependency or _depends_target(default)
    if dependency:
        return _Param(arg.arg, "dep", text, dependency=dependency)
    if names == {"Request"}:
        return _Param(arg.arg, "request", text)
    if "Body" in text or names & models:
        return _Param(arg.arg, "body", text)
    if "{" + arg.arg + "}" in path:
        return _Param(arg.arg, "path", text)
    return _Param(arg.arg, "query", text, safe_int=_is_safe_int(annotation))


def _routes(tree: ast.Module, aliases: Mapping[str, str], models: frozenset[str]) -> list[_Route]:
    routes: list[_Route] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            found = _route_path(decorator)
            if found is None:
                continue
            method, path = found
            params = tuple(
                _classify(arg, default, path, aliases, models)
                for arg, default in _args_with_defaults(node.args)
            )
            routes.append(_Route(method, path, node, params))
    return routes


def _parse_hints(hints: Sequence[str]) -> list[ast.Module]:
    """Hint texts are used only for string literals, so ones that do not parse are skipped."""
    trees: list[ast.Module] = []
    for text in hints:
        try:
            trees.append(ast.parse(text))
        except SyntaxError:
            continue
    return trees


def _file_names(trees: Sequence[ast.Module]) -> tuple[str, ...]:
    """Bare file-name literals (secrets.txt). A statement that mentions `public` is skipped."""
    found: set[str] = set()
    for tree in trees:
        for stmt in ast.walk(tree):
            if not isinstance(stmt, ast.stmt) or isinstance(stmt, COMPOUND_STATEMENTS):
                continue
            if PUBLIC_WORD.search(ast.unparse(stmt)):
                continue
            for node in ast.walk(stmt):
                value = _str_value(node)
                if value is not None and FILE_NAME.fullmatch(value):
                    found.add(value)
    return tuple(sorted(found))


def _internal_hosts(trees: Sequence[ast.Module]) -> tuple[str, ...]:
    """String literals that name an internal host: localhost, *.internal or a private address."""
    found: set[str] = set()
    for tree in trees:
        for node in ast.walk(tree):
            value = _str_value(node)
            if value is not None and INTERNAL_HOST.fullmatch(value):
                found.add(value)
    return tuple(sorted(found))


def _subscript_key(node: ast.AST) -> str | None:
    if isinstance(node, ast.Subscript):
        return _str_value(node.slice)
    return None


def _compared(tree: ast.Module) -> dict[str, tuple[str, ...]]:
    """String constants compared with `x["key"]` by == or != anywhere in the source."""
    found: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        sides = [node.left, *node.comparators]
        for op, left, right in zip(node.ops, sides, sides[1:], strict=False):
            if not isinstance(op, (ast.Eq, ast.NotEq)):
                continue
            for subscript, other in ((left, right), (right, left)):
                key = _subscript_key(subscript)
                value = _str_value(other)
                if key is not None and value is not None:
                    found.setdefault(key, []).append(value)
    return {key: tuple(dict.fromkeys(values)) for key, values in found.items()}


def _context(
    source: str,
    tree: ast.Module,
    hint_trees: Sequence[ast.Module],
    aliases: Mapping[str, str],
    models: frozenset[str],
) -> _Context:
    everything = [tree, *hint_trees]
    return _Context(
        lines=tuple(source.splitlines()),
        functions=_functions(tree),
        aliases=aliases,
        models=models,
        file_names=_file_names(everything),
        internal_hosts=_internal_hosts(everything),
        compared=_compared(tree),
    )


# --- taint -------------------------------------------------------------------------------


def _taint(route: _Route, pairs: Sequence[tuple[ast.AST, ast.AST]]) -> dict[str, frozenset[str]]:
    """Map each name to the path and query parameters it is derived from."""
    origins: dict[str, set[str]] = {
        param.name: {param.name} for param in route.named("path", "query")
    }
    changed = True
    while changed:
        changed = False
        for target, value in pairs:
            found: set[str] = set()
            for name in _names(value):
                found |= origins.get(name, set())
            if not found:
                continue
            for name in _names(target):
                current = origins.setdefault(name, set())
                if not found <= current:
                    current |= found
                    changed = True
    return {name: frozenset(values) for name, values in origins.items()}


def _scan_route(route: _Route, ctx: _Context) -> _Scan:
    nodes = [node for stmt in route.func.body for node in ast.walk(stmt)]
    pairs = _assign_pairs(route.func)
    assignments: dict[str, list[ast.AST]] = {}
    for target, value in pairs:
        for name in _names(target):
            assignments.setdefault(name, []).append(value)
    origins = _taint(route, pairs)
    return _Scan(route, ctx, nodes, assignments, origins)


# --- probes ------------------------------------------------------------------------------


def _probe(
    route: _Route,
    vuln_class: str,
    *,
    values: Mapping[str, str] | None = None,
    headers: Mapping[str, str] | None = None,
    json_body: dict[str, object] | None = None,
) -> Probe:
    """A probe on the route. Values for `{name}` template segments go into the path."""
    path = route.path
    params: dict[str, str] = {}
    for name, value in (values or {}).items():
        token = "{" + name + "}"
        if token in path:
            path = path.replace(token, str(value))
        else:
            params[name] = str(value)
    return Probe(
        method=route.method,
        path=path,
        endpoint=route.endpoint,
        vuln_class=vuln_class,
        params=params,
        headers=dict(headers or {}),
        json_body=json_body,
    )


def _lead(vuln_class: str, hits: Sequence[_Hit]) -> _Lead | None:
    """Merge the hits of one rule: the lowest line is reported, every hit's probes are kept."""
    if not hits:
        return None
    ordered = sorted(hits, key=lambda hit: hit.line)
    first = ordered[0]
    probes = tuple(probe for hit in ordered for probe in hit.probes)
    return _Lead(vuln_class, first.line, first.reason, probes)


# --- rules -------------------------------------------------------------------------------


def _query_candidates(expr: ast.AST, assignments: Mapping[str, list[ast.AST]]) -> list[ast.AST]:
    """The query text itself, or the values a name is assigned, when they build a string."""
    exprs = assignments.get(expr.id, []) if isinstance(expr, ast.Name) else [expr]
    return [
        item
        for item in exprs
        if isinstance(item, ast.JoinedStr)
        or (isinstance(item, ast.BinOp) and isinstance(item.op, (ast.Mod, ast.Add)))
    ]


def _check_sqli(scan: _Scan) -> _Lead | None:
    """sqli: a query string built by f-string, % or + that interpolates a request parameter
    and reaches `.execute(`. A plain string first argument (parameters passed separately) clears
    it. Interpolating a value that does not come from the request does not count."""
    hits: list[_Hit] = []
    for call in scan.calls("execute"):
        if not call.args:
            continue
        for query in _query_candidates(call.args[0], scan.assignments):
            origin = scan.origins_of(query)
            if not origin:
                continue
            if isinstance(query, ast.JoinedStr):
                how = "an f-string"
            elif isinstance(query, ast.BinOp) and isinstance(query.op, ast.Mod):
                how = "% formatting"
            else:
                how = "concatenation"
            param = sorted(origin)[0]
            probes = tuple(
                _probe(scan.route, "sqli", values={name: value})
                for name in sorted(origin)
                for value in SQLI_VALUES
            )
            reason = f"query text is built with {how} from parameter {param}"
            hits.append(_Hit(call.lineno, reason, probes))
    return _lead("sqli", hits)


def _has_containment_check(scan: _Scan) -> bool:
    """True when the route resolves real paths and checks them with startswith or is_relative_to.

    A `.replace("../", "")` is not a containment check and does not count here.
    """
    resolves = any(
        ast.unparse(call.func).endswith("realpath") or _callee(call) == "resolve"
        for call in scan.calls()
    )
    checks = any(_callee(call) in ("startswith", "is_relative_to") for call in scan.calls())
    return resolves and checks


def _is_join(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        return ast.unparse(node.func) in ("os.path.join", "posixpath.join")
    return isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)


def _reached_names(scan: _Scan, sinks: Sequence[ast.AST]) -> set[str]:
    """Names that feed a sink, directly or through assignments."""
    reached: set[str] = set()
    for expr in sinks:
        reached |= _names(expr)
    changed = True
    while changed:
        changed = False
        for name, values in scan.assignments.items():
            if name not in reached:
                continue
            for value in values:
                new = _names(value) - reached
                if new:
                    reached |= new
                    changed = True
    return reached


def _traversal_probes(scan: _Scan, param: str) -> tuple[Probe, ...]:
    files = scan.ctx.file_names
    if files:
        values = [prefix + name for name in files for prefix in TRAVERSAL_PREFIXES]
    else:
        values = [FALLBACK_TRAVERSAL]
    return tuple(_probe(scan.route, "path_traversal", values={param: v}) for v in values)


def _check_path_traversal(scan: _Scan) -> _Lead | None:
    """path_traversal: a request parameter joined into a path (os.path.join or Path /) whose
    result reaches open(), .read_text() or .read_bytes(). A route that calls realpath or
    resolve and also startswith or is_relative_to is treated as contained."""
    if _has_containment_check(scan):
        return None
    sinks: list[ast.AST] = []
    for call in scan.calls():
        callee = _callee(call)
        if callee == "open" and call.args:
            sinks.append(call.args[0])
        elif callee in ("read_text", "read_bytes") and isinstance(call.func, ast.Attribute):
            sinks.append(call.func.value)
    reached = _reached_names(scan, sinks)
    hits: list[_Hit] = []
    for node in scan.nodes:
        if not _is_join(node) or not scan.origins_of(node):
            continue
        in_sink = any(_contains(expr, node) for expr in sinks)
        flows = any(
            name in reached and any(_contains(value, node) for value in values)
            for name, values in scan.assignments.items()
        )
        if not (in_sink or flows):
            continue
        param = sorted(scan.origins_of(node))[0]
        reason = (
            f"request parameter {param} is joined into a path that is read "
            "without a containment check"
        )
        hits.append(_Hit(node.lineno, reason, _traversal_probes(scan, param)))
    return _lead("path_traversal", hits)


def _check_idor(scan: _Scan) -> _Lead | None:
    """idor: a path id (`id` or ending in `_id`) is passed to `.execute(` while the handler never
    references any dependency parameter, which is the current user. Referencing the user anywhere
    in the body clears it."""
    ids = [
        param.name
        for param in scan.route.named("path")
        if param.name == "id" or param.name.endswith("_id")
    ]
    if not ids:
        return None
    users = {param.name for param in scan.route.named("dep")}
    used = {node.id for node in scan.nodes if isinstance(node, ast.Name)}
    if users & used:
        return None
    hits: list[_Hit] = []
    for call in scan.calls("execute"):
        for name in ids:
            touched = any(
                isinstance(node, ast.Name) and node.id == name
                for arg in call.args
                for node in ast.walk(arg)
            )
            if not touched:
                continue
            reason = f"path id {name} reaches a query and the handler never reads the current user"
            probes = tuple(_probe(scan.route, "idor", values={name: v}) for v in IDOR_IDS)
            hits.append(_Hit(call.lineno, reason, probes))
    return _lead("idor", hits)


def _check_crash(scan: _Scan) -> _Lead | None:
    """crash: a str-annotated request parameter converted with int(), or a request value used as
    the right operand of /, // or %. Every parameter involved must be annotated
    Annotated[int, Query(ge=n)] with n >= 1 to clear the divisor case."""
    params = {param.name: param for param in scan.route.named("query", "path")}
    hits: list[_Hit] = []
    for node in scan.nodes:
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id != "int" or not node.args:
                continue
            names = sorted(
                name for name in scan.origins_of(node.args[0]) if params[name].annotation == "str"
            )
            if names:
                reason = (
                    f"request parameter {names[0]} is a str converted with int() "
                    "without a range check"
                )
                hits.append(_Hit(node.lineno, reason, _crash_probes(scan, names)))
        elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
            names = sorted(
                name for name in scan.origins_of(node.right) if not params[name].safe_int
            )
            if names:
                reason = f"request parameter {names[0]} reaches a divisor without a range check"
                hits.append(_Hit(node.lineno, reason, _crash_probes(scan, names)))
    return _lead("crash", hits)


def _crash_probes(scan: _Scan, names: Sequence[str]) -> tuple[Probe, ...]:
    return tuple(
        _probe(scan.route, "crash", values={name: value})
        for name in names
        for value in CRASH_VALUES
    )


def _check_mass_assignment(scan: _Scan) -> _Lead | None:
    """mass_assignment: a loop over a request body that writes (an UPDATE through .execute, or
    setattr) and whose `in` test lists a privileged field such as role. A guard outside the loop
    does not clear it; only dropping the privileged name from the tuple does."""
    bodies = {param.name for param in scan.route.named("body")}
    hits: list[_Hit] = []
    for loop in scan.nodes:
        if not isinstance(loop, ast.For) or not _iterates_body_items(loop.iter, bodies):
            continue
        inner = [node for stmt in loop.body for node in ast.walk(stmt)]
        writes = [
            node
            for node in inner
            if isinstance(node, ast.Call)
            and (
                (
                    _callee(node) == "execute"
                    and node.args
                    and "UPDATE" in ast.unparse(node.args[0]).upper()
                )
                or _callee(node) == "setattr"
            )
        ]
        privileged = sorted(_listed_privileged(inner))
        if not writes or not privileged:
            continue
        write = min(writes, key=lambda node: node.lineno)
        reason = (
            "request body loop writes fields allowed by a membership test that includes "
            + ", ".join(privileged)
        )
        probes: list[Probe] = []
        for field in privileged:
            values: tuple[object, ...] = scan.ctx.compared.get(field) or (True,)
            for key in dict.fromkeys((field, field.capitalize(), field.upper())):
                for value in values:
                    probes.append(_probe(scan.route, "mass_assignment", json_body={key: value}))
        hits.append(_Hit(write.lineno, reason, tuple(probes)))
    return _lead("mass_assignment", hits)


def _iterates_body_items(iterable: ast.expr, bodies: set[str]) -> bool:
    return (
        isinstance(iterable, ast.Call)
        and isinstance(iterable.func, ast.Attribute)
        and iterable.func.attr == "items"
        and isinstance(iterable.func.value, ast.Name)
        and iterable.func.value.id in bodies
    )


def _listed_privileged(nodes: Sequence[ast.AST]) -> set[str]:
    """Privileged field names inside a literal tuple, list or set on the right of `in`."""
    found: set[str] = set()
    for node in nodes:
        if not isinstance(node, ast.Compare):
            continue
        if not any(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops):
            continue
        for comparator in node.comparators:
            if not isinstance(comparator, (ast.Tuple, ast.List, ast.Set)):
                continue
            for elt in comparator.elts:
                value = _str_value(elt)
                if value in PRIVILEGED_FIELDS:
                    found.add(str(value))
    return found


def _has_host_check(scan: _Scan) -> bool:
    """True when the route parses the URL and compares its hostname with ==, != or in against a
    constant. A substring test on the raw URL does not count."""
    if not any(_callee(call) in ("urlsplit", "urlparse") for call in scan.calls()):
        return False
    derived: set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, values in scan.assignments.items():
            if name not in derived and any(_mentions_hostname(v, derived) for v in values):
                derived.add(name)
                changed = True
    for node in scan.nodes:
        if not isinstance(node, ast.Compare):
            continue
        if not any(isinstance(op, (ast.Eq, ast.NotEq, ast.In, ast.NotIn)) for op in node.ops):
            continue
        sides = [node.left, *node.comparators]
        from_host = [side for side in sides if _mentions_hostname(side, derived)]
        if from_host and any(_has_constant(s) for s in sides if s not in from_host):
            return True
    return False


def _mentions_hostname(expr: ast.AST, derived: set[str]) -> bool:
    return any(
        (isinstance(node, ast.Attribute) and node.attr == "hostname")
        or (isinstance(node, ast.Name) and node.id in derived)
        for node in ast.walk(expr)
    )


def _has_constant(expr: ast.AST) -> bool:
    return any(_str_value(node) is not None for node in ast.walk(expr))


def _check_ssrf(scan: _Scan) -> _Lead | None:
    """ssrf: a request parameter passed directly to a call whose name contains fetch, urlopen,
    request or get. A same-function urlsplit or urlparse with the hostname compared against a
    constant clears it."""
    if _has_host_check(scan):
        return None
    targets = tuple(f"http://{host}/latest/secret" for host in scan.ctx.internal_hosts) + (
        "http://169.254.169.254/latest/secret",
        "http://localhost/",
    )
    hits: list[_Hit] = []
    for call in scan.calls():
        callee = _callee(call)
        if not any(word in callee.lower() for word in ("fetch", "urlopen", "request", "get")):
            continue
        args = [*call.args, *(keyword.value for keyword in call.keywords)]
        names = sorted(
            {name for arg in args if isinstance(arg, ast.Name) for name in scan.origins_of(arg)}
        )
        if not names:
            continue
        reason = f"parameter {names[0]} is passed to {callee}() without a parsed-host check"
        probes = tuple(_probe(scan.route, "ssrf", values={names[0]: v}) for v in targets)
        hits.append(_Hit(call.lineno, reason, probes))
    return _lead("ssrf", hits)


def _check_auth_bypass(scan: _Scan) -> _Lead | None:
    """auth_bypass: the route compares the user from a dependency with ["role"] against a string
    constant, and that dependency reads an identity header other than x-token or authorization
    whose value reaches a query or a return. Removing the header read clears it."""
    deps = scan.route.named("dep")
    if not deps:
        return None
    dep_names = {param.name for param in deps}
    compared = _role_constants(scan.nodes, dep_names)
    if not compared:
        return None
    hits: list[_Hit] = []
    for param in deps:
        func = scan.ctx.functions.get(param.dependency)
        if func is None:
            continue
        for line, header in _identity_headers(func):
            canonical = "-".join(part.capitalize() for part in header.split("-"))
            reason = f"identity comes from request header {canonical} read in {func.name}()"
            probes = tuple(
                _probe(scan.route, "auth_bypass", headers={canonical: value}) for value in compared
            )
            hits.append(_Hit(line, reason, probes))
    return _lead("auth_bypass", hits)


def _is_role_of(node: ast.AST, dep_names: set[str]) -> bool:
    if isinstance(node, ast.Subscript):
        return (
            isinstance(node.value, ast.Name)
            and node.value.id in dep_names
            and _str_value(node.slice) == "role"
        )
    if isinstance(node, ast.Attribute):
        return node.attr == "role" and isinstance(node.value, ast.Name)
    return False


def _role_constants(nodes: Sequence[ast.AST], dep_names: set[str]) -> tuple[str, ...]:
    found: list[str] = []
    for node in nodes:
        if not isinstance(node, ast.Compare):
            continue
        sides = [node.left, *node.comparators]
        for op, left, right in zip(node.ops, sides, sides[1:], strict=False):
            if not isinstance(op, (ast.Eq, ast.NotEq)):
                continue
            for side, other in ((left, right), (right, left)):
                value = _str_value(other)
                if value is not None and _is_role_of(side, dep_names):
                    found.append(value)
    return tuple(dict.fromkeys(found))


def _header_read(node: ast.AST) -> str | None:
    """The header name in request.headers.get("x") or request.headers["x"], else None."""
    if isinstance(node, ast.Call) and ast.unparse(node.func).endswith("headers.get"):
        return _str_value(node.args[0]) if node.args else None
    if isinstance(node, ast.Subscript) and ast.unparse(node.value).endswith("headers"):
        return _str_value(node.slice)
    return None


def _identity_headers(func: ast.AST) -> list[tuple[int, str]]:
    """(line, header) for each identity-header read whose value reaches a query or a return."""
    pairs = _assign_pairs(func)
    found: list[tuple[int, str]] = []
    for node in ast.walk(func):
        header = _header_read(node)
        if header is None or header.lower() in SAFE_HEADERS:
            continue
        bound = _bound_names(node, pairs)
        if _reaches_sink(func, bound):
            found.append((node.lineno, header))
    return found


def _bound_names(read: ast.AST, pairs: Sequence[tuple[ast.AST, ast.AST]]) -> set[str]:
    """Names assigned from the header read, and names assigned from those in turn."""
    bound: set[str] = set()
    for target, value in pairs:
        if any(node is read for node in ast.walk(value)):
            bound |= _names(target)
    changed = True
    while changed:
        changed = False
        for target, value in pairs:
            if _names(value) & bound and not _names(target) <= bound:
                bound |= _names(target)
                changed = True
    return bound


def _reaches_sink(func: ast.AST, bound: set[str]) -> bool:
    for node in ast.walk(func):
        if isinstance(node, ast.Return) and node.value is not None:
            if _names(node.value) & bound:
                return True
        if isinstance(node, ast.Call) and _callee(node) == "execute":
            if any(_names(arg) & bound for arg in node.args):
                return True
    return False


_CHECKS: tuple[Callable[[_Scan], _Lead | None], ...] = (
    _check_sqli,
    _check_path_traversal,
    _check_idor,
    _check_crash,
    _check_mass_assignment,
    _check_ssrf,
    _check_auth_bypass,
)


def _hypothesis(route: _Route, lead: _Lead, ctx: _Context) -> Hypothesis:
    """Attach the scout note to each probe, dedupe them, and keep at most MAX_PROBES."""
    note = f"scout: {lead.reason}"
    probes: list[Probe] = []
    seen: set[str] = set()
    for probe in lead.probes:
        signature = probe.signature()
        if signature in seen:
            continue
        seen.add(signature)
        probes.append(dataclasses.replace(probe, note=note))
        if len(probes) == MAX_PROBES:
            break
    return Hypothesis(
        vuln_class=lead.vuln_class,
        endpoint=route.endpoint,
        line=lead.line,
        evidence=ctx.lines[lead.line - 1].strip(),
        reason=lead.reason,
        probes=tuple(probes),
    )


# --- public API --------------------------------------------------------------------------


def scout(source: str, *, hints: Sequence[str] = ()) -> list[Hypothesis]:
    """Return one hypothesis per (endpoint, vulnerability class) found in `source`.

    `hints` are other source texts of the target, used only for string literals (file names
    and internal hosts). Raises SyntaxError if `source` does not parse.
    """
    tree = ast.parse(source)
    aliases = _aliases(tree)
    models = _models(tree)
    ctx = _context(source, tree, _parse_hints(hints), aliases, models)
    found: dict[str, Hypothesis] = {}
    for route in _routes(tree, aliases, models):
        scan = _scan_route(route, ctx)
        for check in _CHECKS:
            lead = check(scan)
            if lead is not None:
                hypothesis = _hypothesis(route, lead, ctx)
                found.setdefault(hypothesis.key, hypothesis)
    return sorted(found.values(), key=lambda hyp: (hyp.endpoint, hyp.vuln_class))


def scout_target(target: Target, source: str | None = None) -> list[Hypothesis]:
    """Scout a target's source (its seed when `source` is None), with its package as hints."""
    text = target.load_source() if source is None else source
    seed = target.seed_path.resolve()
    hints = [
        path.read_text(encoding="utf-8")
        for path in sorted(seed.parent.glob("*.py"))
        if path.resolve() != seed
    ]
    return scout(text, hints=hints)


def render(hypotheses: Sequence[Hypothesis]) -> str:
    """One human-readable line per hypothesis, with no trailing newline."""
    return "\n".join(
        f"{hyp.vuln_class}  {hyp.endpoint}  line {hyp.line}  {hyp.reason}  "
        f"({len(hyp.probes)} {'probe' if len(hyp.probes) == 1 else 'probes'})"
        for hyp in hypotheses
    )
