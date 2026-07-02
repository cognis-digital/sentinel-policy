"""Import/export a policy to other formats without adding a dependency.

Two directions:

  * YAML   — a friendlier authoring format. If PyYAML is installed it is used;
             otherwise a small, safe, stdlib-only reader/writer handles the
             subset a policy needs (scalars, block lists, nested maps). No
             ``eval`` and no arbitrary-object construction either way.

  * Rego   — export the policy as a readable subset of Open Policy Agent's Rego
             so a team already standardized on OPA can review the same rules in
             their native language. This is a one-way, human-facing export
             (comments cite the doctrine); it is not a full Rego compiler.

Everything round-trips through ``Policy.to_dict`` / ``Policy.from_dict`` so the
JSON form stays the single source of truth.
"""

from __future__ import annotations

import json
from typing import Any, List

from .policy import Policy

try:  # optional; the stdlib fallback covers the policy subset without it
    import yaml as _pyyaml  # type: ignore
except Exception:  # pragma: no cover - depends on environment
    _pyyaml = None


# --------------------------------------------------------------------------- #
# YAML                                                                        #
# --------------------------------------------------------------------------- #
def to_yaml(policy: Policy) -> str:
    data = policy.to_dict()
    if _pyyaml is not None:
        return _pyyaml.safe_dump(data, sort_keys=False)
    return _dump_yaml(data)


def from_yaml(text: str) -> Policy:
    if _pyyaml is not None:
        return Policy.from_dict(_pyyaml.safe_load(text))
    return Policy.from_dict(_load_yaml(text))


# ---- minimal stdlib YAML (policy subset) ---------------------------------- #
def _scalar_out(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return "null"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    if s == "" or any(c in s for c in ":#{}[],&*!|>'\"%@`") or s.strip() != s \
            or s.lower() in ("true", "false", "null", "yes", "no"):
        return json.dumps(s)  # safely quoted
    return s


def _dump_yaml(obj: Any, indent: int = 0) -> str:
    pad = "  " * indent
    lines: List[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, dict) and v:
                lines.append(f"{pad}{k}:")
                lines.append(_dump_yaml(v, indent + 1))
            elif isinstance(v, list) and v:
                lines.append(f"{pad}{k}:")
                for item in v:
                    if isinstance(item, (dict, list)) and item:
                        # "- " then the block, re-indented under the dash
                        block = _dump_yaml(item, indent + 2).split("\n")
                        first = block[0].lstrip()
                        lines.append(f"{pad}  - {first}")
                        lines.extend(block[1:])
                    else:
                        lines.append(f"{pad}  - {_scalar_out(item)}")
            elif isinstance(v, (dict, list)):  # empty
                lines.append(f"{pad}{k}: {'{}' if isinstance(v, dict) else '[]'}")
            else:
                lines.append(f"{pad}{k}: {_scalar_out(v)}")
    else:
        lines.append(f"{pad}{_scalar_out(obj)}")
    return "\n".join(l for l in lines if l != "")


def _scalar_in(tok: str) -> Any:
    tok = tok.strip()
    if tok == "" or tok == "null" or tok == "~":
        return None
    if tok in ("true", "false"):
        return tok == "true"
    if (tok[0] == '"' and tok[-1] == '"') or (tok[0] == "'" and tok[-1] == "'"):
        try:
            return json.loads(tok) if tok[0] == '"' else tok[1:-1]
        except json.JSONDecodeError:
            return tok[1:-1]
    if tok in ("{}", "[]"):
        return {} if tok == "{}" else []
    try:
        return int(tok)
    except ValueError:
        pass
    try:
        return float(tok)
    except ValueError:
        pass
    return tok


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _load_yaml(text: str) -> Any:
    lines = [ln for ln in text.split("\n")
             if ln.strip() != "" and not ln.lstrip().startswith("#")]

    def parse_block(idx: int, indent: int):
        """Return (value, next_index) for the block starting at `idx`."""
        # decide list vs map by the first line at this indent
        if idx >= len(lines):
            return None, idx
        stripped = lines[idx].lstrip(" ")
        if stripped.startswith("- "):
            return parse_list(idx, indent)
        return parse_map(idx, indent)

    def parse_map(idx: int, indent: int):
        out: dict = {}
        while idx < len(lines):
            line = lines[idx]
            ind = _indent_of(line)
            if ind < indent:
                break
            if ind > indent:  # shouldn't happen at map level
                break
            key, _, rest = line.strip().partition(":")
            rest = rest.strip()
            if rest == "":
                # nested block on following, deeper lines
                nxt = idx + 1
                if nxt < len(lines) and _indent_of(lines[nxt]) > indent:
                    val, idx = parse_block(nxt, _indent_of(lines[nxt]))
                    out[key] = val
                    continue
                out[key] = None
                idx += 1
            else:
                out[key] = _scalar_in(rest)
                idx += 1
        return out, idx

    def parse_list(idx: int, indent: int):
        out: list = []
        while idx < len(lines):
            line = lines[idx]
            ind = _indent_of(line)
            if ind != indent or not line.lstrip(" ").startswith("- "):
                break
            item_body = line.lstrip(" ")[2:]
            if ":" in item_body and not item_body.strip().startswith(("\"", "'")):
                # inline start of a map item; synthesize a sub-block
                key, _, rest = item_body.partition(":")
                item: dict = {}
                item_indent = ind + 2
                if rest.strip() == "":
                    nxt = idx + 1
                    if nxt < len(lines) and _indent_of(lines[nxt]) > item_indent:
                        val, idx2 = parse_block(nxt, _indent_of(lines[nxt]))
                        item[key.strip()] = val
                        idx = idx2
                    else:
                        item[key.strip()] = None
                        idx += 1
                else:
                    item[key.strip()] = _scalar_in(rest)
                    idx += 1
                # absorb further keys belonging to this list item
                while idx < len(lines) and _indent_of(lines[idx]) == item_indent \
                        and not lines[idx].lstrip(" ").startswith("- "):
                    k2, _, r2 = lines[idx].strip().partition(":")
                    if r2.strip() == "":
                        nxt = idx + 1
                        if nxt < len(lines) and _indent_of(lines[nxt]) > item_indent:
                            val, idx = parse_block(nxt, _indent_of(lines[nxt]))
                            item[k2.strip()] = val
                            continue
                        item[k2.strip()] = None
                        idx += 1
                    else:
                        item[k2.strip()] = _scalar_in(r2)
                        idx += 1
                out.append(item)
            else:
                out.append(_scalar_in(item_body))
                idx += 1
        return out, idx

    if not lines:
        return {}
    value, _ = parse_block(0, _indent_of(lines[0]))
    return value


# --------------------------------------------------------------------------- #
# Rego (subset export)                                                         #
# --------------------------------------------------------------------------- #
_REGO_OP = {
    "eq": "==", "ne": "!=", "gt": ">", "ge": ">=", "lt": "<", "le": "<=",
}


def _rego_field(path: str) -> str:
    # input.params.env  (dotted path off the directive)
    return "input." + path


def _rego_literal(v: Any) -> str:
    return json.dumps(v)


def _rego_conditions(match: dict) -> List[str]:
    out: List[str] = []
    for path, spec in match.items():
        lhs = _rego_field(path)
        if isinstance(spec, dict):
            for op, operand in spec.items():
                if op in _REGO_OP:
                    out.append(f"{lhs} {_REGO_OP[op]} {_rego_literal(operand)}")
                elif op == "in":
                    out.append(f"{lhs} == {_rego_literal(operand)}[_]")
                elif op == "exists":
                    out.append(lhs if operand else f"not {lhs}")
                elif op == "glob":
                    out.append(f'glob.match({_rego_literal(operand)}, [], {lhs})')
                elif op == "regex":
                    out.append(f'regex.match({_rego_literal(operand)}, {lhs})')
                elif op == "startswith":
                    out.append(f"startswith({lhs}, {_rego_literal(operand)})")
                elif op == "endswith":
                    out.append(f"endswith({lhs}, {_rego_literal(operand)})")
                elif op == "cidr":
                    out.append(f'net.cidr_contains({_rego_literal(operand)}, {lhs})')
                else:
                    out.append(f"# unsupported-in-rego: {path} {op}={_rego_literal(operand)}")
        elif isinstance(spec, str) and any(c in "*?[]" for c in spec):
            out.append(f'glob.match({_rego_literal(spec)}, [], {lhs})')
        else:
            out.append(f"{lhs} == {_rego_literal(spec)}")
    return out or ["true"]


def to_rego(policy: Policy, package: str = "sentinel") -> str:
    """Export the policy as a readable subset of OPA Rego (human-facing)."""
    lines = [
        f"# Generated by sentinel-policy from policy {policy.name!r} "
        f"(v{policy.version}).",
        "# One-way export for OPA-native review. Effects: allow / deny / "
        "require_approval.",
        f"package {package}",
        "",
        f'default decision := "{policy.default.value}"',
        "",
    ]
    for r in policy.rules:
        cite = f"  # doctrine {r.doctrine}" if r.doctrine else ""
        if r.reason:
            lines.append(f"# {r.reason}")
        lines.append(f'decision := "{r.effect.value}" {{{cite}')
        for cond in _rego_conditions(r.match):
            lines.append(f"  {cond}")
        lines.append(f"}}  # rule {r.id}")
        lines.append("")
    return "\n".join(lines)
