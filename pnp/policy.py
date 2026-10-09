"""PNP-lite: a structured policy executed over Laya's yes/no perceptions.

A policy names its conditions (each one a yes/no question Laya answers about the state) and lists
if/then rules over them. The first rule whose condition holds decides; `default` decides when none
do. Laya does the perception, this module does the logic, so the rules are followed exactly.

    policy = Policy.from_dict({
        "conditions": {"authorized": "Is the activity explicitly authorized or approved?", ...},
        "rules": [{"if": "not authorized and (stolen_creds or malware)", "then": "contain"}, ...],
        "default": "close",
    })
    result = policy.decide(agent, state)

Rule conditions are boolean expressions over condition names using `and`, `or`, `not` and
parentheses; anything else is rejected when the policy is built.
"""
import ast
import itertools
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


def _check_expr(node: ast.AST, names: set) -> None:
    if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
        for v in node.values:
            _check_expr(v, names)
    elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        _check_expr(node.operand, names)
    elif isinstance(node, ast.Name):
        if node.id not in names:
            raise ValueError("rule uses unknown condition %r" % node.id)
    else:
        raise ValueError("rules may only use condition names, and, or, not, parentheses")


def _eval_expr(node: ast.AST, truth: Dict[str, bool]) -> bool:
    if isinstance(node, ast.BoolOp):
        vals = (_eval_expr(v, truth) for v in node.values)
        return all(vals) if isinstance(node.op, ast.And) else any(vals)
    if isinstance(node, ast.UnaryOp):
        return not _eval_expr(node.operand, truth)
    return truth[node.id]


@dataclass
class Rule:
    when: str
    then: str
    tree: ast.AST = field(repr=False, default=None)


@dataclass
class Policy:
    conditions: Dict[str, str]
    rules: List[Rule]
    default: str
    threshold: float = 0.5

    @classmethod
    def from_dict(cls, spec: Dict[str, Any]) -> "Policy":
        names = set(spec["conditions"])
        rules = []
        for r in spec["rules"]:
            tree = ast.parse(r["if"], mode="eval").body
            _check_expr(tree, names)
            rules.append(Rule(r["if"], r["then"], tree))
        return cls(dict(spec["conditions"]), rules, spec["default"], spec.get("threshold", 0.5))

    @property
    def decisions(self) -> List[str]:
        return list(dict.fromkeys([r.then for r in self.rules] + [self.default]))

    def execute(self, truth: Dict[str, bool]) -> Dict[str, Any]:
        """Run the rules on known truth values; returns the decision and the rule that fired."""
        for i, r in enumerate(self.rules):
            if _eval_expr(r.tree, truth):
                return {"decision": r.then, "rule": i}
        return {"decision": self.default, "rule": None}

    def distribution(self, probs: Dict[str, float]) -> Dict[str, float]:
        """P(decision), treating the condition probabilities as independent.

        Enumerates every truth assignment, so it is exact under that assumption and meant for
        policies with a handful of conditions (2^n assignments).
        """
        names = list(self.conditions)
        out = {d: 0.0 for d in self.decisions}
        for bits in itertools.product((True, False), repeat=len(names)):
            p = 1.0
            for n, b in zip(names, bits):
                p *= probs[n] if b else 1.0 - probs[n]
            out[self.execute(dict(zip(names, bits)))["decision"]] += p
        return out

    def questions(self) -> Dict[str, Dict[str, Any]]:
        return {n: {"type": "noul", "instructions": q} for n, q in self.conditions.items()}

    def decide(self, agent: Any, state: Any, **predict_kwargs: Any) -> Dict[str, Any]:
        """Ask Laya every condition in one call, then apply the rules."""
        answers = agent.predict(state, self.questions(), **predict_kwargs)["answers"]
        probs = {n: float(answers[n]["noul"]) for n in self.conditions}
        truth = {n: p >= self.threshold for n, p in probs.items()}
        fired = self.execute(truth)
        dist = self.distribution(probs)
        return {**fired, "conditions": probs, "probability": dist[fired["decision"]],
                "distribution": dist}

    def as_text(self) -> str:
        """The policy as plain-language rules, for putting it in a prompt instead."""
        lines = ["Conditions:"]
        lines += ["- %s: %s" % (n, q) for n, q in self.conditions.items()]
        lines.append("Apply the first rule that matches:")
        lines += ["%d. If %s, answer %s." % (i + 1, r.when, r.then) for i, r in enumerate(self.rules)]
        lines.append("%d. Otherwise, answer %s." % (len(self.rules) + 1, self.default))
        return "\n".join(lines)
