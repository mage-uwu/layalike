"""Compare three ways of making policy decisions with Laya, with no fine-tuning.

  plain     one choice question listing the decisions (what Laya is usually asked)
  prompted  the same question with the whole policy written into its instructions
  pnp       each condition asked as a yes/no question, the rules applied in code

    python -m pnp.evaluate --weights weights/laya --out pnp/results
"""
import argparse
import itertools
import json
import os
import time
from collections import defaultdict

from pnp.policies import SUITES
from pnp.policy import Policy

CHECKPOINTS = {"english": None, "typed-decisions": "typed-decisions", "multilingual": "multilingual"}


def gold_decision(policy, labels):
    """The policy's decision on the labels; every unlabeled condition must not change it."""
    open_ = [n for n, v in labels.items() if v is None]
    seen = set()
    for bits in itertools.product((True, False), repeat=len(open_)):
        seen.add(policy.execute({**labels, **dict(zip(open_, bits))})["decision"])
    if len(seen) != 1:
        raise ValueError("unlabeled conditions change the decision: %r" % labels)
    return seen.pop()


def choice_question(spec, policy, with_policy):
    instructions = spec["question"]
    if with_policy:
        instructions += "\n" + policy.as_text()
    return {"decision": {"type": "choice", "instructions": instructions,
                         "criteria": {d: spec["descriptions"][d] for d in policy.decisions}}}


def run(agent, budget):
    rows = []
    for spec, cases in SUITES:
        policy = Policy.from_dict(spec)
        plain_q = choice_question(spec, policy, False)
        prompted_q = choice_question(spec, policy, True)
        for state, labels in cases:
            gold = gold_decision(policy, labels)
            row = {"suite": spec["name"], "state": state, "gold": gold}

            t = time.perf_counter()
            row["plain"] = agent.predict(state, plain_q)["answers"]["decision"]["choice"]
            row["plain_ms"] = (time.perf_counter() - t) * 1000

            t = time.perf_counter()
            row["prompted"] = agent.predict(state, prompted_q, **budget)["answers"]["decision"]["choice"]
            row["prompted_ms"] = (time.perf_counter() - t) * 1000

            t = time.perf_counter()
            res = policy.decide(agent, state)
            row["pnp_ms"] = (time.perf_counter() - t) * 1000
            row["pnp"] = res["decision"]
            row["pnp_probability"] = res["probability"]
            row["conditions"] = res["conditions"]
            row["condition_errors"] = [n for n, v in labels.items()
                                       if v is not None and (res["conditions"][n] >= policy.threshold) != v]
            row["conditions_scored"] = sum(v is not None for v in labels.values())
            rows.append(row)
    return rows


def summarise(rows):
    by = defaultdict(list)
    for r in rows:
        by[r["suite"]].append(r)
    by["all"] = rows
    out = {}
    for suite, rs in by.items():
        n = len(rs)
        out[suite] = {
            "cases": n,
            **{m: sum(r[m] == r["gold"] for r in rs) / n for m in ("plain", "prompted", "pnp")},
            "condition_accuracy": 1 - sum(len(r["condition_errors"]) for r in rs) / sum(r["conditions_scored"] for r in rs),
            **{m + "_ms": sum(r[m + "_ms"] for r in rs) / n for m in ("plain", "prompted", "pnp")},
        }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--weights", default="weights/laya")
    ap.add_argument("--checkpoints", nargs="+", default=list(CHECKPOINTS))
    ap.add_argument("--out", default="pnp/results")
    args = ap.parse_args()

    import laya
    import torch
    torch.set_num_threads(os.cpu_count())
    os.makedirs(args.out, exist_ok=True)
    report = {}
    for name in args.checkpoints:
        sub = CHECKPOINTS[name]
        agent = laya.load(args.weights, subfolder=sub, device="cpu") if sub else laya.load(args.weights, device="cpu")
        # The written-out policy needs more room for the question than the shipped budgets give.
        budget = {"max_len": 1024, "head_max_len": 512}
        agent.predict("warm up", choice_question(*[(s, Policy.from_dict(s)) for s, _ in SUITES][0], False))
        rows = run(agent, budget)
        report[name] = summarise(rows)
        with open(os.path.join(args.out, "%s.jsonl" % name), "w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        print(name, json.dumps(report[name]["all"], indent=1))
        del agent
    with open(os.path.join(args.out, "summary.json"), "w") as f:
        json.dump(report, f, indent=1)


if __name__ == "__main__":
    main()
