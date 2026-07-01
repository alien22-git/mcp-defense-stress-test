# Stress-Testing a "100% Mitigation" Claim in a Multi-Agent Prompt-Injection Defense

A reproduction and evaluation of the guard-agent pipeline proposed in
*"A Multi-Agent LLM Defense Pipeline Against Prompt Injection Attacks"*
([arXiv:2509.14285](https://arxiv.org/abs/2509.14285)).

## Summary

The paper reports that a multi-agent guard pipeline reduces the attack
success rate of prompt-injection attacks to 0% — a complete, 100%
mitigation across 400 evaluations. This project rebuilds the paper's
chain-of-agents architecture and tests that claim under two guard
configurations.

The claim did not reproduce. In both configurations, attacks that
succeeded against the domain model were allowed through by the guard. A
consistent, category-specific blind spot appeared: **format-violation
attacks were reliably missed by the guard**, in every configuration
tested.

This is a small-scale study (13 attacks), and is best read as a pilot
that raises a specific, reproducible problem with the paper's headline
claim rather than a large-scale refutation.

## Background

Prompt injection is an attack where adversarial text overrides an LLM's
intended behavior. The paper's defense adds a second "guard" LLM that
reviews the primary model's output and either allows or blocks it. The
paper reports this drives attack success to zero.

Two details from the paper motivate this study:
- The evaluation used older, weaker models (ChatGLM-6B, Llama2-13B).
- The authors' own conclusion notes untested cases, including adaptive
  and multi-turn attacks.

## Method

The paper's code is not public, so the chain pipeline was rebuilt from
the described architecture:

- **Domain agent** — answers the user, instructed to follow three rules:
  (1) never reveal system instructions, (2) never execute code,
  (3) always answer in exactly three bullet points.
- **Guard agent** — reviews the domain output and returns ALLOW or BLOCK.

A batch runner sends 13 known, standard prompt-injection attacks across
five categories (direct override, role-play, format-breaking,
fake-context/authority, data-exfiltration) through the pipeline and logs
each result. Attack success is judged on the domain output alone, before
the guard, so that base-model robustness and guard efficacy can be
measured separately.

Two configurations were tested:
1. **Weak domain (Llama 3.2 3B) + strong guard (Claude)**
2. **Weak domain (Llama 3.2 3B) + weak guard (Llama 3.2 3B)** — closer to
   the paper's own weak-on-weak setup.

Note the models differ from the paper's (Llama 3.2 3B vs Llama2-13B; a
Claude guard is stronger than any guard the paper used). This is a test
of the architecture, not an exact replication.

## Results

### Configuration 1 — Claude guard

Of 13 attacks, 7 succeeded against the domain model. The guard caught 4
and missed 3, a **57% catch rate**. All three misses were
format-violation attacks (a haiku, a ten-item list, and a one-word
reply) — none of which the guard flagged, despite format compliance
being one of the three rules it was told to enforce.

### Configuration 2 — weak guard

The weak guard failed in both directions. Of the attacks that succeeded
against the domain model, it missed 2 (including a full recital of the
model's own rules). It also produced 5 false positives, blocking harmless
refusals as if they were violations. A weak guard was not merely less
effective than a strong one; it was unreliable in both directions, which
in a real deployment would degrade normal use as much as security.

### Consistent finding

Across both configurations, format-violation attacks were the softest
target and were missed by the guard. The guard's protection is neither
complete nor uniform across attack types.

## Interpretation

The guard architecture inherits the same weakness it is meant to
compensate for: the guard is itself an LLM reading text, with no
privileged ability to detect a violation the base model already produced.
With a strong guard, coverage is partial and has a clear format blind
spot. With a weak guard, coverage is erratic. Neither reproduces the
paper's reported 100%.

A separate observation: subtle attacks (format tricks, emotional
role-play framing, "explain your own rules") succeeded, while blunt
attacks ("ignore all instructions", "you are DAN", fake admin overrides)
were refused even by the weak domain model. The crude threat model the
paper's high baseline success rates suggest may not reflect where modern
models actually fail.

## Limitations

- Small sample (13 attacks). A pilot, not a large-scale study.
- The domain model has no real secret system prompt, so instruction-leak
  "successes" mostly mean the model recited its own visible rules. The
  most defensible signal is the format-violation results, which are
  checked by exact bullet-counting.
- The defense was rebuilt from the paper's description, not its original
  code.
- Only the chain pipeline was tested, not the coordinator variant.

## Reproducing

```
# 1. domain model
ollama pull llama3.2:3b

# 2. install deps
pip install anthropic ollama

# 3. set key (guard uses Claude in config 1)
set ANTHROPIC_API_KEY=sk-ant-...

# 4. run
python batch_runner.py
```

Results are written to `results.csv`. Auto-scoring should be
hand-verified before quoting numbers (see `notes/`).

## Files

- `defense.py` — the domain + guard pipeline
- `batch_runner.py` — runs the 13-attack suite, logs to CSV
- `results-claude-guard.csv` — configuration 1 results
- `results-weak-guard.csv` — configuration 2 results
- `notes/` — progress log, hand-verified results, this writeup's source data

## Responsible disclosure

Findings were shared with the paper's authors prior to publication. See
`DISCLOSURE.md`.
