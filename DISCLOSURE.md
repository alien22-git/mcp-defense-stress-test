# Responsible Disclosure

## Summary

This note documents contact with the authors of *"A Multi-Agent LLM
Defense Pipeline Against Prompt Injection Attacks"* (arXiv:2509.14285)
regarding findings from an independent reproduction of their chain-of-agents
defense.

## What was found

A rebuild of the paper's chain pipeline did not reproduce the reported
100% mitigation. In a configuration using a stronger guard than the paper
employed, 3 of 7 successful attacks were allowed through by the guard (a
57% catch rate). All misses were format-violation attacks. In a weak-guard
configuration closer to the paper's own setup, the guard missed attacks
and also produced false positives on benign outputs.

## Why this is being shared

The intent is constructive. The finding suggests the "100% mitigation"
claim is sensitive to model choice and attack category, and does not hold
for format-violation attacks in the configurations tested. This is
relevant context for anyone deploying the architecture on the strength of
the paper's headline number.

## Scope and limitations (stated plainly to the authors)

- Small sample (13 attacks); a pilot, not a large-scale refutation.
- Different models than the original (Llama 3.2 3B; a Claude guard).
- Rebuilt from the paper's description, as no code was released.
- Only the chain pipeline was tested.

## Draft message to authors

> Dear authors,
>
> I'm an undergraduate researcher studying multi-agent LLM security. I
> reproduced the chain-of-agents defense from your paper (arXiv:2509.14285)
> and wanted to share a finding before publishing a short writeup.
>
> In my rebuild, the guard did not achieve full mitigation. Using a guard
> stronger than the one in your evaluation, it still allowed through the
> format-violation attacks in my test suite (a 57% catch rate over the
> attacks that succeeded against the base model). A weaker guard was
> unreliable in both directions.
>
> I recognize this is a small study with different models than yours, and
> I've stated those limitations clearly in the writeup. My aim is
> constructive — to note that the 100% result appears sensitive to model
> choice and attack category. I'd welcome any correction if I've
> misrepresented the architecture.
>
> Writeup and code: [link]
>
> Thank you for the work, and for making the design clear enough to
> rebuild.
