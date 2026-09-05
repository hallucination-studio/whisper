# Future scope beyond the first RF room

The accepted first-room implementation is defined by
[RF world-model v1](specs/rf-world-model-v1.md), with its only live execution graph
in [Spec #163](https://github.com/hallucination-studio/whisper/issues/163).
Phone initialization, heterogeneous fixed RF, array calibration, joint0–2-person
state, history, prediction and persistent service are already in that target;
they are not separate speculative programs.

Only these capabilities remain later intent:

- More than two people, with actual coupled multi-person data and an explicit
  state-complexity budget.
- Fine 3D body pose and activity-conditioned simulation, with suitable spatial
  labels and actual action variables.
- Joint multi-room presence and trajectory association, including cross-room RF
  influence and door handoffs, without adding independent room counts.
- Precise unknown furniture/structure reconstruction beyond phone initialization
  and verified RF change detection.
- Additional concrete RF hardware families and mobile platforms through the
  accepted observation/scene contracts, after actual capability qualification.

These extensions use the same facts, geometry, model-run, state and version
boundaries. They receive a bounded specification and fresh implementation
issues when selected. There is no separate RSSM/Mamba/MoT or foundation-model
roadmap and no obligation to preserve the retired statistical product.
