---
status: accepted
---

# Keep delivery maturity out of compatibility identities

Delivery milestones change independently of the domain behavior that persisted
compatibility identities describe. Embedding a milestone label in such an
identity would force unrelated identity churn whenever delivery maturity
changes. We therefore choose domain-behavior terminology for production
compatibility identities while retaining delivery labels for planning and
evidence scope. This accepts one explicit identity cutover in exchange for
stable terminology across later maturity changes; exact behavior is owned by
the [Demo Slice v2 specification](../specs/demo-slice-v2.md).
