# Issue tracker: GitHub

Issues and specs for this repository live in GitHub Issues. Use the `gh`
CLI from this checkout; infer `hallucination-studio/whisper` from its remote.

## Conventions

- Create: `gh issue create --title "..." --body "..."`
- Read: `gh issue view <number> --comments`
- List: `gh issue list --state open --json number,title,body,labels,comments`
- Comment: `gh issue comment <number> --body "..."`
- Label: `gh issue edit <number> --add-label "..."` or `--remove-label "..."`
- Close: `gh issue close <number> --comment "..."`

Use heredocs for multiline issue bodies. When a skill says "publish to the
issue tracker", create a GitHub issue. When it says "fetch the relevant
ticket", read the issue and its comments.

## Pull requests as a triage surface

**PRs as a request surface: no.**

## Dependencies

Use GitHub sub-issues for parent/child relationships and native issue
dependencies for blocking edges. If either feature is unavailable, record
`Part of #<map>` and `Blocked by: #<number>` in the issue body.

A ticket is ready only when all blocking issues are closed. Claim work with
`gh issue edit <number> --add-assignee @me`.

## RF world-model execution

The active parent is [Spec #163](https://github.com/hallucination-studio/whisper/issues/163).
The previous open graph was closed as not planned, without transferring status
or blocking edges. Only the new native child/dependency graph determines order.

Every new ticket freezes Work, independent Standards review, independent Spec
review, and the applicable RF algorithm under [execution rules](ticket-execution.md).
Use `ready-for-agent` only on a specified slice whose blockers are all closed;
blocked slices need no triage label. The aggregate specification stays open
until its implementation and real acceptance children complete.
