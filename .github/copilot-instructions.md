# OpenCTI connectors: Copilot instructions

The repository instructions for AI assistants live in
[`CLAUDE.md`](../CLAUDE.md) at the repository root. Read that file first and
follow it: it covers the repository layout, connector patterns, validation
commands, generated files and CI.

Keep this file as a pointer only. Update `CLAUDE.md` instead of duplicating
content here, so the two never drift apart.

<!-- filigran-conventions:start -->
## Commit, PR & issue conventions

All commits, pull requests and issues in this repository follow the
[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
specification with a GitHub issue reference:

```
type(scope?)!?: description (#issue)
```

- Types: `feat`, `fix`, `chore`, `docs`, `style`, `refactor`, `perf`, `test`,
  `build`, `ci`, `revert`.
- The description starts with a lowercase letter and has no trailing period;
  preserve acronyms and proper nouns.
- The old `[backend]` / `[frontend]` bracket prefixes are discontinued — use a
  Conventional Commits scope instead.
- Pull request titles **must** end with the related issue reference, e.g.
  `(#1234)`, and every pull request must be linked to an issue.
- Sign your commits.

When generating commit messages, PR titles or issue titles, always follow this
convention. See [`.github/LABELS.md`](.github/LABELS.md) for the full title and
label taxonomy.
<!-- filigran-conventions:end -->


<!-- filigran-model-policy:start -->
## GitHub Copilot model usage

To keep token consumption under control, pick the model that matches the task:

- **Opus 4.6** — reserve for complex work: deep reasoning, large refactors,
  architecture design, tricky debugging. It is significantly more
  token-expensive, so it is not the daily driver.
- **Sonnet / Gemini / GPT** — default for everyday tasks: autocomplete, small
  fixes, quick questions, code explanations.

We have a limited token budget — being mindful of the model you pick makes a
real difference at scale. Think of Opus as a specialist you call in when you
really need it.
<!-- filigran-model-policy:end -->
