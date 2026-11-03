# Pitch deck

The 12-slide deck used for the a16z speedrun application, November 2026.
Every number in it was checked against this repository on November 1, 2026:
101 commits on main, 786 tests collected and 87 merged pull requests.
Those counts will drift as work lands; the deck does not update itself.

- `Aureproof-speedrun-deck.pdf` is the deck as a PDF, one page per slide in its
  final state.
- `deck/` is the [HyperFrames](https://hyperframes.heygen.com) source. Present it
  with `npx hyperframes present docs/pitch/deck` and press P for speaker notes.
- `diagrams/` holds the [Archify](https://github.com/belinwu/archify) inputs for
  the two diagram slides, the architecture and the end-to-end flow. Each box cites
  the lines of code it stands for, at commit `8c99d4f`. Render one with
  `archify finalize architecture diagrams/architecture.json out.html --repo-root .`
  (or `workflow` for `flow.json`). The PNGs in `deck/assets/` are those renders.

The deck says what is not true yet as plainly as what is: there are no users,
design partners or revenue, and no benchmark result on real agents.
