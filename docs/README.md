# docs/

Source for <https://kdairatchi.github.io/flaw/> — flaw's documentation
site, served via GitHub Pages + Jekyll + the `just-the-docs` remote
theme. Mirrors the CronLord docs aesthetic with flaw's own gemstone
palette.

## Structure

```
docs/
├── _config.yml                  # Jekyll + just-the-docs config
├── _includes/head_custom.html   # fonts, OG tags, favicon
├── _sass/
│   ├── color_schemes/flaw.scss  # gemstone palette (cream + emerald teal)
│   └── custom/custom.scss       # typography, hero, stats, severity pills
├── index.md                     # landing page
├── getting-started.md           # install + first scan + baselines
├── cli.md                       # every subcommand, flag, env var
├── rules.md                     # full rule catalog with severity pills
├── ci-integration.md            # GitHub Actions, SARIF, pre-commit, GitLab
├── authoring.md                 # rule contract + scaffold + validation
├── 404.html                     # 404 page
├── Gemfile                      # local preview
└── static/                      # hero art, logo, OG image
```

## Enable on GitHub

Already live if Pages is enabled. Otherwise:

1. Repo **Settings → Pages**
2. **Source:** Deploy from a branch
3. **Branch:** `main` / `/docs`
4. Save. First build takes a minute; the site comes up at
   `https://kdairatchi.github.io/flaw/`.

## Preview locally

```sh
cd docs
bundle install
bundle exec jekyll serve --baseurl ""
# open http://localhost:4000
```

> The `--baseurl ""` override is important for local preview because
> `_config.yml` sets `baseurl: /flaw` for the deployed site.

## Design choices

- **Theme:** `just-the-docs` — good search, left nav, easy to extend.
  Same choice as CronLord.
- **Palette:** warm parchment cream canvas, deep emerald teal
  (`#0f7a6b`) accent, muted amber blush for secondary highlights.
  Mirrors the "hold the code up to the light" gemology metaphor.
- **Type:** Fraunces for display, Inter for body, JetBrains Mono for
  code. Matches CronLord's editorial feel.
- **Components:** `.flaw-hero`, `.flaw-stats`, `.flaw-cats`,
  `.flaw-chip`, `.sev-*` pills. Defined in
  `_sass/custom/custom.scss`.
