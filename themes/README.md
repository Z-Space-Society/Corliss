# Themes

A theme changes how one Corliss deployment looks and what its prose pages say,
without forking the app.

## How a theme is chosen

Each folder here is named for the domain it dresses:

```
themes/
  staging.sharedcomputer.network/
  cascadia.social/
```

Corliss takes the host out of `PUBLIC_BASE_URL` and uses the folder of that
name. A deployment is themed by its folder existing, with nothing to set. A host
with no folder (`sharedcomputer.network`, today) gets the default look.

`THEME` in the environment overrides the choice. Its main use is local: see
[Trying a theme locally](#trying-a-theme-locally). A hand-set `THEME` naming a
folder that doesn't exist fails Django's system check (`corliss.E003`), so a
typo fails the deploy rather than quietly serving the default.

## Add only what you change

A theme mirrors the app's own layout:

```
<domain>/
  templates/   shadows corliss/templates/
  static/      shadows corliss/static/
```

Django looks in the theme first and in the app second, **one file at a time**.
A file the theme has wins; a file it doesn't have comes from the app. A theme
holding a single `templates/about_system.html` changes that one page and
nothing else.

Either folder can be missing. A theme with only `static/` is fine.

## What to override

### Colours: `static/css/theme.css`

The app ships an empty `theme.css` and loads it after `base.css`, so a theme's
copy redefines the design tokens in `base.css`'s `:root`:

```css
:root {
  --bg: oklch(0.5 0.14 255);
  --brand-accent: #000;
}
```

The useful ones: `--bg`, `--surface`, `--text`, `--accent` (buttons, links,
focus rings) and `--brand-accent` (the logo and the accented half of the
wordmark, defaulting to `--accent`). The full list is at the top of
`corliss/static/css/base.css`. Plain CSS rules work here too.

### The site's name and chrome: partials

| File | What it is |
|---|---|
| `templates/_site_title.html` | The site name after every page's own title: "Home · **SCN**". Keep it on one line. |
| `templates/_brand.html` | The logo and wordmark in the nav. |
| `templates/_footer_copy.html` | The copyright line in the footer. |
| `static/favicon.svg`, `static/favicon.ico` | The browser tab icon. |

### Whole pages

Copy the app's template into the theme's `templates/` under the same name and
edit it. The file name is the template's, which is not always the URL:

| URL | Template |
|---|---|
| `/about/` | `about.html` |
| `/about/system/` | `about_system.html` |
| `/about/team/` | `about_team.html` |
| `/` | `home.html` |
| `/auth/login` | `login.html` |

The about pages are the ones meant for this: they are prose and take no context
beyond what the nav needs. `about_team.html` also receives `avatars`, looked up
from the handles in `corliss.views.TEAM_HANDLES`.

## Rules

- **Override partials and pages, never `base.html`.** It carries the nav's
  access rules, and a themed copy would stop receiving fixes to them.
- **A copied page does not pick up later changes to the original.** When
  Corliss is upgraded, compare each copied page against the app's.
- **A theme is templates and static files only.** No Python and no settings.
- **Names are an interface.** The partials, templates and tokens above are what
  themes depend on, so renaming one in the app silently un-themes every
  deployment using it.

## Trying a theme locally

Local `PUBLIC_BASE_URL` is localhost, which has no folder, so name the theme in
`.env`:

```
THEME=staging.sharedcomputer.network
```

Then `./manage.py collectstatic --noinput` (theme CSS is collected like the
app's) and reload the page. Remove the line to go back to the default.

## Shipping a theme

Themes ship with Corliss: commit, release, and bump `corliss_version` in
zai-ops. The corliss role hands `collectstatic` the public URL, so the matching
folder is picked up with nothing else to set.
