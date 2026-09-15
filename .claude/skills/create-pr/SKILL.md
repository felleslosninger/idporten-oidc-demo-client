---
name: create-pr
description: Create a pull request to main from the current branch — derive the Jira id from the branch name, run tests, push, title "ID-XXXX: …", fill .github/pull_request_template.md correctly, handle dependabot PRs and open it with gh. Use when asked to "create a PR", "open a pull request", "lag PR" or "opprett PR".
argument-hint: "[optional PR title text after the Jira id]"
---

# Create a PR from the current branch

Target `main` in `felleslosninger/idporten-oidc-demo-client`. `$ARGUMENTS` = title text after `ID-XXXX: `.

## 1. Preflight

```bash
git branch --show-current && git status --porcelain && git fetch origin main
git log --oneline origin/main..HEAD
gh pr list --head "$(git branch --show-current)" --state all --json number,title,url
```

Stop if: on `main`; nothing ahead of `origin/main`; an open PR already exists (report URL). Uncommitted
changes → ask, never commit unasked. Jira id = branch prefix `^(ID|PF)-[0-9]+`; missing → ask, never invent.

Run tests; never push a red build:

```bash
set -o pipefail; mvn -B test 2>&1 | grep -E "<<< (FAILURE|ERROR)!|BUILD (SUCCESS|FAILURE)"
```

## 2. Dependabots

Do this before the `.trivyignore` check — a bump can remove the need for an entry.

```bash
gh pr list --author app/dependabot --state open --json number,title,headRefName
```

For each open PR compare its version with `pom.xml` on the branch:

- **Stale** (branch already has the version or newer): comment `@dependabot rebase` on it
  (`gh pr comment <n> --body '@dependabot rebase'`); dependabot closes it within a minute. Do not merge it.
- **Not stale**: report it; merge only on the user's go (`git merge origin/main` first, then
  `git fetch origin <headRefName> && git merge --no-edit origin/<headRefName>`, rerun tests). Respect the
  version groups commented in `pom.xml`.

## 3. Trivyignore

`.trivyignore` empty → nothing to trim. Otherwise, for each entry check whether the dependency tree
(`mvn dependency:tree`) still has the affected version after step 2; remove entries that no longer apply.

## 4. Push

`git push` (or `git push -u origin <branch>` if no upstream). Never force-push.

## 5. Title

`ID-XXXX: <short description>`, 10–100 chars, usually Norwegian, same language as the commits. Use
`$ARGUMENTS` if given, else the main change from the commit log. CI allows prefixes `Bump`, `PF-`, `ID-` only.
Never write `(INTERNAL-COMMIT)`; never add labels `internal`/`manual-deploy`.

## 6. Body

Copy `.github/pull_request_template.md` verbatim. Only edits:

1. `SAK:` → `[ID-XXXX](https://digdir.atlassian.net/browse/ID-XXXX)`.
2. One bare bullet per change (a few words) between `SAK:` and `Sjekklister:`. Nothing covered by a
   checklist line gets a bullet.
3. `Eigar:` boxes `[x]`/`[ ]` only. Never touch `Kodeles:`. Never reword or annotate a line.

| Eigar line | Tick when |
|---|---|
| Vurdert Manual deploy / Vurdert "internal" | never |
| Avhengigheter til andre saker avklart | user confirmed, or the change has no related ticket |
| … dokumentert i catalog-info | no new runtime dependency on another component, or `catalog-info.yaml` updated |
| Har kjørt opp lokalt med docker-compose … | never — a human does it |
| Oppdatering/oppretting av regresjonstester … | user confirmed |
| Har oppdatert dependabots | step 2 done: nothing open, or stale ones commented and the rest merged/reported |
| Trimmet .trivyignore | step 3 done |

Unsure → leave unticked and say so in the report.

## 7. Create and report

```bash
gh pr create --base main --head "$(git branch --show-current)" --title "ID-XXXX: …" --body-file <scratchpad>/pr-body.md
```

End the body with the attribution line given in the session's system reminder. `--draft`, labels,
reviewers only if asked. Report URL, boxes left for the user, dependabot PRs handled, README status.
Never merge. Merging to `main` builds the image and opens image-update PRs in `idporten-cd` for all three
systest apps (`idporten-`, `ansattporten-`, `eidas-oidc-demo-client`).
