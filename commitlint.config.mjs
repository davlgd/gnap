// Commit subject conventions, described in CONTRIBUTING.md under "Commit messages".
//
// commitlint is installed by mise as a standalone npm tool, so shared configs such as
// @commitlint/config-conventional can't be resolved from here: every rule is set below.

// Capitalised, these open a subject that is a sentence rather than an imperative, as in
// GitHub's default `Update file.md`.
const COMMIT_VERBS = new Set(`
  add address allow bump change check clarify complete correct create deduplicate
  delete deprecate document drop edit enable ensure expose extract fix harden
  implement improve inline introduce list make mention merge migrate move prepare
  publish raise refactor refresh reject remove rename reorganize replace require
  restore restrict revert rewrite run set simplify split support switch test
  tweak unify update upgrade use validate verify wire
`.trim().split(/\s+/));

export default {
  // A Conventional Commits header, with an optional scope and breaking-change `!`.
  parserPreset: {
    parserOpts: {
      headerPattern: /^([a-z]+)(?:\(([^()\s](?:[^()]*[^()\s])?)\))?!?: (\S.*)$/,
      headerCorrespondence: ['type', 'scope', 'subject'],
    },
  },

  // The default ignores let `fixup!` and `squash!` commits through.
  defaultIgnores: false,
  ignores: [(message) => /^Merge /.test(message) || /^Revert ".+"/.test(message)],

  helpUrl: 'https://github.com/davlgd/gnap/blob/main/CONTRIBUTING.md#commit-messages',

  plugins: [
    {
      rules: {
        'header-no-autosquash': ({ header }) => [
          !/^(fixup|squash|amend)! /.test(header ?? ''),
          'an autosquash marker is left over, run `git rebase -i --autosquash`',
        ],
        'subject-lowercase-verb': ({ subject }) => {
          const first = (subject ?? '').split(/\s+/)[0];
          const capitalised = /^[A-Z]/.test(first) && COMMIT_VERBS.has(first.toLowerCase());
          return [!capitalised, `subject must start with a lowercase verb, write \`${first.toLowerCase()}\``];
        },
      },
    },
  ],

  rules: {
    'body-empty': [2, 'always'],
    'footer-empty': [2, 'always'],
    'header-max-length': [2, 'always', 100],
    'header-no-autosquash': [2, 'always'],
    'header-trim': [2, 'always'],
    'subject-empty': [2, 'never'],
    'subject-full-stop': [2, 'never', '.'],
    'subject-lowercase-verb': [2, 'always'],
    'type-empty': [2, 'never'],
    'type-enum': [2, 'always', ['build', 'chore', 'ci', 'docs', 'feat', 'fix', 'perf', 'refactor', 'revert', 'test']],
  },
};
