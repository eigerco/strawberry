# Contributing

## Strawberry

To contribute to the Strawberry implementation, start with the proper development copy.
You may want to use the GitHub interface to fork [Strawberry](https://github.com/eigerco/strawberry) and check out your fork.
For development environment setup and first build, see [Strawberry README](https://github.com/eigerco/strawberry/README.md)

### Legal Notice

When contributing to this project, you must agree that you have authored 100% of the content, have the necessary rights, and that the content you contribute may be provided under the project license.

Any JAM-implementation code which is viewed before or during implementation must be declared.

## Versioning

The project uses [SemVer](http://semver.org/) for versioning.
For the versions available, see the [tags on this repository](https://github.com/eigerco/strawberry/tags).

## Developer Workflow

Changes to the project are proposed through pull requests. The general pull request workflow is as follows:
1. Fork this project on GitHub and check out your copy of the repository to start contributing.
2. Ensure your fork is up-to-date and create a topic branch for your feature or bug fix.
3. Do your changes and add relevant tests. Each commit and tag should be signed using your GPG key.
4. Ensure any install or build dependencies are removed before the end of the layer when doing a build.
5. Update the README.md with details of changes to the interface, this includes new environment variables, exposed ports, proper file locations and container parameters.
6. Increase the version numbers in any example files and the README.md to the new version this Pull Request represents.
7. You may merge the Pull Request once you have at least one accepting review.

When merging the PR to the `main` branch choose the merging strategy that won't affect the commit timeline. Do not force-push.

When creating a pull request, its description should reference the corresponding issue ID.

Project history should be linear and bisect-able so that when regressions are identified it could be easily to use git bisect to be able to pin-point the exact commit which introduced the regression. This requires that every commit is able to be built and passes all lints and tests. So if your pull request includes multiple commits be sure that each and every commit is able to be built and passes all checks performed by CI.

### A note on "big" changes

When planning "big" changes to the project, it's encouraged to ask for feedback on an issue before implementing things in code. The created issue should explain, at a minimum:

* The motivation for such a change.
* What would be the suggested implementation and what other alternatives were considered.

How big is "big"? As a rule of thumb, if the work spans more than one coding day, it's probably advisable to create an issue first and then work on it after confirmation. However, this may differ depending on the contributor context. I.e. if the author is already a maintainer, the base context will be high and the risk of rejection low. It is probably the opposite in the case of an external, non-habitual contributor. So, the author should use common sense here.

## Style Guides

### Commit Messages

Commits should be [atomic](https://en.wikipedia.org/wiki/Atomic_commit#Atomic_commit_convention) and broken down into logically separate changes. Diffs should also be made easy for reviewers to read and review, so formatting fixes or code moves should not be included in commits with actual code changes.

We are using the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) convention for our commit messages. This convention dovetails with SemVer, describing the features, fixes, and breaking changes in commit messages.

### Code style

Refer to general coding style guidelines for the Go programming language [here](https://go.dev/doc/effective_go) for detailed guidance about contributing to the project.

Code must be idiomatic.

## I Have a Question

Before you ask a question, searching for existing [Issues](/issues) that might help you is best. In case you have found a suitable issue and still need clarification, you can write your question in this issue. It is also advisable to search the internet for answers first.

If you still feel the need to ask a question and need clarification, we recommend the following:

- Open an [Issue](/issues/new).
- Provide as much context as possible about what you're running into.
- Provide project and platform versions (nodejs, npm, etc), depending on what seems relevant.

