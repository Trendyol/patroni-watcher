# Contributing Guide

Thank you for your interest in contributing to the Patroni Alarm System project! Please follow these guidelines when contributing to our project.

## How to Contribute?

### 1. Issues

* Before suggesting a new feature or reporting a bug, please check the existing issues.
* If the issue hasn't been reported yet, create a new one:
  * Clearly define the issue
  * Provide steps to reproduce the bug if possible
  * Explain the expected and actual behavior
  * Specify the platform and versions you're using

### 2. Development Workflow

1. Fork the project to your GitHub account
2. Clone your fork to your local machine:
   ```bash
   git clone https://github.com/Trendyol/patroni-watcher.git
   cd patroni-watcher 
   ```
3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/Trendyol/patroni-watcher.git
   ```
4. Create a new branch:
   ```bash
   git checkout -b feature/new-feature-name
   ```
   or
   ```bash
   git checkout -b bugfix/bug-fix-name
   ```
5. Make your changes
6. Commit your changes:
   ```bash
   git commit -m "A descriptive commit message"
   ```
7. Push your changes to your fork:
   ```bash
   git push origin feature/new-feature-name
   ```
8. Create a Pull Request on GitHub

### 3. Pull Request Process

* Clearly state what you've done in your PR
* Explain which issue your changes solve or which feature they add
* If possible, add tests that verify your changes
* Ensure your PR doesn't have conflicts with the main branch

## Code Standards

### Go Code Standards

* Follow the guidelines in [Effective Go](https://golang.org/doc/effective_go) and [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
* Format your code with `go fmt`
* Follow Go's conventional naming rules for variables and functions
* Avoid unnecessary comments and code
* Add proper documentation for all exported functions and structures

### Testing Requirements

* Add unit tests for new features and bug fixes
* Run tests with:
  ```bash
  go test ./...
  ```
* Add necessary mocks for integration tests

## Versioning

This project uses [Semantic Versioning](https://semver.org/). Version numbers follow the format: `MAJOR.MINOR.PATCH`.

## License

By contributing, you agree that your contributions will be licensed under the project's main license, the MIT License. See the `LICENSE` file for details.

## Communication

For questions or issues:

* Use GitHub Issues
* Join our community to communicate with other contributors and users

## Code of Conduct

Everyone contributing to this project agrees to follow these rules of conduct to ensure a fair, respectful, and professional environment:

* Use respectful and inclusive language
* Respect different perspectives and experiences
* Gracefully accept and give constructive feedback
* Aim for the best for the community
* Show empathy towards other community members

---

Thank you for contributing to the Patroni Watcher project! 