<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="skarvel-logo-white.png">
    <source media="(prefers-color-scheme: light)" srcset="skarvel-logo.png">
    <img src="skarvel-logo-white.png" alt="Skarvel" width="360">
  </picture>
</p>

<h3 align="center">Hunt malicious git repositories.</h3>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.26-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/deps-zero-e3242b?style=flat-square" alt="Zero dependencies">
  <img src="https://img.shields.io/badge/platforms-GitHub%20%7C%20Bitbucket-181717?style=flat-square&logo=github" alt="Platforms">
  <img src="https://img.shields.io/badge/use-threat%20hunting-e3242b?style=flat-square" alt="Threat hunting">
</p>

---

**Skarvel** takes a single indicator of compromise, finds every public repository carrying it, digs through all their branches and pull requests, mines fresh IoCs from confirmed payloads, and keeps hunting.

## Features

- Hunts an IoC: domain, IP, URL, secret, raw, base64 or hex
- Scans **every** branch and pull request
- Scores each repo as **malicious** or **review**
- Flags forged commit timestamps
- Mines new C2 indicators and follows them automatically
- Live terminal dashboard plus a plain-text report

## Quick start

```sh
go build -o skarvel ./cmd/skarvel
export GITHUB_TOKEN=ghp_...   

./skarvel --ioc codeprettier.pro    
./skarvel -r owner/repo             
./skarvel --ioc evil.tld --platform bitbucket
```

Results land in `skarvel_output_<date>_<time>.txt`.