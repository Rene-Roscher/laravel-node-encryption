# Setup Guide

## 1. Create NPM Token

1. Login to [npmjs.com](https://www.npmjs.com/)
2. Profile → **Access Tokens** → **Generate New Token**
3. Choose **Automation** type
4. Copy token (starts with `npm_...`)

## 2. Add GitHub Secret

1. Go to your GitHub repository
2. **Settings** → **Secrets and variables** → **Actions**
3. Add secret: `NPM_TOKEN` = your token

## 3. Push Repository

```bash
cd laravel-node-encryption
git init
git add .
git commit -m "feat: initial release"
git remote add origin https://github.com/Rene-Roscher/laravel-node-encryption.git
git push -u origin main
```

## 4. Publish Package

### Option A: Manual (first release)
```bash
npm publish --access public
```

### Option B: GitHub Actions
1. Go to **Actions** tab
2. Select **Publish Package**
3. **Run workflow** → Choose version type → Run

## GitHub Actions

### CI (`ci.yml`)
- Runs on every push/PR
- Tests on Node 16, 18, 20
- Tests on Windows, Linux, macOS
- Laravel 8.x - 11.x integration tests

### Publish (`publish.yml`)
- Manual trigger via GitHub UI
- Auto trigger on tags (`v*`)
- Publishes to NPM & GitHub Packages
- Creates GitHub release

### Release (`release.yml`)
- Automatic changelog generation
- Uses Release Please

## Version Updates

### Via GitHub UI
1. Actions → Publish Package → Run workflow
2. Choose: `patch`, `minor`, or `major`

### Via Git Tags
```bash
npm version patch -m "chore: release %s"
git push origin main --tags
```

## Monitoring

- **NPM**: https://www.npmjs.com/package/laravel-node-encryption
- **Actions**: https://github.com/Rene-Roscher/laravel-node-encryption/actions
- **Downloads**: https://npm-stat.com/charts.html?package=laravel-node-encryption