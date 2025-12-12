# GitHub Setup Guide

This guide will help you upload the Cybersecurity Hardening Toolkit to GitHub.

## Prerequisites

1. **Git Installation**: Download and install Git from https://git-scm.com/download/win
2. **GitHub Account**: Create an account at https://github.com if you don't have one

## Step 1: Install Git (if not already installed)

1. Download Git for Windows: https://git-scm.com/download/win
2. Run the installer with default settings
3. Restart your terminal/PowerShell after installation

## Step 2: Configure Git (First Time Only)

Open PowerShell and run:

```powershell
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

## Step 3: Navigate to Your Desktop Toolkit

```powershell
cd "$env:USERPROFILE\Desktop\cybersecurity-hardening-toolkit"
```

## Step 4: Initialize Git Repository

```powershell
git init
```

## Step 5: Add All Files

```powershell
git add .
```

## Step 6: Create Initial Commit

```powershell
git commit -m "Initial commit: Cybersecurity Hardening Toolkit"
```

## Step 7: Create GitHub Repository

1. Go to https://github.com and sign in
2. Click the **"+"** icon in the top right corner
3. Select **"New repository"**
4. Repository name: `cybersecurity-hardening-toolkit`
5. Description: `Professional, modular Cybersecurity Hardening Toolkit for Windows and Linux`
6. Choose **Public** or **Private**
7. **DO NOT** initialize with README, .gitignore, or license (we already have these)
8. Click **"Create repository"**

## Step 8: Connect Local Repository to GitHub

After creating the repository, GitHub will show you commands. Use these:

```powershell
git remote add origin https://github.com/YOUR_USERNAME/cybersecurity-hardening-toolkit.git
```

Replace `YOUR_USERNAME` with your actual GitHub username.

## Step 9: Push to GitHub

```powershell
git branch -M main
git push -u origin main
```

You'll be prompted for your GitHub username and password (or personal access token).

## Alternative: Using GitHub Desktop (Easier Method)

If you prefer a graphical interface:

1. Download GitHub Desktop: https://desktop.github.com/
2. Install and sign in with your GitHub account
3. Click **"File"** → **"Add Local Repository"**
4. Browse to: `C:\Users\Advait\Desktop\cybersecurity-hardening-toolkit`
5. Click **"Publish repository"**
6. Choose repository name and visibility
7. Click **"Publish Repository"**

## Step 10: Verify Upload

1. Go to your GitHub repository page
2. You should see all your files including:
   - README.md
   - QUICK_START.md
   - windows/ folder with all PowerShell scripts
   - linux/ folder with all bash scripts
   - .gitignore file

## Future Updates

When you make changes to files:

```powershell
cd "$env:USERPROFILE\Desktop\cybersecurity-hardening-toolkit"
git add .
git commit -m "Description of your changes"
git push
```

## Troubleshooting

### Git not recognized
- Make sure Git is installed and added to PATH
- Restart PowerShell after installation
- Try using Git Bash instead of PowerShell

### Authentication Issues
- Use a Personal Access Token instead of password
- Create token: GitHub → Settings → Developer settings → Personal access tokens
- Use token as password when prompted

### Push Rejected
- If repository has files, use: `git pull origin main --allow-unrelated-histories` first
- Then push again

## Repository Structure

Your repository should have:

```
cybersecurity-hardening-toolkit/
├── .gitignore
├── README.md
├── QUICK_START.md
├── GITHUB_SETUP.md
├── windows/
│   ├── hardening.ps1
│   ├── forensics.ps1
│   ├── browser-hardening.ps1
│   ├── firewall-check.ps1
│   ├── service-management.ps1
│   ├── user-policies.ps1
│   └── app-removal.ps1
└── linux/
    ├── hardening.sh
    ├── forensics.sh
    ├── service-management.sh
    └── firewall-config.sh
```

## Adding a License (Optional)

You may want to add a license file:

1. Go to your repository on GitHub
2. Click **"Add file"** → **"Create new file"**
3. Name it `LICENSE`
4. Choose a license template (MIT, Apache 2.0, etc.)
5. Commit the file

---

**Need Help?** Check GitHub's documentation: https://docs.github.com/

