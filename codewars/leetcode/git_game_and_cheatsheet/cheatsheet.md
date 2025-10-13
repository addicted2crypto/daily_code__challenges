📋 The Complete Git Commands Spreadsheet
Command
Purpose
Category
Emoji
git init
Initialize a new Git repository
Setup
🏗️
git clone <url>
Copy a remote repository to your local machine
Setup
📥
git add <file>
Stage a file for commit
Staging
➕
git add .
Stage all modified files
Staging
➕
git commit -m "message"
Commit staged changes with a message
Committing
📝
git commit --amend
Edit the last commit message or content
Committing
✏️
git status
Show the state of the working directory
Inspection
🔍
git log
Show commit history
Inspection
📜
git log --oneline
Show compact, one-line commit history
Inspection
📜
git log --graph --oneline --all
Show full branch history with graph
Inspection
🌲
git diff
Show unstaged changes
Inspection
⚖️
git diff --staged
Show staged changes (before commit)
Inspection
⚖️
git diff <commit1> <commit2>
Compare two commits
Inspection
⚖️
git show <commit>
Show details of a specific commit
Inspection
📦
git blame <file>
Show who last modified each line
Inspection
👥
git checkout <branch>
Switch to a branch
Branching
🎯
git checkout -b <new-branch>
Create and switch to a new branch
Branching
➕
git branch
List all local branches
Branching
🌿
git branch -a
List all local and remote branches
Branching
🌿
git branch -d <branch>
Delete a local branch
Branching
🗑️
git branch -D <branch>
Force delete a branch (even if unmerged)
Branching
🗑️
git merge <branch>
Merge another branch into current branch
Merging
🔗
git merge --no-ff <branch>
Merge with a commit node (preserves history)
Merging
🔗
git rebase <branch>
Move or combine a sequence of commits to a new base
Merging
🔄
git rebase -i HEAD~3
Interactively rebase last 3 commits
Merging
🔄
git stash
Temporarily save uncommitted changes
Stashing
📦
git stash pop
Restore the most recent stash and remove it
Stashing
📦
git stash list
List all stashes
Stashing
📦
git stash apply
Restore a stash without removing it
Stashing
📦
git remote -v
Show remote repository URLs
Remote
🌐
git remote add origin <url>
Add a remote repository
Remote
➕
git remote rename old new
Rename a remote
Remote
✏️
git remote remove origin
Remove a remote
Remote
🗑️
git pull
Fetch and merge changes from remote (usually origin/main)
Sync
⬇️
git pull --rebase
Fetch and rebase instead of merge
Sync
⬇️
git push
Push local commits to remote branch
Sync
⬆️
git push -u origin <branch>
Push and set upstream tracking
Sync
⬆️
git push --force
Force push (use with caution!)
Sync
⚠️
git push --force-with-lease
Safer force push — only if remote hasn’t changed
Sync
⚠️
git fetch
Download objects and refs from remote (no merge)
Sync
📥
git reset --soft HEAD~1
Undo commit, keep changes staged
Reset
🚫
git reset --mixed HEAD~1
Undo commit, unstage changes (default)
Reset
🚫
git reset --hard HEAD~1
Discard commit and changes
Reset
🚫
git clean -fd
Remove untracked files and directories
Cleanup
🧹
git rm <file>
Remove file from staging and working directory
Cleanup
🗑️
git mv <old> <new>
Rename or move a file
Cleanup
✏️
git tag <tagname>
Create a lightweight tag
Release
🏷️
git tag -a <tagname> -m "message"
Create an annotated tag
Release
🏷️
git show <tag>
Show tag details
Release
📦
git push origin <tag>
Push a tag to remote
Release
📤
git config --global user.name "Your Name"
Set global username
Config
⚙️
git config --global user.email "you@example.com"
Set global email
Config
⚙️
git config --global alias.l "log --oneline --graph --all"
Create custom alias
Config
⚙️
git config --global core.editor "code --wait"
Set default editor
Config
⚙️
git help <command>
Open help for any command
Help
❓

🔍 Quick Reference: Top 10 Most Used Commands
Command
Use Case
git add .
Stage all changes
git commit -m "message"
Save your work
git push
Share your work
git pull
Get others’ work
git status
Check what’s changed
git log --oneline
See history
git checkout -b new-feature
Start a new feature
git merge main
Integrate into main
git stash
Save work-in-progress
git reset --hard
Start over (dangerous!)