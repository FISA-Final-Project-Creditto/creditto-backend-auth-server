## GIT 협업 규칙

### 커밋 전략

`git commit -m "type: 커밋 내용 작성"`
| 타입 | 의미 |
| ---------- | --------------------------- |
| `feat` | 새로운 기능 추가 (feature) |
| `fix` | 버그 수정 (bug fix) |
| `chore` | 코드 변경이 아닌 잡일, 설정 변경 등 |
| `build` | 의존성 추가, gradle 관련 변경 등 |
| `style` | 코드 포맷, 세미콜론, 공백 등 스타일 관련 수정 |
| `refactor` | 기능 변경 없이 코드 구조 개선 |
| `docs` | 문서 수정 |
| `test` | 테스트 코드 추가/수정 |
| `ci` | CI/CD 관련 설정 변경 |

### 브랜치 전략

- **기능 브랜치 전략 (github-flow)**

```
{type}/#issue

- 🚀 feat/#1
- 🚨 fix/#5
- 🔧 refactor/#13
- 📃 docs/#17
```

```
🚀 [main 브랜치]

git fetch origin main
git pull

🪾 [branch 생성]

git checkout -b {type}/#issue // git checkout -b feat/#1
git checkout {type}/#issue

💬 [생성 branch]

git commit -m "[type] commit message" // git commit -m "[feat] User 엔티티 생성"
git push origin {feature branch}

// ✅ PR -> code review -> merge

// ❌ delete feature branch

🗑️ [Merge 이후]

git checkout main
git branch -d {feature branch}
git push origin --delete {feature branch}
```
