# Security Guidelines

## API Key Management

**NEVER commit API keys to Git!**

### Safe Practices:

1. **Use Environment Variables**:
   ```bash
   set GOPLUS_API_KEY=your_actual_api_key_here
   ```

2. **Use .env file** (already in .gitignore):
   ```bash
   copy env.example .env
   # Edit .env with your actual API key
   ```

3. **For Testing**: Use placeholder values in test scripts
4. **For Production**: Configure through Smithery platform

### Files to Never Commit:

- `.env` files
- Any file containing `*api-key*` or `*secret*`
- Test files with real API keys
- Configuration files with hardcoded keys

### If You Accidentally Commit an API Key:

1. **Immediately rotate the API key** on GoPlus Security platform
2. **Remove the key from Git history**:
   ```bash
   git filter-branch --force --index-filter 'git rm --cached --ignore-unmatch path/to/file' --prune-empty --tag-name-filter cat -- --all
   ```
3. **Force push** to update remote repository
4. **Update .gitignore** to prevent future commits

## Environment Setup

### Development:
```bash
# Copy example file
copy env.example .env

# Edit .env with your API key
# .env is already in .gitignore
```

### Production:
- Configure API keys through Smithery platform
- Use environment variables in deployment
- Never hardcode keys in source code

## Testing

Use placeholder values in test files:
```powershell
$API_KEY = "YOUR_GOPLUS_API_KEY" # Replace with actual key for testing
```

Never commit test files with real API keys!
