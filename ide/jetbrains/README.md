# GuardRail JetBrains integration

JetBrains IDEs (IntelliJ, PyCharm, WebStorm) can use GuardRail via:

## Option A — External Tools (zero plugin code)

1. **Settings → Tools → External Tools → +**
2. Name: `GuardRail Scan File`
3. Program: `python`
4. Arguments:
   ```
   -c "import json,sys; from guardrail.hybrid_scan import hybrid_scan; p=r'$FilePath$'; print(json.dumps(hybrid_scan(open(p,encoding='utf-8').read(), filename=p), indent=2))"
   ```
5. Working directory: `$ProjectFileDir$`
6. Environment: `PYTHONPATH=<path-to-guardrail-mcp>`

## Option B — MCP in AI Assistant / JetBrains AI

Register the STDIO MCP server the same way as Cursor:

```json
{
  "command": "python",
  "args": ["-m", "guardrail", "--mode", "stdio"],
  "env": { "PYTHONPATH": "/path/to/guardrail-mcp" }
}
```

## Option C — Full plugin

A full JPS plugin (Kotlin) can wrap the same CLI and show findings in the Problems tool window. Scaffold:

```
ide/jetbrains/plugin/
  src/main/kotlin/com/guardrail/ScanAction.kt
  build.gradle.kts
```

Use External Tools (A) for immediate adoption; promote to a marketplace plugin when branding/signing is ready.
