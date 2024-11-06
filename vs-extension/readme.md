Based on the search results, I'll provide a complete implementation for a VSCode extension that properly handles Python library installation and Streamlit integration. Here's the detailed implementation:

## Project Structure
```
aider-vscode/
├── package.json
├── src/
│   ├── extension.ts
│   ├── python/
│   │   ├── requirements.txt
│   │   ├── app.py          # Your Streamlit app
│   │   └── install.py      # Python dependency installer
├── .vscodeignore
└── README.md
```

## 1. Package Configuration
```json
{
  "name": "aider-vscode",
  "displayName": "Aider VSCode",
  "description": "AI pair programming with Aider in VSCode",
  "version": "0.1.0",
  "engines": {
    "vscode": "^1.74.0"
  },
  "categories": ["Other"],
  "activationEvents": ["onCommand:aider.startChat"],
  "main": "./out/extension.js",
  "contributes": {
    "commands": [
      {
        "command": "aider.startChat",
        "title": "Start Aider Chat"
      }
    ],
    "configuration": {
      "title": "Aider",
      "properties": {
        "aider.port": {
          "type": "number",
          "default": 8501,
          "description": "Port for Streamlit server"
        }
      }
    }
  },
  "scripts": {
    "vscode:prepublish": "npm run compile",
    "compile": "tsc -p ./",
    "watch": "tsc -watch -p ./",
    "pretest": "npm run compile"
  },
  "devDependencies": {
    "@types/vscode": "^1.74.0",
    "@types/node": "^16.18.34",
    "typescript": "^5.1.3"
  }
}
```

## 2. Extension Implementation
```typescript
// src/extension.ts
import * as vscode from 'vscode';
import * as path from 'path';
import { spawn } from 'child_process';

export async function activate(context: vscode.ExtensionContext) {
    let currentPanel: vscode.WebviewPanel | undefined = undefined;
    let streamlitProcess: any;

    const startAider = vscode.commands.registerCommand('aider.startChat', async () => {
        try {
            // Install requirements first
            await installRequirements(context.extensionPath);

            // Get configuration
            const config = vscode.workspace.getConfiguration('aider');
            const port = config.get('port') || 8501;

            // Create and show panel
            if (currentPanel) {
                currentPanel.reveal(vscode.ViewColumn.Two);
            } else {
                currentPanel = vscode.window.createWebviewPanel(
                    'aiderChat',
                    'Aider Chat',
                    vscode.ViewColumn.Two,
                    {
                        enableScripts: true,
                        retainContextWhenHidden: true,
                        localResourceRoots: [vscode.Uri.file(context.extensionPath)]
                    }
                );

                // Start Streamlit server
                const pythonPath = await getPythonPath();
                streamlitProcess = spawn(pythonPath, [
                    '-m', 'streamlit', 'run',
                    path.join(context.extensionPath, 'src', 'python', 'app.py'),
                    '--server.port', port.toString(),
                    '--server.address', 'localhost',
                    '--server.headless', 'true'
                ]);

                // Handle stdout
                streamlitProcess.stdout.on('data', (data: Buffer) => {
                    console.log(`Streamlit: ${data}`);
                });

                // Handle stderr
                streamlitProcess.stderr.on('data', (data: Buffer) => {
                    console.error(`Streamlit Error: ${data}`);
                });

                // Set webview content
                currentPanel.webview.html = getWebviewContent(port);

                // Handle panel disposal
                currentPanel.onDidDispose(() => {
                    currentPanel = undefined;
                    if (streamlitProcess) {
                        streamlitProcess.kill();
                    }
                });
            }
        } catch (error) {
            vscode.window.showErrorMessage(`Failed to start Aider: ${error}`);
        }
    });

    context.subscriptions.push(startAider);
}

async function installRequirements(extensionPath: string): Promise<void> {
    return new Promise(async (resolve, reject) => {
        try {
            const pythonPath = await getPythonPath();
            const requirementsPath = path.join(extensionPath, 'src', 'python', 'requirements.txt');
            
            const pip = spawn(pythonPath, [
                '-m', 'pip', 'install', '-r', requirementsPath
            ]);

            pip.stdout.on('data', (data: Buffer) => {
                console.log(`pip: ${data}`);
            });

            pip.stderr.on('data', (data: Buffer) => {
                console.error(`pip error: ${data}`);
            });

            pip.on('close', (code: number) => {
                if (code === 0) {
                    resolve();
                } else {
                    reject(new Error(`pip install failed with code ${code}`));
                }
            });
        } catch (error) {
            reject(error);
        }
    });
}

async function getPythonPath(): Promise<string> {
    const pythonConfig = vscode.workspace.getConfiguration('python');
    return pythonConfig.get<string>('defaultInterpreterPath') || 'python';
}

function getWebviewContent(port: number): string {
    return `
        <!DOCTYPE html>
        <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Aider Chat</title>
                <style>
                    body, html, iframe {
                        margin: 0;
                        padding: 0;
                        width: 100%;
                        height: 100%;
                        overflow: hidden;
                    }
                </style>
            </head>
            <body>
                <iframe 
                    src="http://localhost:${port}"
                    width="100%"
                    height="100%"
                    frameborder="0"
                ></iframe>
            </body>
        </html>
    `;
}
```

## 3. Python Requirements
```text
# src/python/requirements.txt
streamlit>=1.24.0
aider-chat>=0.62.0
```

## Documentation

### Installation
1. Install the extension:
```bash
code --install-extension aider-vscode-0.1.0.vsix
```

2. Configure Python interpreter in VSCode settings
3. Ensure git repository is initialized in workspace

### Usage
1. Open Command Palette (Ctrl+Shift+P)
2. Run "Start Aider Chat"
3. Wait for dependencies installation
4. Streamlit UI will appear in a new panel

### Features
- Automatic dependency installation
- Configurable port
- Persistent chat session
- Git integration
- Error handling and logging

### Configuration
In `settings.json`:
```json
{
    "aider.port": 8501,
    "python.defaultInterpreterPath": "/path/to/python"
}
```

### Development
1. Clone repository
2. Install dependencies:
```bash
npm install
```

3. Compile:
```bash
npm run compile
```

4. Debug:
- Press F5 in VSCode
- Select "Extension Development Host"
- Use Command Palette to start Aider

### Testing
1. Create test workspace with git repository
2. Install extension
3. Verify:
   - Dependency installation
   - Streamlit server startup
   - UI rendering
   - Port configuration
   - Error handling

### Troubleshooting
- Check Output panel for extension logs
- Verify Python interpreter configuration
- Check port availability
- Ensure git repository is initialized
- Check Python dependencies installation status

This implementation provides:
1. Automatic dependency management
2. Configurable port settings
3. Proper process cleanup
4. Error handling
5. Logging
6. Development tools integration
 