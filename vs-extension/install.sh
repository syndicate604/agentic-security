#!/bin/bash

# Project name
PROJECT_NAME="aider-vscode"

# Create main project directory
mkdir -p $PROJECT_NAME

# Navigate into project directory
cd $PROJECT_NAME

# Create package.json
cat > package.json << 'EOL'
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
EOL

# Create directory structure
mkdir -p src/{python,webview}
mkdir -p .vscode

# Create Python requirements file
cat > src/python/requirements.txt << 'EOL'
streamlit>=1.24.0
aider-chat>=0.62.0
EOL

# Create main extension file
cat > src/extension.ts << 'EOL'
import * as vscode from 'vscode';
import * as path from 'path';
import { spawn } from 'child_process';

export async function activate(context: vscode.ExtensionContext) {
    let currentPanel: vscode.WebviewPanel | undefined = undefined;
    let streamlitProcess: any;

    const startAider = vscode.commands.registerCommand('aider.startChat', async () => {
        try {
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
EOL

# Create tsconfig.json
cat > tsconfig.json << 'EOL'
{
    "compilerOptions": {
        "module": "commonjs",
        "target": "ES2020",
        "outDir": "out",
        "lib": ["ES2020"],
        "sourceMap": true,
        "rootDir": "src",
        "strict": true
    },
    "exclude": ["node_modules", ".vscode-test"]
}
EOL

# Create launch configuration
cat > .vscode/launch.json << 'EOL'
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Extension",
            "type": "extensionHost",
            "request": "launch",
            "args": [
                "--extensionDevelopmentPath=${workspaceFolder}"
            ],
            "outFiles": [
                "${workspaceFolder}/out/**/*.js"
            ],
            "preLaunchTask": "${defaultBuildTask}"
        }
    ]
}
EOL

# Create .gitignore
cat > .gitignore << 'EOL'
out
node_modules
.vscode-test/
*.vsix
.DS_Store
__pycache__/
*.pyc
EOL

# Create README.md
cat > README.md << 'EOL'
# Aider VSCode Extension

AI pair programming with Aider in VSCode.

## Features
- Streamlit-based UI
- Git integration
- Model switching
- Temperature control
- File management

## Development
1. npm install
2. pip install -r src/python/requirements.txt
3. F5 to start debugging

## Usage
1. Command Palette -> "Start Aider Chat"
2. Use the chat interface in the panel
EOL

# Make the script executable
chmod +x src/python/*.py

echo "Project structure created successfully!"
echo "Next steps:"
echo "1. npm install"
echo "2. pip install -r src/python/requirements.txt"
echo "3. code ."