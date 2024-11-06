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
            const port: number = config.get('port') as number || 8501;

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
