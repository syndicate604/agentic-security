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
                console.log(`Starting Streamlit with Python path: ${pythonPath}`);
                
                const appPath = path.join(context.extensionPath, 'src', 'python', 'app.py');
                console.log(`App path: ${appPath}`);
                
                streamlitProcess = spawn(pythonPath, [
                    '-m', 'streamlit', 'run',
                    appPath,
                    '--server.port', port.toString(),
                    '--server.address', 'localhost',
                    '--server.headless', 'true'
                ]);

                // Add logging for Streamlit process
                streamlitProcess.stdout.on('data', (data: Buffer) => {
                    console.log(`Streamlit stdout: ${data}`);
                });

                streamlitProcess.stderr.on('data', (data: Buffer) => {
                    console.error(`Streamlit stderr: ${data}`);
                });

                // Wait for server to start
                await new Promise((resolve, reject) => {
                    const timeout = setTimeout(() => {
                        reject(new Error('Streamlit server failed to start within 30 seconds'));
                    }, 30000);

                    const checkServer = async () => {
                        try {
                            const response = await (globalThis as any).fetch(`http://localhost:${port}`);
                            if (response.ok) {
                                clearTimeout(timeout);
                                resolve(true);
                            } else {
                                setTimeout(checkServer, 1000);
                            }
                        } catch (error) {
                            setTimeout(checkServer, 1000);
                        }
                    };
                    checkServer();
                });

                // Set webview content after server is confirmed running
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
