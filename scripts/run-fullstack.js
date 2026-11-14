const { spawn } = require('child_process');
const path = require('path');

const root = path.resolve(__dirname, '..');
const isWin = process.platform === 'win32';
const pythonExe = isWin
  ? 'C:/Users/usr1/AppData/Local/Programs/Python/Python311/python.exe'
  : 'python3';
const npmExe = isWin ? 'npm.cmd' : 'npm';

const backend = spawn(pythonExe, ['main.py'], {
  cwd: root,
  stdio: 'inherit',
  shell: true
});

const frontend = spawn(npmExe, ['run', 'dev'], {
  cwd: root,
  stdio: 'inherit',
  shell: true
});

const shutdown = () => {
  backend.kill('SIGTERM');
  frontend.kill('SIGTERM');
  process.exit(0);
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
