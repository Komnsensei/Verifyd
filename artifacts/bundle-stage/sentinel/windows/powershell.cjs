'use strict';

const { execFile } = require('child_process');

const MARKER = '@@SENTINEL_JSON@@';

function isWindows() {
  return process.platform === 'win32';
}

function psError(code, message, detail) {
  const e = new Error(message);
  e.code = code;
  if (detail) e.detail = detail;
  return e;
}

// Runs a PowerShell script and parses the JSON it emits after MARKER.
// Scripts must end with the marker write, so incidental PowerShell output
// (progress, warnings) cannot corrupt the payload.
function makePowerShellRunner(opts) {
  opts = opts || {};
  const timeoutMs = opts.timeoutMs || 20000;
  const exec = opts.execFile || execFile;
  const platform = opts.platform || process.platform;

  return function runPowerShell(script, runOpts) {
    runOpts = runOpts || {};
    if (platform !== 'win32') {
      return Promise.reject(psError('PLATFORM_NOT_WINDOWS', 'PowerShell host telemetry requires Windows; this host is ' + platform));
    }
    const wrapped = [
      '$ProgressPreference = "SilentlyContinue";',
      '$ErrorActionPreference = "Stop";',
      script,
      'Write-Output "' + MARKER + '";'
    ].join('\n');

    const args = [
      '-NoLogo',
      '-NoProfile',
      '-NonInteractive',
      '-ExecutionPolicy', 'Bypass',
      '-Command', wrapped
    ];

    return new Promise((resolve, reject) => {
      exec('powershell.exe', args, {
        timeout: runOpts.timeoutMs || timeoutMs,
        maxBuffer: 16 * 1024 * 1024,
        windowsHide: true
      }, (err, stdout, stderr) => {
        if (err) {
          if (err.killed) return reject(psError('PS_TIMEOUT', 'PowerShell timed out after ' + (runOpts.timeoutMs || timeoutMs) + 'ms'));
          const detail = String(stderr || '').trim().slice(0, 800);
          return reject(psError('PS_FAILED', 'PowerShell failed: ' + (detail || err.message), detail));
        }
        const text = String(stdout || '');
        const idx = text.lastIndexOf(MARKER);
        if (idx === -1) return reject(psError('PS_NO_MARKER', 'PowerShell produced no structured output'));
        const jsonText = text.slice(0, idx).trim();
        if (!jsonText) return resolve(null);
        try {
          return resolve(JSON.parse(jsonText));
        } catch (e) {
          return reject(psError('PS_BAD_JSON', 'PowerShell output was not valid JSON: ' + e.message));
        }
      });
    });
  };
}

function psJsonExpr(expr) {
  return expr + ' | ConvertTo-Json -Compress -Depth 6';
}

module.exports = { makePowerShellRunner, isWindows, psJsonExpr, MARKER, psError };
