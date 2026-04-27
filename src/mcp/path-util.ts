// src/sswp/mcp/path-util.ts
/** Convert Windows repo paths to WSL /mnt/{drive}/ form */

export function toWslPath(winPath: string): string {
  // Already unix-style (no backslashes, no drive colon)
  const hasBackslash = winPath.includes(String.fromCharCode(92));
  const hasDrive = winPath.length >= 2 && winPath[1] === ':';
  if (!hasBackslash && !hasDrive) return winPath;

  // Replace backslashes with forward slashes
  let s = winPath;
  const bs = String.fromCharCode(92);
  while (s.includes(bs)) { s = s.replace(bs, "/"); }

  // Convert C:/ to /mnt/c/
  if (s.length >= 2 && s[1] === ':' && /^[A-Za-z]/.test(s[0])) {
    const drive = s[0].toLowerCase();
    s = '/mnt/' + drive + '/' + s.slice(2).replace(/^\/+/, '');
  }
  return s;
}

export function toWinPath(wslPath: string): string {
  if (wslPath.startsWith('/mnt/') && wslPath.length >= 7) {
    const drive = wslPath[5].toUpperCase();
    const rest = wslPath.slice(6).replace(/\//g, String.fromCharCode(92));
    return drive + ':' + rest;
  }
  return wslPath;
}
