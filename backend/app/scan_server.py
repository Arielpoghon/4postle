import asyncio
import json
import traceback
from urllib.parse import urlparse
from asyncio.subprocess import PIPE

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

app = FastAPI()


_HTML = """<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>4postle scan4all</title>
  <style>
    body{background:#000;color:#22c55e;font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;margin:0;padding:24px}
    .row{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
    input{flex:1;min-width:260px;background:#000;border:1px solid rgba(34,197,94,.35);color:#22c55e;padding:10px 12px;border-radius:8px;outline:none}
    button{background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.45);color:#22c55e;padding:10px 14px;border-radius:8px;cursor:pointer}
    button:disabled{opacity:.5;cursor:not-allowed}
    pre{margin-top:14px;background:rgba(0,0,0,.6);border:1px solid rgba(34,197,94,.25);padding:12px;border-radius:8px;max-height:65vh;overflow:auto;white-space:pre-wrap;word-break:break-word}
    .err{color:#ef4444;margin-top:10px}
  </style>
</head>
<body>
  <h1>4postle - scan4all</h1>
  <div class=\"row\">
    <input id=\"target\" placeholder=\"https://example.com or example.com\" />
    <button id=\"btn\">START SCAN</button>
  </div>
  <div id=\"err\" class=\"err\"></div>
  <noscript>
    <div class=\"err\">JavaScript is disabled. Enable it to run scans.</div>
  </noscript>
  <pre id=\"log\">[CLIENT] PAGE LOADED (waiting for JS)...
  </pre>

<script>
(() => {
  const btn = document.getElementById('btn');
  const targetEl = document.getElementById('target');
  const logEl = document.getElementById('log');
  const errEl = document.getElementById('err');

  let ws = null;
  let running = false;

  function append(line){
    if (!logEl) return;
    logEl.textContent += (line + "\n");
    logEl.scrollTop = logEl.scrollHeight;
  }

  function setError(msg){
    if (!errEl) return;
    errEl.textContent = msg || '';
  }

  function setRunning(next){
    running = next;
    if (btn) btn.textContent = running ? 'STOP SCANNING' : 'START SCAN';
  }

  window.addEventListener('error', (e) => {
    append('[CLIENT] JS ERROR: ' + (e?.message || 'unknown'));
  });

  if (!btn || !targetEl || !logEl || !errEl) {
    append('[CLIENT] UI INIT FAILED: missing DOM element(s)');
    append('[CLIENT] btn=' + Boolean(btn) + ' target=' + Boolean(targetEl) + ' log=' + Boolean(logEl) + ' err=' + Boolean(errEl));
    return;
  }

  append('[CLIENT] JS LOADED');

  btn.addEventListener('click', () => {
    setError('');

    if (running) {
      if (ws && ws.readyState === WebSocket.OPEN) {
        try { ws.send('STOP'); } catch {}
      }
      append('[CLIENT] STOP REQUESTED');
      return;
    }

    const target = (targetEl.value || '').trim();
    if (!target) {
      setError('Invalid URL');
      return;
    }

    logEl.textContent = '';
    append('[CLIENT] CONNECTING...');

    ws = new WebSocket(`ws://${location.host}/ws/scan`);
    setRunning(true);

    ws.onopen = () => {
      append('[CLIENT] CONNECTED');
      ws.send(JSON.stringify({ target }));
    };

    ws.onmessage = (ev) => {
      const msg = String(ev.data || '');
      if (msg === 'SCAN_COMPLETE') {
        append('[CLIENT] SCAN COMPLETE');
        setRunning(false);
        try { ws.close(); } catch {}
        return;
      }
      if (msg === 'SCAN_STOPPED') {
        append('[CLIENT] SCAN STOPPED');
        setRunning(false);
        try { ws.close(); } catch {}
        return;
      }
      if (msg === 'Invalid URL') {
        setError('Invalid URL');
        setRunning(false);
        try { ws.close(); } catch {}
        return;
      }
      if (msg === 'Backend unreachable') {
        setError('Backend unreachable');
        setRunning(false);
        try { ws.close(); } catch {}
        return;
      }
      append(msg);
    };

    ws.onerror = () => {
      setError('Backend unreachable');
      setRunning(false);
      try { ws.close(); } catch {}
    };

    ws.onclose = () => {
      ws = null;
      setRunning(false);
    };
  });
})();
</script>
</body>
</html>
"""


def _normalize_target(raw: str) -> str:
    target = (raw or "").strip()
    if not target:
        return ""
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        return (parsed.hostname or "").strip()
    return target


@app.get("/")
async def index():
    return HTMLResponse(
        _HTML,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


@app.websocket("/ws/scan")
async def ws_scan(websocket: WebSocket):
    await websocket.accept()

    process = None
    stop_requested = False

    try:
        payload_text = await websocket.receive_text()
        payload = json.loads(payload_text)
        target = _normalize_target(payload.get("target"))

        if not target:
            await websocket.send_text("Invalid URL")
            await websocket.close(code=1003)
            return

        cmd = ["docker", "run", "--rm", "4postle-scan4all", "-host", target]
        await websocket.send_text(f"[SERVER] starting: {' '.join(cmd)}")
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        stop_task = asyncio.create_task(websocket.receive_text())
        try:
            while True:
                stdout_task = asyncio.create_task(process.stdout.readline())
                done, pending = await asyncio.wait(
                    {stdout_task, stop_task},
                    return_when=asyncio.FIRST_COMPLETED,
                )

                if stop_task in done:
                    msg = stop_task.result()
                    if msg.strip().upper() == "STOP":
                        stop_requested = True
                        if process.returncode is None:
                            process.terminate()
                        break
                    stop_task = asyncio.create_task(websocket.receive_text())

                if stdout_task in done:
                    line = stdout_task.result()
                    if not line:
                        break
                    await websocket.send_text(line.decode(errors="replace").rstrip("\n"))

                for t in pending:
                    t.cancel()
        finally:
            if not stop_task.done():
                stop_task.cancel()

        exit_code = await process.wait()
        if stop_requested:
            await websocket.send_text("SCAN_STOPPED")
        elif exit_code == 0:
            await websocket.send_text("SCAN_COMPLETE")
        else:
            await websocket.send_text(f"Scan failed, try again (exit code {exit_code})")

    except FileNotFoundError as e:
        await websocket.send_text(f"[SERVER] docker not found: {e}")
    except PermissionError as e:
        await websocket.send_text(f"[SERVER] permission error: {e}")

    except WebSocketDisconnect:
        if process and process.returncode is None:
            process.terminate()
    except json.JSONDecodeError:
        await websocket.send_text("Invalid request")
    except Exception:
        await websocket.send_text("[SERVER] unhandled error")
        await websocket.send_text(traceback.format_exc())
    finally:
        if process and process.returncode is None:
            process.terminate()
