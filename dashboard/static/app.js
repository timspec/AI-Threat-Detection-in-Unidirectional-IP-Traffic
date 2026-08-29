/**
 * dashboard/static/app.js — Shared Client Utilities & Live WebSocket Manager.
 */

// ── Severity Chip Renderer (Text Label + Color) ──────────────────────────
function renderSeverityChip(severity) {
  const sev = (severity || 'LOW').toUpperCase();
  let cssClass = 'chip-low';
  if (sev === 'CRITICAL') cssClass = 'chip-critical';
  else if (sev === 'HIGH') cssClass = 'chip-high';
  else if (sev === 'MEDIUM') cssClass = 'chip-medium';
  return `<span class="chip ${cssClass}">${sev}</span>`;
}

// ── Timestamp Formatter ──────────────────────────────────────────────────
function formatTimestamp(epochSeconds) {
  if (!epochSeconds) return '—';
  const d = new Date(epochSeconds * 1000);
  return d.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
}

function formatRelativeTime(epochSeconds) {
  if (!epochSeconds) return '—';
  const diff = Math.floor(Date.now() / 1000 - epochSeconds);
  if (diff < 5) return 'just now';
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

// ── WebSocket Live Streaming Client ──────────────────────────────────────
class ThreatWebSocketClient {
  constructor(onAlertCallback, onKpiCallback) {
    this.onAlert = onAlertCallback;
    this.onKpi = onKpiCallback;
    this.ws = null;
    this.reconnectInterval = 3000;
    this.connect();
  }

  connect() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host || '127.0.0.1:8000';
    const wsUrl = `${protocol}//${host}/ws/alerts`;

    try {
      this.ws = new WebSocket(wsUrl);

      this.ws.onopen = () => {
        console.log('[WebSocket] Connected to threat stream:', wsUrl);
        const statusDot = document.getElementById('ws-status-dot');
        if (statusDot) statusDot.style.backgroundColor = '#4CAF50';
      };

      this.ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'alert.new' && this.onAlert) {
            this.onAlert(msg.data);
          } else if (msg.type === 'kpi.tick' && this.onKpi) {
            this.onKpi(msg.data);
          }
        } catch (err) {
          console.error('[WebSocket] Failed to parse message:', err);
        }
      };

      this.ws.onclose = () => {
        console.warn('[WebSocket] Stream disconnected. Retrying in 3s...');
        const statusDot = document.getElementById('ws-status-dot');
        if (statusDot) statusDot.style.backgroundColor = '#E8B923';
        setTimeout(() => this.connect(), this.reconnectInterval);
      };

      this.ws.onerror = (err) => {
        console.error('[WebSocket] Error:', err);
        this.ws.close();
      };
    } catch (e) {
      setTimeout(() => this.connect(), this.reconnectInterval);
    }
  }
}
