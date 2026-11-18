// Shared polling + rendering helpers used across dashboard pages.

async function fetchJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Request failed: ${res.status}`);
  return res.json();
}

function timeAgo(isoTimestamp) {
  // SQLite timestamps come back as "YYYY-MM-DD HH:MM:SS" (UTC-ish, no offset marker)
  const t = new Date(isoTimestamp.replace(" ", "T") + "Z");
  const diff = Math.max(0, Math.floor((Date.now() - t.getTime()) / 1000));
  if (diff < 5) return "just now";
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}
