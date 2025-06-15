function classifyScore(score, sensitivity = 'normal') {
  const levels = {
    low:    { safe: 61, warning: 31 },
    normal: { safe: 81, warning: 51 },
    high:   { safe: 91, warning: 61 },
  }[sensitivity];

  if (score >= levels.safe) return 'safe';
  if (score >= levels.warning) return 'warning';
  return 'danger';
}

chrome.storage.local.get(['score', 'reasons'], (data) => {
  const sensitivity = document.getElementById('sensitivity').value;
  const level = classifyScore(data.score || 0, sensitivity);

  document.getElementById('score').textContent = `총점: ${data.score || 0} (${level})`;
  document.getElementById('score').style.color = 
    level === 'safe' ? 'green' : level === 'warning' ? 'orange' : 'red';

  if (Array.isArray(data.reasons)) {
    document.getElementById('reasons').innerHTML = data.reasons.map(r => `• ${r}`).join('<br>');
  } else {
    document.getElementById('reasons').textContent = '감점 사유 없음';
  }
});

document.getElementById('sensitivity').addEventListener('change', () => {
  chrome.storage.local.get(['score', 'reasons'], (data) => {
    const sensitivity = document.getElementById('sensitivity').value;
    const level = classifyScore(data.score || 0, sensitivity);
    document.getElementById('score').textContent = `총점: ${data.score || 0} (${level})`;
    document.getElementById('score').style.color = 
      level === 'safe' ? 'green' : level === 'warning' ? 'orange' : 'red';
  });
});
