const sensitivityLevels = {
  low:    { safe: 61, warning: 31 },
  normal: { safe: 81, warning: 51 },
  high:   { safe: 91, warning: 61 },
};

function classifyScore(score, sensitivity = 'normal') {
  const levels = sensitivityLevels[sensitivity];
  if (score >= levels.safe) return 'safe';
  if (score >= levels.warning) return 'warning';
  return 'danger';
}
function calculateScore(vtData, parsedHeader) {
  let score = 100;

  // 1. VirusTotal 점수 (최대 -40)
  const engines = vtData.data.attributes.last_analysis_results;
  for (const engine in engines) {
    if (engines[engine].category === 'malicious') {
      if (tier1.includes(engine)) score -= 20;
      else if (tier2.includes(engine)) score -= 15;
      else if (tier3.includes(engine)) score -= 5;
    }
  }

  // 2. SPF (-15)
  if (parsedHeader.spf !== 'pass') {
    score -= 15;
  }

  // 3. DKIM (-15)
  if (parsedHeader.dkim !== 'pass') {
    score -= 15;
  }

  // 4. WHOIS 생성일 (-15)
  const creationDateStr = vtData.data.attributes.whois;
  const recent = checkWhoisRecent(creationDateStr);
  if (recent) score -= 15;

  // 5. Return-Path 불일치 (-15)
  const returnDomain = parsedHeader.returnPath?.split('@')[1];
  if (parsedHeader.domain && returnDomain && parsedHeader.domain !== returnDomain) {
    score -= 15;
  }

  return Math.max(score, 0);
}

function buildReasons(vtData, headerData) {
  const rs = [];

  // VirusTotal 감지 엔진 수에 따른 감점
  const maliciousEngines = Object.entries(vtData.data.attributes.last_analysis_results)
    .filter(([_, info]) => info.category === 'malicious');
  const vtPenalty = maliciousEngines.reduce((sum, [eng, info]) => {
    // 티어별 점수 차등 감점
    let p = tier1.includes(eng) ? 20 : tier2.includes(eng) ? 15 : 5;
    sum += p;
    return sum;
  }, 0);
  if (vtPenalty) {
    rs.push(`VirusTotal에서 ${maliciousEngines.length}개의 백신이 악성으로 탐지했습니다. (-${vtPenalty}점)`);
  }

  // SPF/DKIM
  if (headerData.spf !== 'pass') rs.push('SPF 인증이 실패했습니다. (-15점)');
  if (headerData.dkim !== 'pass') rs.push('DKIM 인증이 실패했습니다. (-15점)');

  // Whois 생성日
  if (checkWhoisRecent(vtData.data.attributes.whois)) {
    rs.push('도메인이 최근에 생성되었습니다. (-10점)');
  }

  // Return-Path vs From
  const retDomain = headerData.returnPath?.split('@')[1];
  if (headerData.domain && retDomain && headerData.domain !== retDomain) {
    rs.push('Return-Path와 From 도메인이 일치하지 않습니다. (-15점)');
  }

  return rs;
}

function checkWhoisRecent(whoisText) {
  const yearMatch = whoisText?.match(/(?:Created|Creation Date|등록일)\D*(\d{4})/i);
  if (!yearMatch) return false;
  const year = parseInt(yearMatch[1], 10);
  const currentYear = new Date().getFullYear();
  return currentYear - year <= 1;
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'CHECK_DOMAIN') {
    fetch(`http://localhost:3005/api/virustotal/${request.domain}`)
      .then(res => res.json())
      .then(vtData => {
        const score = calculateScore(vtData, request.headerData);
        const reasons = buildReasons(vtData, request.headerData);

        const action = classifyScore(score);
        sendResponse({ success: true, score, reasons, action });
        chrome.storage.local.set({ score, reasons });
      })
      .catch(error => {
        sendResponse({ success: false, error: 'VT 요청 실패' });
        console.log(error);
      });
    return true;
  }
});
