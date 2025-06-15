function parseEmailHeader(headers) {
  const result = {
    spf: null,
    dkim: null,
    returnPath: null,
    received: [],
    domain: null,
  };

  const lines = headers.split(/\r?\n/);
  const unifiedLines = [];
  for (let line of lines) {
    if (/^\s/.test(line)) {
      unifiedLines[unifiedLines.length - 1] += ' ' + line.trim();
    } else {
      unifiedLines.push(line.trim());
    }
  }

  for (const line of unifiedLines) {
    if (line.startsWith('Received-SPF')) {
      result.spf = line.includes('pass') ? 'pass' : 'fail';
      const match = line.match(/smtp\.mailfrom=([\w.-]+@[\w.-]+)/);
      if (match) {
        result.domain = match[1].split('@')[1];
      }
    }

    if (line.startsWith('Authentication-Results') && line.includes('dkim=')) {
      result.dkim = line.includes('dkim=pass') ? 'pass' : 'fail';
    }

    if (line.startsWith('Return-Path:')) {
      const match = line.match(/<([^>]+)>/);
      if (match) {
        result.returnPath = match[1];
        const domainMatch = match[1].split('@');
        if (domainMatch.length === 2) {
          result.domain = domainMatch[1];
        }
      }
    }

    if (line.startsWith('Received:')) {
      result.received.push(line);
    }
  }
  
  return result;
}

// 지메일일에서 헤더 추출
// 수정된 Gmail 헤더 추출
function extractGmailHeader() {
  const preElement = document.querySelector('pre'); 
  if (!preElement) return;

  const rawHeader = preElement.innerText;
  handleParsedHeader(rawHeader);
}

// 네이버버에서 헤더 추출
function extractNaverHeader() {
  const headerContainer = document.querySelector('.read_header');
  if (!headerContainer) return;
  
  const rawHeader = headerContainer.innerText;
  handleParsedHeader(rawHeader);
}

function handleParsedHeader(rawHeader) {
  const parsedResult = parseEmailHeader(rawHeader);
  
  
  chrome.runtime.sendMessage({
    type: 'CHECK_DOMAIN',
    domain: parsedResult.domain,
    headerData: parsedResult
  }, (response) => {
    if (response.success) {
      console.log('💡 최종 점수:', response.score);
      console.log('🚨 대응 조치:', response.action);
    applyAction(response.action);
    
    // ✅ 팝업도 같이 렌더링
    renderPhishPopup(response.score, response.reasons);
  } else {
    console.error('❌ 분석 실패:', response.error);
  }
});
}

function applyAction(action) {
  if (action === 'safe') {
    alert('✅ 이 이메일은 안전합니다.');
  } else if (action === 'warning') {
    document.body.style.filter = 'grayscale(100%)';
    alert('⚠️ 주의: 이 메일은 의심스러운 요소가 있습니다.');
  } else if (action === 'danger') {
    alert('🚨 위험: 이 메일은 차단됩니다.');
    // 실제로 삭제는 어려우므로 아래와 같은 대체 방법 가능
    document.body.innerHTML = '<h1>위험한 메일입니다. 차단되었습니다.</h1>';
  }
}

function detectMailService() {
  const hostname = window.location.hostname;
  if (hostname.includes('mail.google.com')) {
    extractGmailHeader();
  } else if (hostname.includes('mail.naver.com')) {
    extractNaverHeader();
  }
}

// --- 점수 등급 기준
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

// --- 팝업 UI 생성 및 렌더링
    function renderPhishPopup(score, reasons, sensitivity = 'normal') {
      const level = classifyScore(score, sensitivity);
      const colorMap = { safe: 'green', warning: 'orange', danger: 'red' };
      const messageMap = {
        safe: '✅ 안전한 메일입니다.',
        warning: '⚠️ 주의단계로 메일이 읽기모드로 전환됩니다.',
        danger: '🚨 위험단계로 메일이 자동으로 삭제 됩니다.'
      };
      
      let popup = document.getElementById('phish-analyzer-popup');
      if (!popup) {
        popup = document.createElement('div');
        popup.id = 'phish-analyzer-popup';
        Object.assign(popup.style, {
          position: 'fixed',
          top: '20px',
          right: '20px',
          width: '340px',
          padding: '16px',
          background: '#fff',
          border: '1px solid #ccc',
          boxShadow: '0 2px 10px rgba(0,0,0,0.2)',
          zIndex: '99999',
          fontFamily: 'sans-serif',
          borderRadius: '12px'
        });
    document.body.appendChild(popup);
  }
  
  const warningText = reasons.map(r => `* ${r}`).join('<br/>');
  popup.innerHTML = `
  <div id="phish-summary" style="font-size:16px;margin-bottom:12px">
  <strong>총점: <span id="score-value" style="color:${colorMap[level]}">${score}점 (${level === 'safe' ? '안전' : level === 'warning' ? '주의' : '위험'})</span></strong><br/>
  ${messageMap[level]}
  </div>
  
  <div id="phish-warning" style="font-size:14px;margin-bottom:10px">
  <strong>[경고 요약]</strong><br/>${warningText}
  </div>
  
  <div id="phish-guide" style="font-size:14px;margin-bottom:12px">
  <strong>[대응 가이드 제안]</strong><br/>
  * 첨부파일과 링크 클릭 금지<br/>
  * 발신자에게 회신하지 마세요
  </div>
  
  <button id="phish-details-btn" style="margin-right:10px">상세 보기</button>
  <label for="sensitivity-select">보안 민감도:</label>
  <select id="sensitivity-select" style="margin-left:4px">
  <option value="low">낮음</option>
  <option value="normal" selected>기본</option>
  <option value="high">높음</option>
    </select>
    `;
    
    // 민감도 변경 반영
    popup.querySelector('#sensitivity-select').addEventListener('change', (e) => {
      renderPhishPopup(score, reasons, e.target.value);
    });

  // 상세 보기 클릭
  popup.querySelector('#phish-details-btn').addEventListener('click', () => {
    showDetails(score, reasons);
  });
}

// --- 상세 보기 팝업 예시
function showDetails(score, reasons) {
  alert(`🔍 상세 점수 보기:\n\n총점: ${score}\n\n감점 요인:\n${reasons.join('\n')}`);
}


window.addEventListener('load', () => {
  setTimeout(() => {
    extractGmailHeader();
    extractNaverHeader();
  }, 2000);
});