console.log("Content script loaded and running");

// Add CSS styles for the alert
const styles = `
  .phishing-alert {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    z-index: 999999;
    padding: 32px 40px;
    border-radius: 16px;
    font-family: 'Segoe UI', 'Arial', sans-serif;
    font-size: 18px;
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.15);
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 20px;
    opacity: 0;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    cursor: default;
    min-width: 400px;
    max-width: 90vw;
    backdrop-filter: blur(8px);
  }

  .phishing-alert.show {
    opacity: 1;
  }

  .phishing-alert:hover {
    transform: translate(-50%, -50%) scale(1.02);
    box-shadow: 0 12px 32px rgba(0, 0, 0, 0.2);
  }

  .phishing-alert.safe {
    background: linear-gradient(135deg, #43a047 0%, #2e7d32 100%);
    color: white;
  }

  .phishing-alert.danger {
    background: linear-gradient(135deg, #ef5350 0%, #d32f2f 100%);
    color: white;
  }

  .alert-header {
    display: flex;
    align-items: center;
    gap: 16px;
    width: 100%;
  }

  .alert-icon {
    font-size: 36px;
    line-height: 1;
  }

  .alert-content {
    display: flex;
    flex-direction: column;
    flex-grow: 1;
  }

  .alert-title {
    font-size: 24px;
    font-weight: 600;
    margin-bottom: 8px;
    letter-spacing: -0.5px;
  }

  .alert-message {
    font-size: 16px;
    opacity: 0.9;
    line-height: 1.5;
  }

  .alert-actions {
    display: flex;
    gap: 12px;
    margin-top: 8px;
    width: 100%;
  }

  .alert-button {
    padding: 12px 24px;
    border: none;
    border-radius: 8px;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s ease;
    flex: 1;
    text-align: center;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
  }

  .button-back {
    background-color: white;
    color: #d32f2f;
  }

  .button-back:hover {
    background-color: #f5f5f5;
    transform: translateY(-2px);
  }

  .button-continue {
    background-color: rgba(255, 255, 255, 0.1);
    color: white;
    border: 1px solid rgba(255, 255, 255, 0.2);
  }

  .button-continue:hover {
    background-color: rgba(255, 255, 255, 0.2);
    transform: translateY(-2px);
  }

  .close-button {
    position: absolute;
    top: 16px;
    right: 16px;
    background: none;
    border: none;
    color: white;
    font-size: 24px;
    cursor: pointer;
    opacity: 0.8;
    transition: all 0.2s;
    width: 32px;
    height: 32px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 50%;
  }

  .close-button:hover {
    opacity: 1;
    background-color: rgba(255, 255, 255, 0.1);
  }
`;

// Add styles to the document
const styleSheet = document.createElement("style");
styleSheet.textContent = styles;
document.head.appendChild(styleSheet);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log("Message received in content script:", message);

  if (message.is_phishing !== undefined) {
    // Remove existing alert if present
    const existingAlert = document.getElementById("phishing-alert");
    if (existingAlert) {
      existingAlert.remove();
    }

    // Create alert container
    const alert = document.createElement("div");
    alert.id = "phishing-alert";
    alert.className = `phishing-alert ${message.is_phishing ? 'danger' : 'safe'}`;

    // Create alert content
    const confidence = message.is_phishing 
      ? (message.probability_phishing * 100).toFixed(1)
      : (message.probability_safe * 100).toFixed(1);

    alert.innerHTML = `
      <div class="alert-header">
        <div class="alert-icon">
          ${message.error ? '⚠️' : message.is_phishing ? '🚨' : '✅'}
        </div>
        <div class="alert-content">
          <div class="alert-title">
            ${message.error ? 'Detection Issue' : message.is_phishing ? 'Warning: Potential Phishing Site' : 'Safe Website'}
          </div>
          <div class="alert-message">
            ${message.error ? message.error : 
              message.is_phishing 
                ? `This website has been flagged as potentially dangerous (${confidence}% confidence)`
                : `This website appears to be safe (${confidence}% confidence)`
            }
          </div>
        </div>
        ${message.is_phishing || message.error ? '<button class="close-button">×</button>' : ''}
      </div>
      ${message.is_phishing ? `
        <div class="alert-actions">
          <button class="alert-button button-back">
            <span>⬅️</span> Go Back to Safety
          </button>
          <button class="alert-button button-continue">
            <span>⚠️</span> Continue at Risk
          </button>
        </div>
      ` : ''}
    `;

    document.body.appendChild(alert);

    // Add event listeners for unsafe sites
    if (message.is_phishing) {
      const closeButton = alert.querySelector('.close-button');
      const backButton = alert.querySelector('.button-back');
      const continueButton = alert.querySelector('.button-continue');

      closeButton.addEventListener('click', (e) => {
        e.stopPropagation();
        alert.remove();
      });

      backButton.addEventListener('click', (e) => {
        e.stopPropagation();
        // Try to go back using window.location
        if (window.history.length > 1) {
          window.history.back();
        } else {
          // Fallback: If no history, go to a safe default page
          window.location.href = 'https://www.google.com';
        }
        alert.remove();
      });

      continueButton.addEventListener('click', (e) => {
        e.stopPropagation();
        alert.remove();
      });
    }

    // Show the alert with animation
    requestAnimationFrame(() => {
      alert.classList.add('show');
    });

    // For safe sites, remove after 4 seconds
    if (!message.is_phishing) {
      setTimeout(() => {
        alert.classList.remove('show');
        setTimeout(() => alert.remove(), 300); // Remove after fade out animation
      }, 4000);
    }
  }
});
