chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url && tab.url.startsWith("http")) {
    console.log("Checking URL:", tab.url);

    // Add timeout to the fetch request
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout

    fetch(`http://127.0.0.1:5000/check?url=${encodeURIComponent(tab.url)}`, {
      signal: controller.signal,
      headers: {
        'Accept': 'application/json',
        'Cache-Control': 'no-cache'
      }
    })
      .then((response) => {
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
      })
      .then((data) => {
        console.log("Received data from backend:", data);
        clearTimeout(timeoutId);

        // Send message to content script
        chrome.tabs.sendMessage(
          tabId,
          { 
            is_phishing: data.is_phishing,
            probability_phishing: data.probability_phishing,
            probability_safe: data.probability_safe
          },
          (response) => {
            if (chrome.runtime.lastError) {
              console.warn("Could not send message to content script:", chrome.runtime.lastError.message);
            }
          }
        );
      })
      .catch((error) => {
        clearTimeout(timeoutId);
        console.error("Error checking URL:", error.message);
        
        // If it's a timeout, notify the user
        if (error.name === 'AbortError') {
          chrome.tabs.sendMessage(tabId, {
            is_phishing: false,
            probability_phishing: 0,
            probability_safe: 1,
            error: "Request timed out. The server might be busy."
          });
        }
      });
  }
});
