document.addEventListener("DOMContentLoaded", () => {
  // Check the current tab when the popup loads
  checkCurrentTab();

  // Add event listener for the manual URL check button
  const checkUrlButton = document.getElementById("check-url");
  if (checkUrlButton) {
    checkUrlButton.addEventListener("click", checkManualUrl);
  }
});

// Function to check the current active tab's URL
function checkCurrentTab() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const currentTab = tabs[0];
    if (currentTab && currentTab.url) {
      const resultDiv = document.getElementById("result");
      resultDiv.textContent = "Checking current website...";

      // Fetch the result from the backend
      fetch(`http://127.0.0.1:5000/check?url=${encodeURIComponent(currentTab.url)}`)
        .then(async (response) => {
          const data = await response.json();
          if (!response.ok) {
            throw new Error(data.details || data.error || "Server error");
          }
          return data;
        })
        .then((data) => {
          if (data.is_phishing) {
            const confidence = (data.probability_phishing * 100).toFixed(2);
            resultDiv.innerHTML = `<strong style="color: red;">🚨 Warning:</strong> This site may be phishing! (${confidence}% confidence)`;
          } else {
            const confidence = (data.probability_safe * 100).toFixed(2);
            resultDiv.innerHTML = `<strong style="color: green;">✅ Safe:</strong> This site is safe (${confidence}% confidence)`;
          }
        })
        .catch((error) => {
          console.error("Error:", error);
          resultDiv.innerHTML = `<strong style="color: orange;">⚠️ Error:</strong> ${error.message}`;
          if (error.message.includes("Model not ready")) {
            resultDiv.innerHTML += "<br><small>Please wait a few seconds and try again...</small>";
          } else if (error.message.includes("Failed to fetch")) {
            resultDiv.innerHTML += "<br><small>Please make sure the backend server is running at http://127.0.0.1:5000</small>";
          }
        });
    } else {
      document.getElementById("result").textContent = "No active tab with a valid URL found.";
    }
  });
}

// Function to format URL with proper protocol
function formatUrl(url) {
  url = url.trim();
  if (!url.match(/^[a-zA-Z]+:\/\//)) {
    return `https://${url}`;
  }
  return url;
}

// Function to manually check a URL entered by the user
function checkManualUrl() {
  let manualUrl = document.getElementById("manual-url").value;
  manualUrl = formatUrl(manualUrl);

  const resultDiv = document.getElementById("manual-result");
  resultDiv.textContent = "Checking URL...";

  fetch(`http://127.0.0.1:5000/check?url=${encodeURIComponent(manualUrl)}`)
    .then(async (response) => {
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.details || data.error || "Server error");
      }
      return data;
    })
    .then((data) => {
      if (data.is_phishing) {
        const confidence = (data.probability_phishing * 100).toFixed(2);
        resultDiv.innerHTML = `<strong style="color: red;">🚨 Warning:</strong> This site may be phishing! (${confidence}% confidence)`;
      } else {
        const confidence = (data.probability_safe * 100).toFixed(2);
        resultDiv.innerHTML = `<strong style="color: green;">✅ Safe:</strong> This site is safe (${confidence}% confidence)`;
      }
    })
    .catch((error) => {
      console.error("Error:", error);
      resultDiv.innerHTML = `<strong style="color: orange;">⚠️ Error:</strong> ${error.message}`;
      if (error.message.includes("Model not ready")) {
        resultDiv.innerHTML += "<br><small>Please wait a few seconds and try again...</small>";
      } else if (error.message.includes("Failed to fetch")) {
        resultDiv.innerHTML += "<br><small>Please make sure the backend server is running at http://127.0.0.1:5000</small>";
      }
    });
}