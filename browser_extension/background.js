chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    // Skip subframes and internal chrome URLs
    if (details.frameId !== 0 || details.url.startsWith("chrome://") || details.url.startsWith("chrome-extension://")) {
        return;
    }

    try {
        const response = await fetch(`http://localhost:8000/api/check?url=${encodeURIComponent(details.url)}`);
        
        if (response.ok) {
            const data = await response.json();
            if (data.is_malicious) {
                chrome.notifications.create({
                    type: "basic",
                    iconUrl: "icon.png", // Will default to a generic icon if missing
                    title: "Security Alert!",
                    message: `The website ${details.url} has a ${data.confidence}% ML confidence score of being malicious.`
                });
            }
        }
    } catch (error) {
        console.error("Local ML scanner is not running.", error);
    }
});
