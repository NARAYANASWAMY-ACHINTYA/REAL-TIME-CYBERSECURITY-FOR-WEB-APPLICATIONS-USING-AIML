document.addEventListener('DOMContentLoaded', function() {
    // Fade in elements on scroll
    const fadeElements = document.querySelectorAll('.fade-in');
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
            }
        });
    });
    
    fadeElements.forEach(element => observer.observe(element));

    // Fetch and update statistics
    function updateStats() {
        fetch('/extension/stats')
            .then(response => response.json())
            .then(data => {
                const totalScans = document.getElementById('totalScans');
                const threatsDetected = document.getElementById('threatsDetected');
                
                if (totalScans) {
                    animateNumber(totalScans, 0, data.total_scans, 2000);
                }
                if (threatsDetected) {
                    animateNumber(threatsDetected, 0, data.threats_detected, 2000);
                }
            })
            .catch(error => console.error('Error fetching stats:', error));
    }

    // Animate number increment
    function animateNumber(element, start, end, duration) {
        const range = end - start;
        const increment = range / (duration / 16);
        let current = start;
        
        function updateNumber() {
            current += increment;
            if (current >= end) {
                element.textContent = end.toLocaleString();
            } else {
                element.textContent = Math.round(current).toLocaleString();
                requestAnimationFrame(updateNumber);
            }
        }
        
        updateNumber();
    }

    // Initialize stats
    updateStats();
    
    // Update stats periodically
    setInterval(updateStats, 30000); // Update every 30 seconds
});