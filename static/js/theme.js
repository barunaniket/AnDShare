document.addEventListener('DOMContentLoaded', () => {
    const themeToggle = document.getElementById('theme-toggle');
    const body = document.body;
    const sakuraContainer = document.getElementById('sakura-container');

    // Function to create sakura petals (if sakura container exists)
    function createSakuraPetals() {
        if (!sakuraContainer) return;
        sakuraContainer.innerHTML = ''; // Clear existing petals
        const petalCount = 30;

        for (let i = 0; i < petalCount; i++) {
            const petal = document.createElement('div');
            petal.classList.add('petal');

            const size = Math.random() * 10 + 10;
            const xPos = Math.random() * 100;
            const drift = (Math.random() - 0.5) * 100;
            const duration = Math.random() * 10 + 10;
            const delay = Math.random() * 15;

            petal.style.setProperty('--x', `${xPos}%`);
            petal.style.setProperty('--drift', `${drift}px`);
            petal.style.width = `${size}px`;
            petal.style.height = `${size}px`;
            petal.style.animationDuration = `${duration}s`;
            petal.style.animationDelay = `${delay}s`;

            // Petal color and shape can be dynamic or fixed
            // For example, using a light pink shade:
            petal.style.backgroundColor = 'var(--accent-glow)'; // Use accent-glow for theme consistency
            petal.style.borderRadius = '30% 70% 70% 30% / 30% 30% 70% 70%';
            petal.style.transform = `rotate(${Math.random() * 360}deg)`;

            sakuraContainer.appendChild(petal);
        }
    }

    // Function to apply the theme
    function applyTheme(theme) {
        if (theme === 'light') {
            body.classList.add('light-mode');
            if (themeToggle) themeToggle.checked = true;
            if (sakuraContainer) createSakuraPetals();
        } else {
            body.classList.remove('light-mode');
            if (themeToggle) themeToggle.checked = false;
            if (sakuraContainer) sakuraContainer.innerHTML = ''; // Clear petals in dark mode
        }
    }

    // Check for saved theme preference or use system preference or default to dark
    let currentTheme = localStorage.getItem('theme');
    if (!currentTheme) {
        // Default to dark if no preference or system preference
        currentTheme = 'dark';
        // Optionally, check system preference:
        // if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
        //     currentTheme = 'light';
        // }
    }

    applyTheme(currentTheme);
    localStorage.setItem('theme', currentTheme); // Ensure it's saved

    // Theme toggle functionality (if toggle exists)
    if (themeToggle) {
        themeToggle.addEventListener('change', () => {
            const newTheme = themeToggle.checked ? 'light' : 'dark';
            applyTheme(newTheme);
            localStorage.setItem('theme', newTheme);
        });
    }
});
