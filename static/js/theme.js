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

            // Petal color and shape for Sakura
            const accentColor = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim();
            // Randomly choose between the main accent color and a slightly lighter/more transparent version for variety
            const petalColor = Math.random() > 0.3 ? accentColor : accentColor + '99'; // Add some transparency for some

            petal.style.backgroundColor = petalColor;
            petal.style.opacity = Math.random() * 0.3 + 0.7; // Opacity between 0.7 and 1.0
            petal.style.borderRadius = '50% 50% 20% 50% / 50% 50% 50% 20%'; // Tweaked for a more sakura-like shape
            petal.style.transform = `rotate(${Math.random() * 360}deg) scale(${Math.random() * 0.3 + 0.7})`; // Slight size variation

            sakuraContainer.appendChild(petal);
        }
    }

    // Function to apply the theme
    function applyTheme(theme) {
        if (theme === 'light') {
            body.classList.remove('dark-mode'); // Ensure dark-mode class is removed
            body.classList.add('light-mode');
            if (themeToggle) themeToggle.checked = true;
            if (sakuraContainer) createSakuraPetals();
            if (window.stopMouseTrail) window.stopMouseTrail(); // Stop mouse trail if running
        } else { // Dark mode
            body.classList.remove('light-mode'); // Ensure light-mode class is removed
            body.classList.add('dark-mode');
            if (themeToggle) themeToggle.checked = false;
            if (sakuraContainer) sakuraContainer.innerHTML = ''; // Clear petals in dark mode
            if (window.startMouseTrail) window.startMouseTrail(); // Start mouse trail
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

    // Interactive Mouse Trail for Dark Mode
    const canvas = document.getElementById('mouse-trail-canvas');
    let ctx;
    let animationFrameId;
    const trailPoints = [];
    const maxPoints = 30; // Length of the trail
    let trailActive = false;

    if (canvas) {
        ctx = canvas.getContext('2d');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;

        window.addEventListener('resize', () => {
            if (canvas) {
                canvas.width = window.innerWidth;
                canvas.height = window.innerHeight;
            }
        });

        document.addEventListener('mousemove', (e) => {
            if (trailActive) {
                trailPoints.push({ x: e.clientX, y: e.clientY, opacity: 1 });
                if (trailPoints.length > maxPoints) {
                    trailPoints.shift();
                }
            }
        });

        function drawTrail() {
            if (!trailActive || !ctx) return;

            ctx.clearRect(0, 0, canvas.width, canvas.height);

            for (let i = 0; i < trailPoints.length; i++) {
                const point = trailPoints[i];
                point.opacity -= 0.03; // Fade out
                if (point.opacity <= 0) {
                    trailPoints.splice(i, 1);
                    i--; // Adjust index after removal
                    continue;
                }

                ctx.beginPath();
                ctx.arc(point.x, point.y, i / (maxPoints / 5), 0, Math.PI * 2); // Size based on position in trail
                // Use the theme's accent color for the trail
                const accentColor = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim();
                ctx.fillStyle = `${accentColor}${Math.max(0, Math.floor(point.opacity * 255)).toString(16).padStart(2, '0')}`; // hex with opacity
                ctx.fill();
            }
            animationFrameId = requestAnimationFrame(drawTrail);
        }

        window.startMouseTrail = () => {
            if (!trailActive && canvas) {
                trailActive = true;
                // canvas.style.opacity = '0.6'; // Set by CSS body.dark-mode #mouse-trail-canvas
                if (animationFrameId) cancelAnimationFrame(animationFrameId); // Clear previous animation
                trailPoints.length = 0; // Clear old points
                drawTrail();
            }
        };

        window.stopMouseTrail = () => {
            if (trailActive && canvas) {
                trailActive = false;
                // canvas.style.opacity = '0'; // Set by CSS
                if (animationFrameId) {
                    cancelAnimationFrame(animationFrameId);
                    animationFrameId = null;
                }
                if (ctx) ctx.clearRect(0, 0, canvas.width, canvas.height); // Clear canvas
                trailPoints.length = 0; // Clear points
            }
        };
    }
     // Initial theme application after everything is defined
    applyTheme(currentTheme);

});
