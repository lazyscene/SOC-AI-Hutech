(function initEarlyTheme() {
    try {
        const saved = localStorage.getItem('soc_theme');
        if (saved === 'light') {
            document.documentElement.classList.remove('dark');
        } else {
            document.documentElement.classList.add('dark');
        }
    } catch (e) {}
})();

tailwind.config = {
    darkMode: 'class',
    theme: {
        extend: {
            colors: {
                background: 'hsl(var(--background) / <alpha-value>)',
                foreground: 'hsl(var(--foreground) / <alpha-value>)',
                card: {
                    DEFAULT: 'hsl(var(--card) / <alpha-value>)',
                    foreground: 'hsl(var(--card-foreground) / <alpha-value>)'
                },
                muted: {
                    DEFAULT: 'hsl(var(--muted) / <alpha-value>)',
                    foreground: 'hsl(var(--muted-foreground) / <alpha-value>)'
                },
                border: 'hsl(var(--border) / <alpha-value>)',
                input: 'hsl(var(--input) / <alpha-value>)',
                primary: {
                    DEFAULT: 'hsl(var(--primary) / <alpha-value>)',
                    foreground: 'hsl(var(--primary-foreground) / <alpha-value>)'
                },
                secondary: {
                    DEFAULT: 'hsl(var(--secondary) / <alpha-value>)',
                    foreground: 'hsl(var(--secondary-foreground) / <alpha-value>)'
                },
                accent: {
                    DEFAULT: 'hsl(var(--accent) / <alpha-value>)',
                    foreground: 'hsl(var(--accent-foreground) / <alpha-value>)'
                },
                sidebar: {
                    DEFAULT: 'hsl(var(--sidebar) / <alpha-value>)',
                    foreground: 'hsl(var(--sidebar-foreground) / <alpha-value>)',
                    border: 'hsl(var(--sidebar-border) / <alpha-value>)',
                    hover: 'hsl(var(--sidebar-hover) / <alpha-value>)'
                }
            }
        }
    }
};
