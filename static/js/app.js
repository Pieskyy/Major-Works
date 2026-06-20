const THEMES = {
    dark: { icon: "🌙" },
    light: { icon: "☀️" },
};

function applyTheme(theme) {
    document.body.classList.toggle("light-mode", theme === "light");
    const button = document.getElementById("theme-toggle");
    if (button) {
        button.textContent = THEMES[theme]?.icon || THEMES.dark.icon;
    }
    localStorage.setItem("site-theme", theme);
}

function loadTheme() {
    const saved = localStorage.getItem("site-theme");
    const theme = saved === "light" ? "light" : "dark";
    applyTheme(theme);
}

function toggleTheme() {
    const current = document.body.classList.contains("light-mode") ? "light" : "dark";
    applyTheme(current === "light" ? "dark" : "light");
}

window.addEventListener("DOMContentLoaded", () => {
    const button = document.getElementById("theme-toggle");
    if (button) {
        button.addEventListener("click", toggleTheme);
    }
    loadTheme();

    if ("serviceWorker" in navigator) {
        navigator.serviceWorker
            .register("/static/js/serviceWorker.js")
            .then(() => console.log("service worker registered"))
            .catch((err) => console.log("service worker not registered", err));
    }
});
