(function () {
    const THEME_KEY = "0xans-theme";
    const FONT_SIZE_KEY = "0xans-reader-font-size";
    const FONT_KEY = "0xans-reader-font";
    const WIDTH_KEY = "0xans-reader-wide";
    const themes = ["rose", "dark", "light"];

    function qs(selector, root = document) {
        return root.querySelector(selector);
    }

    function qsa(selector, root = document) {
        return Array.from(root.querySelectorAll(selector));
    }

    function getStored(key, fallback) {
        try {
            return localStorage.getItem(key) || fallback;
        } catch (_) {
            return fallback;
        }
    }

    function setStored(key, value) {
        try {
            localStorage.setItem(key, value);
        } catch (_) { }
    }

    function escapeHtml(value) {
        return String(value ?? "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function setTheme(theme) {
        const nextTheme = themes.includes(theme) ? theme : "rose";
        document.documentElement.dataset.theme = nextTheme;
        setStored(THEME_KEY, nextTheme);
        qsa("[data-theme-option]").forEach((button) => {
            const active = button.dataset.themeOption === nextTheme;
            button.classList.toggle("is-active", active);
            button.setAttribute("aria-pressed", String(active));
        });
    }

    function initThemeControls() {
        setTheme(getStored(THEME_KEY, document.documentElement.dataset.theme || "rose"));
        qsa("[data-theme-option]").forEach((button) => {
            button.addEventListener("click", () => setTheme(button.dataset.themeOption));
        });
    }

    async function loadContent() {
        const response = await fetch("data/content.json", { cache: "no-store" });
        if (!response.ok) throw new Error("Unable to load content.json");
        return response.json();
    }

    function setProfileLinks(profile) {
        if (!profile) return;
        qsa("[data-profile-github]").forEach((link) => {
            link.href = profile.github || "#";
        });
        qsa("[data-profile-avatar]").forEach((img) => {
            img.src = profile.avatar || "";
            img.alt = `${profile.name || "0xAns"} avatar`;
        });
        qsa("[data-profile-name]").forEach((node) => {
            node.textContent = profile.name || "Anas";
        });
        qsa("[data-profile-role]").forEach((node) => {
            node.textContent = profile.role || "Red Teamer";
        });
        qsa("[data-profile-bio]").forEach((node) => {
            node.textContent = profile.bio || "";
        });
    }

    function tagHtml(tags, accent = false) {
        return (tags || [])
            .map((tag) => `<span class="tag${accent ? " accent" : ""}">${escapeHtml(tag)}</span>`)
            .join("");
    }

    function articleCard(article) {
        return `
            <a class="article-card" href="read.html?id=${encodeURIComponent(article.id)}">
                <div>
                    <div class="article-meta">
                        <span>${escapeHtml(article.date)}</span>
                        <span>${escapeHtml(article.category || "Article")}</span>
                    </div>
                    <h3>${escapeHtml(article.title)}</h3>
                    <p>${escapeHtml(article.summary)}</p>
                    <div class="tag-row">${tagHtml(article.tags)}</div>
                </div>
                <span class="article-arrow" aria-hidden="true"><i class="ph ph-arrow-right"></i></span>
            </a>
        `;
    }

    function initHome(data) {
        setProfileLinks(data.profile);

        const projects = qs("#projects-list");
        if (projects) {
            projects.innerHTML = (data.projects || []).map((project) => `
                <a class="project-card" href="${escapeHtml(project.link)}" target="_blank" rel="noreferrer">
                    <div class="project-top">
                        <i class="ph ph-folder-notch-open" aria-hidden="true"></i>
                        <i class="ph ph-arrow-up-right" aria-hidden="true"></i>
                    </div>
                    <h3>${escapeHtml(project.title)}</h3>
                    <p>${escapeHtml(project.description)}</p>
                    <div class="tag-row">${tagHtml(project.tags, true)}</div>
                </a>
            `).join("");
        }

        const articles = qs("#home-articles");
        if (articles) {
            articles.innerHTML = (data.articles || []).slice(0, 3).map((article) => articleCard(article)).join("");
        }
    }

    function initArticles(data) {
        setProfileLinks(data.profile);
        let currentCategory = "all";
        const articles = data.articles || [];
        const filters = qs("#category-filters");
        const search = qs("#search-bar");
        const list = qs("#all-articles");

        function renderFilters() {
            const categories = ["all", ...new Set(articles.map((article) => article.category || "Uncategorized"))];
            filters.innerHTML = categories.map((category) => `
                <button class="filter-button${category === currentCategory ? " is-active" : ""}" data-category="${escapeHtml(category)}" type="button">
                    ${escapeHtml(category === "all" ? "All" : category)}
                </button>
            `).join("");
            qsa("[data-category]", filters).forEach((button) => {
                button.addEventListener("click", () => {
                    currentCategory = button.dataset.category;
                    renderFilters();
                    renderArticles();
                });
            });
        }

        function renderArticles() {
            const term = (search.value || "").trim().toLowerCase();
            const filtered = articles.filter((article) => {
                const category = article.category || "Uncategorized";
                const matchesCategory = currentCategory === "all" || currentCategory === category;
                const haystack = [article.title, article.summary, category, ...(article.tags || [])].join(" ").toLowerCase();
                return matchesCategory && haystack.includes(term);
            });

            list.innerHTML = filtered.length
                ? filtered.map((article) => articleCard(article)).join("")
                : `<div class="empty-state">No articles matched that signal.</div>`;
        }

        if (search) search.addEventListener("input", renderArticles);
        renderFilters();
        renderArticles();
    }

    function slugify(text) {
        return String(text || "")
            .toLowerCase()
            .trim()
            .replace(/[^\w\s-]/g, "")
            .replace(/\s+/g, "-")
            .replace(/-+/g, "-") || "section";
    }

    function calculateReadingTime(markdown) {
        const words = markdown.trim().split(/\s+/).filter(Boolean).length;
        return Math.max(1, Math.ceil(words / 225));
    }

    function renderReaderSidebar(articles, currentArticleId, term = "") {
        const container = qs("#reader-list");
        if (!container) return;
        const safeTerm = term.trim().toLowerCase();
        const visible = safeTerm
            ? articles.filter((article) => [article.title, article.category, ...(article.tags || [])].join(" ").toLowerCase().includes(safeTerm))
            : articles;
        const groups = visible.reduce((acc, article) => {
            const category = article.category || "General";
            acc[category] = acc[category] || [];
            acc[category].push(article);
            return acc;
        }, {});

        const html = Object.entries(groups).map(([category, items]) => `
            <div class="reader-category">${escapeHtml(category)}</div>
            ${items.map((article) => {
                const active = article.id === currentArticleId ? " is-active" : "";
                return `<a class="reader-link${active}" href="read.html?id=${encodeURIComponent(article.id)}">${escapeHtml(article.title)}</a>`;
            }).join("")}
        `).join("");

        container.innerHTML = html || `<div class="empty-state">No articles found.</div>`;
    }

    function initReaderControls() {
        const settingsButton = qs("#settings-btn");
        const settingsMenu = qs("#settings-menu");
        const wrap = qs("#article-wrap");
        const markdownBody = qs("#markdown-body");
        const sizeDisplay = qs("#font-size-display");
        const wideButton = qs("#wide-toggle");
        let fontSize = parseInt(getStored(FONT_SIZE_KEY, "100"), 10);
        let fontMode = getStored(FONT_KEY, "sans");
        let isWide = getStored(WIDTH_KEY, "false") === "true";

        function applyFontSize() {
            fontSize = Math.min(150, Math.max(80, fontSize));
            if (markdownBody) markdownBody.style.fontSize = `${fontSize}%`;
            if (sizeDisplay) sizeDisplay.textContent = `${fontSize}%`;
            setStored(FONT_SIZE_KEY, String(fontSize));
        }

        function applyFont(mode) {
            fontMode = mode === "serif" ? "serif" : "sans";
            document.body.classList.toggle("font-serif", fontMode === "serif");
            qsa("[data-font-mode]").forEach((button) => {
                button.classList.toggle("is-active", button.dataset.fontMode === fontMode);
            });
            setStored(FONT_KEY, fontMode);
        }

        function applyWidth() {
            if (wrap) wrap.classList.toggle("is-wide", isWide);
            if (wideButton) wideButton.classList.toggle("is-active", isWide);
            setStored(WIDTH_KEY, String(isWide));
        }

        settingsButton?.addEventListener("click", (event) => {
            event.stopPropagation();
            settingsMenu?.classList.toggle("is-open");
        });
        document.addEventListener("click", (event) => {
            if (settingsMenu && !settingsMenu.contains(event.target) && event.target !== settingsButton) {
                settingsMenu.classList.remove("is-open");
            }
        });
        qsa("[data-font-step]").forEach((button) => {
            button.addEventListener("click", () => {
                fontSize += parseInt(button.dataset.fontStep, 10);
                applyFontSize();
            });
        });
        qsa("[data-font-mode]").forEach((button) => {
            button.addEventListener("click", () => applyFont(button.dataset.fontMode));
        });
        wideButton?.addEventListener("click", () => {
            isWide = !isWide;
            applyWidth();
        });

        applyFontSize();
        applyFont(fontMode);
        applyWidth();
    }

    function addCopyButtons() {
        qsa(".article-content pre").forEach((pre) => {
            const wrapper = document.createElement("div");
            wrapper.className = "code-wrapper";
            pre.parentNode.insertBefore(wrapper, pre);
            wrapper.appendChild(pre);

            const button = document.createElement("button");
            button.type = "button";
            button.className = "copy-btn";
            button.innerHTML = `<i class="ph ph-copy" aria-hidden="true"></i> Copy`;
            button.addEventListener("click", async () => {
                const code = pre.textContent || "";
                try {
                    await navigator.clipboard.writeText(code);
                    button.innerHTML = `<i class="ph ph-check" aria-hidden="true"></i> Copied`;
                    window.setTimeout(() => {
                        button.innerHTML = `<i class="ph ph-copy" aria-hidden="true"></i> Copy`;
                    }, 1400);
                } catch (_) {
                    button.textContent = "Copy failed";
                }
            });
            wrapper.appendChild(button);
        });
    }

    function generateToc() {
        const content = qs("#markdown-body");
        const toc = qs("#toc-nav");
        const tocWrap = qs("#reader-toc");
        if (!content || !toc || !tocWrap) return;

        const headings = qsa("h1, h2, h3", content);
        toc.innerHTML = "";
        if (!headings.length) {
            tocWrap.classList.add("hide");
            return;
        }
        tocWrap.classList.remove("hide");

        const usedIds = new Set();
        headings.forEach((heading) => {
            let id = heading.id || slugify(heading.textContent);
            let nextId = id;
            let count = 2;
            while (usedIds.has(nextId)) {
                nextId = `${id}-${count}`;
                count += 1;
            }
            heading.id = nextId;
            usedIds.add(nextId);

            const link = document.createElement("a");
            link.href = `#${nextId}`;
            link.textContent = heading.textContent;
            link.className = `toc-link depth-${heading.tagName.slice(1)}`;
            link.addEventListener("click", (event) => {
                event.preventDefault();
                heading.scrollIntoView({ behavior: "smooth", block: "start" });
            });
            toc.appendChild(link);
        });
    }

    async function initReader(data) {
        setProfileLinks(data.profile);
        initReaderControls();

        const params = new URLSearchParams(window.location.search);
        const currentArticleId = params.get("id");
        const articles = data.articles || [];
        const article = articles.find((item) => item.id === currentArticleId);
        const search = qs("#reader-search");
        const sidebar = qs("#reader-sidebar");
        const overlay = qs("#sidebar-overlay");

        function setSidebar(open) {
            sidebar?.classList.toggle("is-open", open);
            overlay?.classList.toggle("is-open", open);
        }

        qs("#mobile-menu")?.addEventListener("click", () => setSidebar(true));
        qs("#sidebar-close")?.addEventListener("click", () => setSidebar(false));
        overlay?.addEventListener("click", () => setSidebar(false));
        search?.addEventListener("input", () => renderReaderSidebar(articles, currentArticleId, search.value));
        renderReaderSidebar(articles, currentArticleId);

        if (!currentArticleId) {
            qs("#loading").innerHTML = `
                <div>
                    <i class="ph ph-book-open" aria-hidden="true"></i>
                    <p>Select an article from the library.</p>
                </div>
            `;
            return;
        }

        if (!article) {
            qs("#loading").innerHTML = `
                <div>
                    <i class="ph ph-warning" aria-hidden="true"></i>
                    <p>Article not found.</p>
                </div>
            `;
            return;
        }

        document.title = `${article.title} | 0xAns`;
        qs("#crumb-title").textContent = article.title;
        qs("#article-title").textContent = article.title;
        qs("#article-date").textContent = article.date;
        qs("#article-category").textContent = article.category || "Article";
        qs("#article-tags").innerHTML = tagHtml(article.tags, true);
        if (article.cover) {
            const cover = qs("#article-cover");
            cover.src = article.cover;
            cover.alt = `${article.title} cover`;
            cover.classList.remove("hide");
        }

        try {
            const markdownResponse = await fetch(article.file, { cache: "no-store" });
            if (!markdownResponse.ok) throw new Error("Unable to load markdown");
            const markdown = await markdownResponse.text();
            qs("#read-time").textContent = `${calculateReadingTime(markdown)} min read`;

            if (window.marked) {
                marked.use({ gfm: true, breaks: true });
                qs("#markdown-body").innerHTML = marked.parse(markdown);
            } else {
                qs("#markdown-body").textContent = markdown;
            }

            if (window.hljs) hljs.highlightAll();
            addCopyButtons();
            generateToc();
            qs("#loading").classList.add("hide");
            qs("#reader-article").classList.remove("hide");
        } catch (error) {
            qs("#loading").innerHTML = `
                <div>
                    <i class="ph ph-warning" aria-hidden="true"></i>
                    <p>Could not load this article.</p>
                </div>
            `;
            console.error(error);
        }
    }

    document.addEventListener("DOMContentLoaded", async () => {
        initThemeControls();
        try {
            const data = await loadContent();
            const page = document.body.dataset.page;
            if (page === "home") initHome(data);
            if (page === "articles") initArticles(data);
            if (page === "reader") initReader(data);
        } catch (error) {
            console.error(error);
            qsa("[data-load-error]").forEach((node) => {
                node.textContent = "Could not load site content.";
            });
        }
    });
})();
