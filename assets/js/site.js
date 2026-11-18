(function () {
    const FONT_SIZE_KEY = "0xans-reader-font-size";
    const FONT_KEY = "0xans-reader-font";
    const WIDTH_KEY = "0xans-reader-wide";

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
        qsa("[data-profile-bio]").forEach((node) => {
            node.textContent = profile.bio || "";
        });
    }

    function tagHtml(tags) {
        return (tags || []).map(tag => `<span class="tag">${escapeHtml(tag)}</span>`).join("");
    }

    function displayDate(value) {
        const date = new Date(`${value}T00:00:00Z`);
        return Number.isNaN(date.getTime()) ? value : date.toLocaleDateString("en-GB", {
            day: "numeric", month: "short", year: "numeric", timeZone: "UTC"
        });
    }

    function articleCard(article) {
        const cover = article.cover
            ? `<div class="article-thumb"><img src="${escapeHtml(article.cover)}" alt=""></div>`
            : "";
        return `
            <a class="article-card${cover ? "" : " no-cover"}" href="read.html?id=${encodeURIComponent(article.id)}">
                ${cover}
                <div>
                    <div class="meta"><time datetime="${escapeHtml(article.date)}">${escapeHtml(displayDate(article.date))}</time></div>
                    <h3>${escapeHtml(article.title)}</h3>
                    <p>${escapeHtml(article.summary)}</p>
                    <div class="tag-row">${tagHtml(article.tags)}</div>
                </div>
            </a>`;
    }

    function initHome(data) {
        setProfileLinks(data.profile);
        qs("#projects-list").innerHTML = (data.projects || []).map(project => `
            <a class="project-link" href="${escapeHtml(project.link)}">
                <div class="project-line"><strong>${escapeHtml(project.title)}</strong><span>${escapeHtml(project.tags?.[0])}</span></div>
                <p>${escapeHtml(project.description)}</p>
            </a>`).join("");
        qs("#home-articles").innerHTML = (data.articles || []).slice(0, 3).map(articleCard).join("");
    }

    function initArticles(data) {
        setProfileLinks(data.profile);
        let currentCategory = "all";
        const articles = data.articles || [];
        initLibrary(articles, null);
        const filters = qs("#category-filters");
        const search = qs("#search-bar");
        const list = qs("#all-articles");

        function renderFilters() {
            const categories = ["all", ...new Set(articles.map((article) => article.category || "Uncategorized"))];
            filters.innerHTML = categories.map((category) => `
                <button aria-pressed="${category === currentCategory}" data-category="${escapeHtml(category)}" type="button">
                    ${escapeHtml(category === "all" ? "All" : category)}
                </button>
            `).join("");
            qsa("[data-category]", filters).forEach((button) => {
                button.addEventListener("click", () => {
                    currentCategory = button.dataset.category;
                    qsa("[data-category]", filters).forEach(option => option.setAttribute("aria-pressed", String(option === button)));
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

            qs("#result-count").textContent = `${filtered.length} ${filtered.length === 1 ? "article" : "articles"}`;
            list.innerHTML = filtered.length
                ? filtered.map((article) => articleCard(article)).join("")
                : `<div class="empty-state">No matching articles. Try another search or category.</div>`;
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

    function initLibrary(articles, currentId) {
        const panel = qs("#library-panel");
        const toggle = qs("#library-toggle");
        const list = qs("#library-groups");
        const search = qs("#library-search");
        const desktop = window.matchMedia("(min-width: 850px)");
        const toolbar = qs(".reader-tools");
        const layout = panel.parentElement;
        const visibilityKey = "0xans-library-open";

        function show(open) {
            panel.hidden = !open;
            toggle.setAttribute("aria-expanded", String(open));
        }
        function restore() {
            if (desktop.matches) layout.prepend(panel);
            else toolbar.append(panel);
            show(desktop.matches && getStored(visibilityKey, "true") === "true");
        }
        toggle.addEventListener("click", () => {
            show(panel.hidden);
            if (desktop.matches) setStored(visibilityKey, String(!panel.hidden));
        });
        document.addEventListener("click", event => {
            if (!desktop.matches && !panel.contains(event.target) && !toggle.contains(event.target)) show(false);
        });
        document.addEventListener("keydown", event => {
            if (event.key === "Escape" && !desktop.matches && !panel.hidden) {
                show(false);
                toggle.focus();
            }
        });
        desktop.addEventListener("change", restore);
        restore();

        const topics = new Map();
        articles.forEach(article => {
            const topic = article.category || "Uncategorized";
            if (!topics.has(topic)) topics.set(topic, []);
            topics.get(topic).push(article);
        });
        let expanded = new Set();
        for (const [topic, entries] of topics) {
            if (entries.some(article => article.id === currentId)) expanded.add(topic);
        }
        function render(term = "") {
            const sections = [];
            for (const [topic, entries] of topics) {
                const matches = entries.filter(article =>
                    [topic, article.title, article.summary, ...(article.tags || [])].join(" ").toLowerCase().includes(term)
                );
                if (!matches.length) continue;
                const links = matches.map(article => {
                    const current = article.id === currentId ? ' aria-current="page"' : "";
                    return `<a href="read.html?id=${encodeURIComponent(article.id)}"${current}>${escapeHtml(article.title)}</a>`;
                }).join("");
                sections.push(`<details class="topic" data-topic="${escapeHtml(topic)}" ${term || expanded.has(topic) ? "open" : ""}>
                    <summary>${escapeHtml(topic)} <span>${matches.length}</span></summary>
                    <div>${links}</div></details>`);
            }
            list.innerHTML = sections.join("") || '<p class="empty-state">No articles found.</p>';
        }
        let searching = false;
        search.addEventListener("input", () => {
            const term = search.value.trim().toLowerCase();
            if (!searching) expanded = new Set(qsa(".topic[open]", list).map(group => group.dataset.topic));
            searching = Boolean(term);
            render(term);
        });
        render();
    }

    function initReaderControls() {
        const form = qs("#reading-settings");
        const menu = form.closest("details");
        const article = qs("#reader-article");
        const size = qs("#text-size");
        const leading = qs("#line-height");
        const width = qs("#line-width");
        const font = qs("#typeface");
        const widthKey = "0xans-reader-measure";
        const leadingKey = "0xans-reader-leading";
        const defaults = { size: "110", leading: "175", width: "standard", font: "sans" };

        function apply() {
            const sizeValue = size.value + "%";
            const leadingValue = String(Number(leading.value) / 100);
            qs("#size-value").textContent = sizeValue;
            qs("#leading-value").textContent = leadingValue + "×";
            size.setAttribute("aria-valuetext", sizeValue);
            leading.setAttribute("aria-valuetext", leadingValue + " times text size");
            article.style.setProperty("--reading-size", size.value + "%");
            article.style.setProperty("--reading-leading", leadingValue);
            article.style.setProperty("--reading-font", "var(--" + font.value + ")");
            article.dataset.measure = width.value;
        }
        function setValues(values) {
            size.value = values.size;
            leading.value = values.leading;
            width.value = ["narrow", "standard", "wide"].includes(values.width) ? values.width : defaults.width;
            font.value = ["sans", "serif", "mono"].includes(values.font) ? values.font : defaults.font;
            apply();
        }
        function save() {
            setStored(FONT_SIZE_KEY, size.value);
            setStored(FONT_KEY, font.value);
            setStored(leadingKey, leading.value);
            setStored(widthKey, width.value);
        }
        setValues({
            size: getStored(FONT_SIZE_KEY, defaults.size),
            leading: getStored(leadingKey, defaults.leading),
            width: getStored(widthKey, getStored(WIDTH_KEY, "false") === "true" ? "wide" : defaults.width),
            font: getStored(FONT_KEY, defaults.font)
        });
        form.addEventListener("input", () => { apply(); save(); });
        form.addEventListener("reset", event => {
            event.preventDefault();
            setValues(defaults);
            save();
        });
        document.addEventListener("click", event => {
            if (!menu.contains(event.target)) menu.open = false;
        });
        document.addEventListener("keydown", event => {
            if (event.key === "Escape" && menu.open) {
                menu.open = false;
                qs("summary", menu).focus();
            }
        });
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
            button.textContent = "Copy";
            button.addEventListener("click", async () => {
                const code = pre.textContent || "";
                try {
                    await navigator.clipboard.writeText(code);
                    button.textContent = "Copied";
                    window.setTimeout(() => {
                        button.textContent = "Copy";
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
        initLibrary(articles, currentArticleId);

        if (!currentArticleId) {
            qs("#loading").innerHTML = 'Choose a post from the <a href="articles.html">writing archive</a>.';
            return;
        }

        if (!article) {
            qs("#loading").innerHTML = 'Article not found. <a href="articles.html">Browse all writing</a>.';
            return;
        }

        document.title = `${article.title} | 0xAns`;
        qs("#article-title").textContent = article.title;
        qs("#article-date").textContent = displayDate(article.date);
        qs("#article-category").textContent = article.category || "Article";
        qs("#article-tags").innerHTML = tagHtml(article.tags);
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
                const body = qs("#markdown-body");
                body.innerHTML = marked.parse(markdown);
                const heading = body.firstElementChild;
                if (heading?.tagName === "H1") {
                    const title = heading.textContent.trim();
                    if (title === article.title) {
                        heading.remove();
                    } else if (title.startsWith(article.title + ":")) {
                        const subtitle = qs("#article-subtitle");
                        subtitle.textContent = title.slice(article.title.length + 1).trim();
                        subtitle.classList.remove("hide");
                        heading.remove();
                    }
                }
            } else {
                qs("#markdown-body").classList.add("plain-markdown");
                qs("#markdown-body").textContent = markdown;
            }

            if (window.hljs) hljs.highlightAll();
            addCopyButtons();
            generateToc();
            qs("#loading").classList.add("hide");
            qs("#reader-article").classList.remove("hide");
            if (location.hash) document.getElementById(location.hash.slice(1))?.scrollIntoView();
        } catch (error) {
            qs("#loading").textContent = "Could not load this article.";
            console.error(error);
        }
    }

    document.addEventListener("DOMContentLoaded", async () => {
        try {
            const data = await loadContent();
            const page = document.body.dataset.page;
            if (page === "home") initHome(data);
            if (page === "articles") initArticles(data);
            if (page === "reader") await initReader(data);
        } catch (error) {
            console.error(error);
            qsa("[data-load-error]").forEach((node) => {
                node.textContent = "Could not load site content.";
            });
        }
    });
})();
