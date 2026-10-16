const root = document.documentElement;
const search = document.querySelector("#doc-search");
const sections = [...document.querySelectorAll(".doc-section")];
const navLinks = [...document.querySelectorAll(".nav-link")];
const emptyNotice = document.querySelector("#search-empty");
const sidebar = document.querySelector("#sidebar");

function applySearch() {
  const query = search.value.trim().toLowerCase();
  let matches = 0;
  for (const section of sections) {
    const matchesSection =
      !query ||
      `${section.dataset.title} ${section.textContent}`
        .toLowerCase()
        .includes(query);
    section.hidden = !matchesSection;
    if (matchesSection) matches += 1;
  }
  for (const link of navLinks) {
    const target = document.querySelector(link.getAttribute("href"));
    link.hidden = Boolean(query && target && target.hidden);
  }
  emptyNotice.hidden = !query || matches > 0;
}

search.addEventListener("input", applySearch);
document.addEventListener("keydown", (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
    event.preventDefault();
    search.focus();
  }
  if (event.key === "Escape" && document.activeElement === search) {
    search.value = "";
    applySearch();
    search.blur();
  }
});

document.querySelectorAll(".copy-button").forEach((button) => {
  button.addEventListener("click", async () => {
    const text = button.closest(".code-card").querySelector("pre").innerText;
    try {
      await navigator.clipboard.writeText(text);
      button.textContent = "Copied";
      setTimeout(() => {
        button.textContent = "Copy";
      }, 1200);
    } catch {
      button.textContent = "Select code";
    }
  });
});

const theme = localStorage.getItem("rst-auth-docs-theme");
if (theme === "light") root.classList.add("light");
document.querySelector("#theme-toggle").addEventListener("click", () => {
  root.classList.toggle("light");
  localStorage.setItem(
    "rst-auth-docs-theme",
    root.classList.contains("light") ? "light" : "dark",
  );
});

document.querySelector("#mobile-menu").addEventListener("click", (event) => {
  const open = sidebar.classList.toggle("open");
  event.currentTarget.setAttribute("aria-expanded", String(open));
});
navLinks.forEach((link) =>
  link.addEventListener("click", () => {
    navLinks.forEach((item) => item.classList.toggle("active", item === link));
    sidebar.classList.remove("open");
    document
      .querySelector("#mobile-menu")
      .setAttribute("aria-expanded", "false");
  }),
);

const observer = new IntersectionObserver(
  (entries) => {
    const current = entries
      .filter((entry) => entry.isIntersecting)
      .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
    if (!current) return;
    const active = document.querySelector(
      `.nav-link[href="#${current.target.id}"]`,
    );
    if (active)
      navLinks.forEach((link) =>
        link.classList.toggle("active", link === active),
      );
  },
  { rootMargin: "-15% 0px -70% 0px", threshold: [0, 0.2, 0.5] },
);
sections.forEach((section) => observer.observe(section));
