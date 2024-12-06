// Runbook functionality
class RunbookManager {
  constructor() {
    this.initializeVariables();
    this.setupEventListeners();
    this.handleInitialState();
  }

  initializeVariables() {
    // Navigation elements
    this.navToggle = document.querySelector('.nav-toggle');
    this.navLinks = document.querySelector('.nav-links');

    // Table of contents
    this.toc = document.querySelector('.runbook-toc');
    this.tocLinks = document.querySelectorAll('.toc-list a');

    // Content sections
    this.sections = document.querySelectorAll('h2[id], h3[id]');

    // Current section tracking
    this.currentSection = null;
    this.tocObserver = null;
  }

  setupEventListeners() {
    // Mobile navigation
    if (this.navToggle) {
      this.navToggle.addEventListener('click', () => this.toggleNavigation());
    }

    // Table of contents navigation
    this.tocLinks.forEach(link => {
      link.addEventListener('click', (e) => this.handleTocClick(e));
    });

    // Scroll spy
    this.setupScrollSpy();

    // Handle initial hash
    if (window.location.hash) {
      this.scrollToSection(window.location.hash);
    }
  }

  handleInitialState() {
    // Set initial active section
    this.updateActiveSection();

    // Handle mobile nav initial state
    this.handleMobileNavState();
  }

  toggleNavigation() {
    const isExpanded = this.navToggle.getAttribute('aria-expanded') === 'true';
    this.navToggle.setAttribute('aria-expanded', !isExpanded);
    this.navLinks.classList.toggle('active');
  }

  handleTocClick(e) {
    e.preventDefault();
    const targetId = e.target.getAttribute('href');
    this.scrollToSection(targetId);
    history.pushState(null, null, targetId);
  }

  scrollToSection(targetId) {
    const targetElement = document.querySelector(targetId);
    if (!targetElement) return;

    const headerOffset = 80; // Adjust based on fixed header height
    const elementPosition = targetElement.getBoundingClientRect().top;
    const offsetPosition = elementPosition + window.pageYOffset - headerOffset;

    window.scrollTo({
      top: offsetPosition,
      behavior: 'smooth'
    });

    // Highlight the section temporarily
    targetElement.classList.add('highlight');
    setTimeout(() => {
      targetElement.classList.remove('highlight');
    }, 1500);
  }

  setupScrollSpy() {
    const options = {
      root: null,
      rootMargin: '-100px 0px -66%',
      threshold: 0
    };

    this.tocObserver = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          this.updateActiveTocLink(entry.target);
        }
      });
    }, options);

    this.sections.forEach(section => {
      this.tocObserver.observe(section);
    });
  }

  updateActiveTocLink(section) {
    this.tocLinks.forEach(link => {
      link.classList.remove('active');
      if (link.getAttribute('href') === `#${section.id}`) {
        link.classList.add('active');
      }
    });
  }

  updateActiveSection() {
    const scrollPosition = window.scrollY;

    for (const section of this.sections) {
      const sectionTop = section.offsetTop - 100;
      const sectionBottom = sectionTop + section.offsetHeight;

      if (scrollPosition >= sectionTop && scrollPosition < sectionBottom) {
        if (this.currentSection !== section.id) {
          this.currentSection = section.id;
          this.updateActiveTocLink(section);
        }
        break;
      }
    }
  }

  handleMobileNavState() {
    const mediaQuery = window.matchMedia('(max-width: 768px)');

    const handleMobileChange = (e) => {
      if (!e.matches) {
        // Reset mobile nav when returning to desktop
        this.navLinks.classList.remove('active');
        this.navToggle.setAttribute('aria-expanded', 'false');
      }
    };

    mediaQuery.addListener(handleMobileChange);
  }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  new RunbookManager();
});

// Add copy functionality to code blocks
document.querySelectorAll('pre code').forEach((block) => {
  const copyButton = document.createElement('button');
  copyButton.className = 'copy-button';
  copyButton.textContent = 'Copy';

  block.parentNode.style.position = 'relative';
  block.parentNode.appendChild(copyButton);

  copyButton.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(block.textContent);
      copyButton.textContent = 'Copied!';
      copyButton.classList.add('copied');

      setTimeout(() => {
        copyButton.textContent = 'Copy';
        copyButton.classList.remove('copied');
      }, 2000);
    } catch (err) {
      console.error('Failed to copy text:', err);
      copyButton.textContent = 'Failed to copy';
      copyButton.classList.add('error');

      setTimeout(() => {
        copyButton.textContent = 'Copy';
        copyButton.classList.remove('error');
      }, 2000);
    }
  });
});

// Add support for deep linking
window.addEventListener('hashchange', () => {
  if (window.location.hash) {
    const targetElement = document.querySelector(window.location.hash);
    if (targetElement) {
      setTimeout(() => {
        targetElement.scrollIntoView({
          behavior: 'smooth',
          block: 'start'
        });
      }, 0);
    }
  }
});