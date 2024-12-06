// Add anchor links to headings
document.addEventListener('DOMContentLoaded', function () {
  const articleContent = document.querySelector('.runbook-content');
  if (!articleContent) return;

  const headings = articleContent.querySelectorAll('h2, h3, h4, h5, h6');

  headings.forEach(heading => {
    // Skip headings that shouldn't have anchors
    if (heading.classList.contains('no-anchor')) return;

    // Create anchor link
    const anchor = document.createElement('a');
    anchor.className = 'heading-anchor';
    anchor.href = `#${heading.id}`;
    anchor.innerHTML = '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">' +
      '<path d="M7.5 4H4.5C3.67157 4 3 4.67157 3 5.5V10.5C3 11.3284 3.67157 12 4.5 12H7.5M8.5 12H11.5C12.3284 12 13 11.3284 13 10.5V5.5C13 4.67157 12.3284 4 11.5 4H8.5" ' +
      'stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>' +
      '<path d="M6 8H10" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>' +
      '</svg>';

    // Add anchor link after heading text
    heading.appendChild(anchor);

    // Add hover behavior
    heading.addEventListener('mouseenter', () => {
      anchor.style.opacity = '1';
    });

    heading.addEventListener('mouseleave', () => {
      anchor.style.opacity = '0';
    });
  });

  // Handle anchor clicks
  document.querySelectorAll('.heading-anchor').forEach(anchor => {
    anchor.addEventListener('click', (e) => {
      e.preventDefault();
      const targetId = anchor.getAttribute('href').slice(1);
      const targetElement = document.getElementById(targetId);

      if (targetElement) {
        // Add URL fragment without scrolling
        history.pushState(null, null, `#${targetId}`);

        // Smooth scroll to element
        targetElement.scrollIntoView({
          behavior: 'smooth',
          block: 'start'
        });

        // Visual feedback
        targetElement.classList.add('highlight');
        setTimeout(() => {
          targetElement.classList.remove('highlight');
        }, 1500);
      }
    });
  });
});

// Add CSS for anchor links
const style = document.createElement('style');
style.textContent = `
    .heading-anchor {
      opacity: 0;
      margin-left: 0.5rem;
      color: var(--platinum-grey);
      transition: opacity 0.2s ease-in-out;
    }
  
    .heading-anchor:hover {
      color: var(--blue);
    }
  
    h2:hover .heading-anchor,
    h3:hover .heading-anchor,
    h4:hover .heading-anchor,
    h5:hover .heading-anchor,
    h6:hover .heading-anchor {
      opacity: 1;
    }
  
    .highlight {
      animation: highlight 1.5s ease-out;
    }
  
    @keyframes highlight {
      0% { background-color: rgba(56, 119, 255, 0.2); }
      100% { background-color: transparent; }
    }
  `;

document.head.appendChild(style);