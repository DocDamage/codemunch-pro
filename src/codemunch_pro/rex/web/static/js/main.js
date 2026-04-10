/**
 * CodeMunch Pro REX - Main JavaScript
 */

document.addEventListener('DOMContentLoaded', function() {
    initAutocomplete();
    initMobileNav();
});

/**
 * Initialize autocomplete for the global search box
 */
function initAutocomplete() {
    const searchInput = document.getElementById('global-search');
    const resultsContainer = document.getElementById('autocomplete-results');
    
    if (!searchInput || !resultsContainer) return;
    
    let debounceTimer;
    let currentQuery = '';
    
    searchInput.addEventListener('input', function() {
        const query = this.value.trim();
        currentQuery = query;
        
        clearTimeout(debounceTimer);
        
        if (query.length < 2) {
            resultsContainer.classList.remove('active');
            resultsContainer.innerHTML = '';
            return;
        }
        
        debounceTimer = setTimeout(() => {
            fetchAutocomplete(query);
        }, 200);
    });
    
    // Hide results when clicking outside
    document.addEventListener('click', function(e) {
        if (!searchInput.contains(e.target) && !resultsContainer.contains(e.target)) {
            resultsContainer.classList.remove('active');
        }
    });
    
    // Handle keyboard navigation
    searchInput.addEventListener('keydown', function(e) {
        const items = resultsContainer.querySelectorAll('.autocomplete-item');
        const activeItem = resultsContainer.querySelector('.autocomplete-item.active');
        
        if (e.key === 'ArrowDown') {
            e.preventDefault();
            if (!activeItem) {
                if (items.length > 0) {
                    items[0].classList.add('active');
                }
            } else {
                const next = activeItem.nextElementSibling;
                if (next) {
                    activeItem.classList.remove('active');
                    next.classList.add('active');
                }
            }
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            if (activeItem) {
                const prev = activeItem.previousElementSibling;
                if (prev) {
                    activeItem.classList.remove('active');
                    prev.classList.add('active');
                }
            }
        } else if (e.key === 'Enter') {
            if (activeItem) {
                e.preventDefault();
                const href = activeItem.dataset.href;
                if (href) {
                    window.location.href = href;
                }
            }
        } else if (e.key === 'Escape') {
            resultsContainer.classList.remove('active');
        }
    });
    
    async function fetchAutocomplete(query) {
        try {
            const response = await fetch(`/api/autocomplete?q=${encodeURIComponent(query)}`);
            if (!response.ok) throw new Error('Failed to fetch');
            
            const data = await response.json();
            renderResults(data.suggestions, query);
        } catch (error) {
            console.error('Autocomplete error:', error);
        }
    }
    
    function renderResults(suggestions, query) {
        if (suggestions.length === 0 || query !== currentQuery) {
            resultsContainer.classList.remove('active');
            return;
        }
        
        resultsContainer.innerHTML = suggestions.map(item => `
            <div class="autocomplete-item" data-href="/entity/${encodeURIComponent(item.id)}" data-id="${item.id}">
                <span class="badge kind-${item.kind}">${item.kind}</span>
                <span class="autocomplete-name">${escapeHtml(item.name)}</span>
            </div>
        `).join('');
        
        resultsContainer.classList.add('active');
        
        // Add click handlers
        resultsContainer.querySelectorAll('.autocomplete-item').forEach(item => {
            item.addEventListener('click', function() {
                window.location.href = this.dataset.href;
            });
            
            item.addEventListener('mouseenter', function() {
                resultsContainer.querySelectorAll('.autocomplete-item').forEach(i => {
                    i.classList.remove('active');
                });
                this.classList.add('active');
            });
        });
    }
}

/**
 * Initialize mobile navigation
 */
function initMobileNav() {
    // Add mobile menu toggle if needed
    const navLinks = document.querySelector('.nav-links');
    
    if (window.innerWidth <= 768 && navLinks) {
        // Mobile-specific behavior can be added here
        navLinks.classList.add('mobile-friendly');
    }
}

/**
 * Escape HTML special characters
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Format a number as hexadecimal
 */
function formatHex(num, padding = 4) {
    return '0x' + num.toString(16).toUpperCase().padStart(padding, '0');
}

/**
 * Copy text to clipboard
 */
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        return true;
    } catch (err) {
        console.error('Failed to copy:', err);
        return false;
    }
}

/**
 * Show a temporary notification
 */
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 12px 20px;
        background: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: var(--border-radius);
        color: var(--text-primary);
        z-index: 1000;
        box-shadow: var(--shadow-md);
        animation: slideIn 0.3s ease;
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Add CSS animations for notifications
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);
