document.addEventListener('DOMContentLoaded', function() {
  initNavbar();
  initAlerts();
  initModals();
  initTooltips();
});

function initNavbar() {
  const navbar = document.querySelector('[data-navbar]');
  if (!navbar) return;

  const toggle = navbar.querySelector('[data-navbar-toggle]');
  const menu = navbar.querySelector('[data-navbar-menu]');

  if (toggle && menu) {
    toggle.addEventListener('click', () => {
      menu.classList.toggle('hidden');
    });

    document.addEventListener('click', (e) => {
      if (!navbar.contains(e.target)) {
        menu.classList.add('hidden');
      }
    });
  }
}

function initAlerts() {
  const alerts = document.querySelectorAll('[data-alert-dismissible]');
  
  alerts.forEach(alert => {
    const closeBtn = alert.querySelector('[data-alert-close]');
    
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        alert.style.opacity = '0';
        alert.style.transform = 'translateY(-10px)';
        
        setTimeout(() => {
          alert.remove();
        }, 300);
      });
    }

    setTimeout(() => {
      if (document.body.contains(alert)) {
        alert.style.opacity = '0';
        alert.style.transform = 'translateY(-10px)';
        
        setTimeout(() => {
          if (document.body.contains(alert)) {
            alert.remove();
          }
        }, 300);
      }
    }, 5000);
  });
}

function initModals() {
  const modals = document.querySelectorAll('[data-modal]');
  
  modals.forEach(modal => {
    const openBtns = document.querySelectorAll(`[data-modal-open="${modal.id}"]`);
    const closeBtns = modal.querySelectorAll('[data-modal-close]');
    
    openBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        openModal(modal);
      });
    });
    
    closeBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        closeModal(modal);
      });
    });
    
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        closeModal(modal);
      }
    });
    
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && !modal.classList.contains('hidden')) {
        closeModal(modal);
      }
    });
  });
}

function openModal(modal) {
  modal.classList.remove('hidden');
  document.body.style.overflow = 'hidden';
  modal.querySelector('[data-modal-content]')?.classList.add('animate-fade-in');
}

function closeModal(modal) {
  const content = modal.querySelector('[data-modal-content]');
  if (content) {
    content.classList.remove('animate-fade-in');
  }
  
  setTimeout(() => {
    modal.classList.add('hidden');
    document.body.style.overflow = '';
  }, 200);
}

function initTooltips() {
  const tooltips = document.querySelectorAll('[data-tooltip]');
  
  tooltips.forEach(tooltip => {
    tooltip.addEventListener('mouseenter', showTooltip);
    tooltip.addEventListener('mouseleave', hideTooltip);
    tooltip.addEventListener('focus', showTooltip);
    tooltip.addEventListener('blur', hideTooltip);
  });
}

function showTooltip(e) {
  const tooltip = e.target.closest('[data-tooltip]');
  const text = tooltip.getAttribute('data-tooltip');
  
  if (!text) return;
  
  const tooltipEl = document.createElement('div');
  tooltipEl.className = 'fixed bg-slate-800 text-white text-xs px-2 py-1 rounded shadow-lg z-50 pointer-events-none animate-fade-in';
  tooltipEl.textContent = text;
  tooltipEl.id = 'tooltip-' + Date.now();
  
  document.body.appendChild(tooltipEl);
  
  const rect = tooltip.getBoundingClientRect();
  tooltipEl.style.top = (rect.top - tooltipEl.offsetHeight - 8) + 'px';
  tooltipEl.style.left = (rect.left + (rect.width - tooltipEl.offsetWidth) / 2) + 'px';
  
  tooltip.setAttribute('data-tooltip-id', tooltipEl.id);
}

function hideTooltip(e) {
  const tooltip = e.target.closest('[data-tooltip]');
  const tooltipId = tooltip.getAttribute('data-tooltip-id');
  
  if (tooltipId) {
    const tooltipEl = document.getElementById(tooltipId);
    if (tooltipEl) {
      tooltipEl.remove();
    }
    tooltip.removeAttribute('data-tooltip-id');
  }
}

function copyToClipboard(text, button) {
  navigator.clipboard.writeText(text).then(() => {
    const originalText = button.innerHTML;
    button.innerHTML = '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>';
    
    setTimeout(() => {
      button.innerHTML = originalText;
    }, 2000);
  }).catch(err => {
    console.error('Failed to copy:', err);
  });
}

function showLoading(button, originalText) {
  button.disabled = true;
  button.innerHTML = `
    <svg class="animate-spin -ml-1 mr-2 h-4 w-4 text-white inline-block" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
      <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
      <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
    </svg>
    ${originalText}
  `;
}

function hideLoading(button, originalText) {
  button.disabled = false;
  button.innerHTML = originalText;
}

function formatDate(dateString) {
  const date = new Date(dateString);
  const now = new Date();
  const diff = now - date;
  
  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  
  if (days > 7) {
    return date.toLocaleDateString('zh-CN', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  } else if (days > 0) {
    return `${days}天前`;
  } else if (hours > 0) {
    return `${hours}小时前`;
  } else if (minutes > 0) {
    return `${minutes}分钟前`;
  } else {
    return '刚刚';
  }
}

function formatFileSize(bytes) {
  if (bytes === 0) return '0 B';
  
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

window.upypi = {
  copyToClipboard,
  showLoading,
  hideLoading,
  formatDate,
  formatFileSize,
  debounce
};