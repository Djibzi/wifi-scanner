// toast.js — Notifications toast

class Toast {
    static show(type, title, message, duration = 4000) {
        const container = document.getElementById('toast-container');
        if (!container) return;

        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.innerHTML = `
            <div class="toast-title">${title}</div>
            ${message ? `<div class="toast-message">${message}</div>` : ''}
        `;

        container.appendChild(toast);

        setTimeout(() => {
            toast.classList.add('toast-exit');
            setTimeout(() => toast.remove(), 300);
        }, duration);
    }

    static success(title, message) { Toast.show('success', title, message); }
    static error(title, message) { Toast.show('error', title, message, 6000); }
    static warning(title, message) { Toast.show('warning', title, message, 5000); }
    static info(title, message) { Toast.show('info', title, message); }
}

window.Toast = Toast;
