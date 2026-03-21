// device-icons.js — Mappe les types d'appareils vers les icônes SVG

class DeviceIcons {
    // Retourne le chemin de l'icône SVG selon le type d'appareil

    static ICON_MAP = {
        // Téléphones
        'iphone': 'phone',
        'ipad': 'tablet',
        'smartphone': 'phone',
        'samsung': 'phone',
        'android': 'phone',
        'mobile': 'phone',
        'phone': 'phone',
        'huawei': 'phone',
        'oneplus': 'phone',
        'xiaomi': 'phone',
        'oppo': 'phone',

        // Tablettes
        'tablet': 'tablet',

        // Ordinateurs
        'pc': 'computer',
        'mac': 'computer',
        'macbook': 'computer',
        'laptop': 'computer',
        'desktop': 'computer',
        'windows': 'computer',
        'linux': 'computer',
        'liteon': 'computer',

        // Routeurs
        'routeur': 'router',
        'router': 'router',
        'gateway': 'router',
        'freebox': 'router',
        'livebox': 'router',
        'bbox': 'router',
        'sfr': 'router',

        // IoT
        'iot': 'iot',
        'espressif': 'iot',
        'raspberry': 'iot',
        'philips': 'iot',
        'wyze': 'iot',
        'ring': 'iot',

        // TV
        'tv': 'tv',
        'smart tv': 'tv',
        'chromecast': 'tv',
        'roku': 'tv',
        'fire': 'tv',

        // NAS / Serveurs
        'nas': 'server',
        'server': 'server',
        'synology': 'server',
        'qnap': 'server',

        // Enceintes
        'echo': 'speaker',
        'sonos': 'speaker',
        'bose': 'speaker',
        'nest': 'speaker',
        'homepod': 'speaker',
        'google home': 'speaker',

        // Consoles
        'nintendo': 'console',
        'xbox': 'console',
        'playstation': 'console',
        'ps4': 'console',
        'ps5': 'console',
    };

    static getIcon(deviceType, vendor) {
        // Trouve la meilleure icône pour l'appareil
        const text = `${deviceType || ''} ${vendor || ''}`.toLowerCase();

        for (const [keyword, icon] of Object.entries(DeviceIcons.ICON_MAP)) {
            if (text.includes(keyword)) {
                return `assets/icons/${icon}.svg`;
            }
        }

        return 'assets/icons/unknown.svg';
    }

    static getIconHTML(deviceType, vendor, size = 28) {
        // Retourne le HTML de l'icône
        const src = DeviceIcons.getIcon(deviceType, vendor);
        return `<img src="${src}" alt="${deviceType || 'Appareil'}" width="${size}" height="${size}" class="device-icon" style="vertical-align: middle; margin-right: 8px;">`;
    }
}

window.DeviceIcons = DeviceIcons;
