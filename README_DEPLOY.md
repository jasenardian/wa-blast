# Panduan Deployment WA Blast Pro

Project ini adalah aplikasi Node.js yang menggunakan **WhatsApp Web.js** (Puppeteer). Karena kebutuhan sistemnya yang spesifik (Headless Chrome), project ini memiliki persyaratan hosting khusus.

## ⚠️ PENTING: Shared Hosting vs VPS

**Project ini SANGAT DISARANKAN menggunakan VPS (Virtual Private Server), BUKAN Shared Hosting biasa.**

### Mengapa tidak bisa di Shared Hosting biasa?
1.  **Library Chrome:** Library `whatsapp-web.js` menjalankan browser Chrome di background. Shared hosting biasanya tidak memiliki library sistem Linux yang dibutuhkan Chrome untuk berjalan.
2.  **Resource Limit:** Proses Puppeteer memakan RAM yang cukup besar. Shared hosting sering mematikan proses yang "berat".
3.  **Socket.IO:** Aplikasi ini menggunakan koneksi real-time (Socket.IO) yang seringkali diblokir atau tidak stabil di shared hosting standar.

---

## Persyaratan Server (VPS)
*   **OS:** Ubuntu 20.04 / 22.04 LTS (Disarankan)
*   **RAM:** Minimal 1GB (Disarankan 2GB+)
*   **Node.js:** Versi 18.x atau terbaru

## Langkah Instalasi di VPS (Ubuntu)

1.  **Update Server & Install Dependencies Chrome**
    Puppeteer membutuhkan library sistem tertentu agar bisa jalan di Linux (Ubuntu). Jalankan perintah ini:

    ```bash
    sudo apt update && sudo apt upgrade -y
    sudo apt install -y gconf-service libasound2 libatk1.0-0 libc6 libc6-dev libcairo2 libcups2 libdbus-1-3 libexpat1 libfontconfig1 libgcc1 libgconf-2-4 libgdk-pixbuf2.0-0 libglib2.0-0 libgtk-3-0 libnspr4 libpango-1.0-0 libpangocairo-1.0-0 libstdc++6 libx11-6 libx11-xcb1 libxcb1 libxcomposite1 libxcursor1 libxdamage1 libxext6 libxfixes3 libxi6 libxrandr2 libxrender1 libxss1 libxtst6 ca-certificates fonts-liberation libappindicator1 libnss3 lsb-release xdg-utils wget
    ```

2.  **Install Node.js (v18)**
    ```bash
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    sudo apt install -y nodejs
    ```

3.  **Upload File Project**
    Upload semua file project Anda ke server (bisa via FTP atau Git).
    *Catatan: Folder `node_modules` dan `.wwebjs_auth` JANGAN di-upload. Kita install di server.*

4.  **Install Dependencies Project**
    Masuk ke folder project di terminal VPS:
    ```bash
    cd /path/to/project
    npm install
    ```

5.  **Jalankan Aplikasi (Mode Background)**
    Gunakan `pm2` agar aplikasi tetap jalan walaupun terminal ditutup.
    ```bash
    sudo npm install -g pm2
    pm2 start app.js --name "wa-blast"
    pm2 save
    pm2 startup
    ```

## Konfigurasi Tambahan
*   **Port:** Aplikasi berjalan di port `8000` (atau sesuai `process.env.PORT`). Pastikan firewall VPS membuka port tersebut, atau gunakan Nginx sebagai Reverse Proxy (Disarankan).
*   **Telegram Bot:** Pastikan token bot di `app.js` sudah benar.

## Troubleshooting
Jika scan QR gagal atau error Chromium:
*   Pastikan semua library di langkah 1 sudah terinstall.
*   Coba jalankan dengan `npm start` biasa dulu untuk melihat error log.
