class SdImageEncryption {
    static init() {
        console.log("SdImageEncryption: Initializing viewer...");
        this.password = "";
        this.cache = new WeakMap(); // Cache decrypted blobs to avoid re-decrypting

        // Watch for new images
        const observer = new MutationObserver((mutations) => {
            this.addClearButton(); // Check if we need to add button
            for (const mutation of mutations) {
                for (const node of mutation.addedNodes) {
                    if (node.tagName === 'IMG') {
                        this.processImage(node);
                    } else if (node.querySelectorAll) {
                        node.querySelectorAll('img').forEach(img => this.processImage(img));
                    }
                }
            }
        });
        observer.observe(document.body, { childList: true, subtree: true });

        // Also process existing images
        document.querySelectorAll('img').forEach(img => this.processImage(img));

        this.addClearButton();
        this.hookMetadata();
    }

    static addClearButton() {
        const input = document.getElementById('input_encryptionpassword');
        if (!input) return;

        if (document.getElementById('btn_encryption_clear')) return;

        const btn = document.createElement('button');
        btn.id = 'btn_encryption_clear';
        btn.className = 'basic-button';
        btn.innerText = 'Reset';
        btn.title = "Clear the encryption password";
        btn.style.marginLeft = '0.5rem';
        btn.onclick = () => {
            input.value = '';
            input.dispatchEvent(new Event('change', { bubbles: true }));
            input.dispatchEvent(new Event('input', { bubbles: true }));
        };

        input.parentNode.appendChild(btn);
    }

    static hookMetadata() {
        setInterval(() => this.scanAndDecryptText(), 1000);
    }

    static scanAndDecryptText() {
        const password = this.getPassword();
        if (!password) return;

        const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null, false);
        let node;
        while(node = walker.nextNode()) {
            if (node.nodeValue.includes('OPPAI:')) {
                const newVal = node.nodeValue.replace(/OPPAI:([A-Za-z0-9+/=]+)/g, (match, b64) => {
                    try {
                        return this.decryptString(b64, password);
                    } catch (e) {
                        return match;
                    }
                });
                if (newVal !== node.nodeValue) {
                    node.nodeValue = newVal;
                }
            }
        }
    }

    static decryptString(b64, password) {
        try {
            // C#: Base64 -> UTF8 Bytes -> String(XOR'd chars)
            // So JS: Base64 -> Bytes -> UTF8 Decode -> String(XOR'd chars)

            const binaryString = atob(b64);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }

            // Decode UTF-8 to get the string of XOR'd characters
            const xoredString = new TextDecoder().decode(bytes);

            const decrypted = [];
            for (let i = 0; i < xoredString.length; i++) {
                const c = xoredString.charCodeAt(i);
                const p = password.charCodeAt(i % password.length);
                decrypted.push(String.fromCharCode(c ^ p));
            }
            return decrypted.join('');
        } catch (e) {
            console.error("SdImageEncryption: Decryption failed", e);
            return "Decryption Failed";
        }
    }

    static async processImage(img) {
        if (img.dataset.sdEncryptedProcessed) return;

        try {
            // Check if image source is valid
            if (!img.src || img.src.startsWith('data:') || img.src.startsWith('blob:')) return;

            // Mark as processed early to avoid loops, but we might unset it if we fail
            img.dataset.sdEncryptedProcessed = "processing";

            // If we are in a protected context (e.g. ngrok), fetch might fail if not careful with credentials.
            // But usually same-origin is fine.
            const response = await fetch(img.src, { cache: 'force-cache', credentials: 'include' });

            // It might be a 404 or something
            if (!response.ok) {
                img.dataset.sdEncryptedProcessed = "failed";
                return;
            }

            const blob = await response.blob();
            const buffer = await blob.arrayBuffer();

            if (this.isEncrypted(buffer)) {
                console.log("SdImageEncryption: Found encrypted image", img.src);
                img.dataset.sdEncryptedProcessed = "true";
                await this.decryptAndReplace(img, blob, buffer);
            } else {
                img.dataset.sdEncryptedProcessed = "not-encrypted";
            }
        } catch (e) {
            console.error("SdImageEncryption: Error processing image", img.src, e);
            img.dataset.sdEncryptedProcessed = "error";
        }
    }

    static isEncrypted(buffer) {
        const data = new Uint8Array(buffer);
        let offset = 8; // Skip PNG signature
        const view = new DataView(buffer);

        // Simple safety check for PNG
        if (data[0] !== 0x89 || data[1] !== 0x50 || data[2] !== 0x4E || data[3] !== 0x47) {
            return false;
        }

        while (offset < data.length) {
            if (offset + 8 > data.length) break;
            const length = view.getUint32(offset);
            const type = new TextDecoder().decode(data.slice(offset + 4, offset + 8));

            if (type === 'tEXt') {
                if (offset + 8 + length > data.length) break;
                const chunkData = data.slice(offset + 8, offset + 8 + length);
                const nullIndex = chunkData.indexOf(0);
                if (nullIndex > -1) {
                    const keyword = new TextDecoder().decode(chunkData.slice(0, nullIndex));
                    if (keyword === 'Encrypt') {
                        return true;
                    }
                }
            } else if (type === 'IEND') {
                break;
            }

            offset += length + 12; // Length + Type + Data + CRC
        }
        return false;
    }

    static async decryptAndReplace(img, blob, buffer) {
        let password = this.getPassword();
        if (!password) {
            img.style.filter = "blur(10px)";
            img.title = "Encrypted Image - Enter password in settings to view";
            return;
        }

        const decryptedBlob = await this.decryptImage(blob, password);
        if (decryptedBlob) {
            const url = URL.createObjectURL(decryptedBlob);
            img.src = url;
            img.style.filter = "";
            img.title = "Decrypted Image";
            img.dataset.sdDecrypted = "true";
        }
    }

    static getPassword() {
        const input = document.getElementById('input_encryptionpassword');
        if (input && input.value) {
            return input.value;
        }
        return this.password;
    }

    static async sha256(message) {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    static getRange(input, offset, rangeLen = 8) {
        offset = offset % input.length;
        let doubled = input + input;
        return doubled.substring(offset, offset + rangeLen);
    }

    static shuffleArray(length, key) {
        let arr = new Int32Array(length);
        for (let i = 0; i < length; i++) arr[i] = i;

        for (let i = 0; i < length; i++) {
            let s_idx = length - i - 1;
            let rangeHex = this.getRange(key, i, 8);
            // JS Numbers are 64-bit float, integer precision up to 53 bits.
            // 8 hex digits = 32 bits. This is safe.
            let val = parseInt(rangeHex, 16);
            let to_index = val % (length - i);

            let temp = arr[s_idx];
            arr[s_idx] = arr[to_index];
            arr[to_index] = temp;
        }
        return arr;
    }

    static async decryptImage(blob, password) {
        const imgBitmap = await createImageBitmap(blob);
        const canvas = document.createElement('canvas');
        canvas.width = imgBitmap.width;
        canvas.height = imgBitmap.height;
        const ctx = canvas.getContext('2d', { willReadFrequently: true });
        ctx.drawImage(imgBitmap, 0, 0);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const pixels = new Uint32Array(imageData.data.buffer);

        const w = canvas.width;
        const h = canvas.height;

        const pwSha = await this.sha256(password);
        const pwSha2 = await this.sha256(pwSha);

        const x_perm = this.shuffleArray(w, pwSha);
        const y_perm = this.shuffleArray(h, pwSha2);

        const newPixels = new Uint32Array(pixels.length);

        for (let y = 0; y < h; y++) {
            for (let x = 0; x < w; x++) {
                let srcIdx = y * w + x;

                // If encrypted: dest[x, y] = source[x_perm[x], y_perm[y]]
                // So source[x_perm[x], y_perm[y]] is the pixel we want to put at dest[x, y]
                // Wait, decrypting is reversing the encryption.

                // C# Encryption:
                // newImage[x, y] = image[x_perm[x], y_perm[y]];
                // Meaning: The pixel at (x,y) in EncryptedImage comes from (x_perm[x], y_perm[y]) in OriginalImage.
                // Encrypted(x, y) = Original(x_perm[x], y_perm[y])

                // To decrypt, we want to recover Original.
                // Let u = x_perm[x], v = y_perm[y].
                // Original(u, v) = Encrypted(x, y).

                // So we iterate x,y of Encrypted image (source here).
                // And we place that pixel at (u, v) in the Decrypted image (dest here).

                let u = x_perm[x];
                let v = y_perm[y];

                let destIdx = v * w + u; // Destination is Original(u, v)

                newPixels[destIdx] = pixels[srcIdx];
            }
        }

        imageData.data.set(new Uint8Array(newPixels.buffer));
        ctx.putImageData(imageData, 0, 0);

        return new Promise(resolve => canvas.toBlob(resolve, 'image/png'));
    }
}

// Start
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => SdImageEncryption.init());
} else {
    SdImageEncryption.init();
}
