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
        // SwarmUI displays metadata in various places. We need to intercept or update it.
        // The most common place is likely a metadata viewer or parameter list.
        // SwarmUI uses `formatMetadata` helper. We can try to monkey-patch it or
        // observe metadata elements.
        // For now, let's look for elements with "param_view_block" class which contains text.
        // But the text is likely already rendered.
        // If the metadata JSON itself contains "OPPAI:...", SwarmUI might display it as is.

        // Simple polling/observer approach for now to find OPPAI strings in DOM and decrypt them.
        setInterval(() => this.scanAndDecryptText(), 1000);
    }

    static scanAndDecryptText() {
        // Look for text nodes containing OPPAI:
        // This is expensive if done on whole body. Let's restrict to likely containers if possible.
        // Or just use a TreeWalker.

        const password = this.getPassword();
        if (!password) return;

        const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null, false);
        let node;
        while(node = walker.nextNode()) {
            if (node.nodeValue.includes('OPPAI:')) {
                // Decrypt
                const newVal = node.nodeValue.replace(/OPPAI:([A-Za-z0-9+/=]+)/g, (match, b64) => {
                    try {
                        return this.decryptString(b64, password);
                    } catch (e) {
                        console.error("Failed to decrypt text", e);
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
            const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
            const decrypted = [];
            for (let i = 0; i < bytes.length; i++) {
                const c = bytes[i];
                const p = password.charCodeAt(i % password.length);
                decrypted.push(String.fromCharCode(c ^ p));
            }
            return decrypted.join('');
        } catch (e) {
            return "Decryption Failed";
        }
    }

    static async processImage(img) {
        if (img.dataset.sdEncryptedProcessed) return;

        try {
            // Check if image source is valid
            if (!img.src || img.src.startsWith('data:')) return;

            // Fetch image headers to check for Encrypt tag
            // We fetch the whole image as blob because we might need to decrypt it
            const response = await fetch(img.src);
            const blob = await response.blob();
            const buffer = await blob.arrayBuffer();

            if (this.isEncrypted(buffer)) {
                console.log("SdImageEncryption: Found encrypted image", img.src);
                img.dataset.sdEncryptedProcessed = "true"; // Mark as processed so we don't loop
                await this.decryptAndReplace(img, blob, buffer);
            }
        } catch (e) {
            // console.error("SdImageEncryption: Error processing image", e);
            // Silent fail for normal images
        }
    }

    static isEncrypted(buffer) {
        const data = new Uint8Array(buffer);
        let offset = 8; // Skip PNG signature
        const view = new DataView(buffer);

        while (offset < data.length) {
            const length = view.getUint32(offset);
            const type = new TextDecoder().decode(data.slice(offset + 4, offset + 8));

            if (type === 'tEXt') {
                const chunkData = data.slice(offset + 8, offset + 8 + length);
                // tEXt format: Keyword + null + Text
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
        // Get password
        let password = this.getPassword();
        if (!password) {
            // Only blur if we *know* it's encrypted but lack password
            img.style.filter = "blur(10px)";
            img.title = "Encrypted Image - Enter password in settings to view";
            // Mark for retry later?
            img.dataset.sdEncryptedProcessed = ""; // Unset so we retry
            return;
        }

        // Verify password hash if present
        // We need to parse chunks again to find EncryptPwdSha
        // ... omitted for brevity/simplicity, logic assumes password is correct or tries anyway

        const decryptedBlob = await this.decryptImage(blob, password);
        if (decryptedBlob) {
            const url = URL.createObjectURL(decryptedBlob);
            img.src = url;
            img.style.filter = "";
            img.title = "Decrypted Image";
            img.dataset.sdDecrypted = "true";

            // TODO: Also decrypt metadata and update data attributes if SwarmUI uses them
        }
    }

    static getPassword() {
        // Try to find the input in the UI
        const input = document.getElementById('input_encryptionpassword');
        if (input && input.value) {
            return input.value;
        }
        return this.password; // Fallback to cached password
    }

    static async sha256(message) {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    static getRange(input, offset, rangeLen = 8) {
        offset = offset % input.length;
        // input * 2
        let doubled = input + input;
        return doubled.substring(offset, offset + rangeLen);
    }

    static shuffleArray(length, key) {
        // key is hex string of SHA256
        let arr = new Int32Array(length);
        for (let i = 0; i < length; i++) arr[i] = i;

        for (let i = 0; i < length; i++) {
            let s_idx = length - i - 1;
            let rangeHex = this.getRange(key, i, 8);
            // We need to parse 8 hex chars = 32 bits.
            // parseInt handles it, but verify behavior with large numbers (unsigned vs signed)
            // 8 hex chars max is FFFFFFFF = 4294967295. JS numbers are doubles, safe up to 2^53.
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
        // Use Uint32Array to manipulate pixels directly (RGBA)
        const pixels = new Uint32Array(imageData.data.buffer);

        const w = canvas.width;
        const h = canvas.height;

        const pwSha = await this.sha256(password);
        const pwSha2 = await this.sha256(pwSha);

        const x_perm = this.shuffleArray(w, pwSha);
        const y_perm = this.shuffleArray(h, pwSha2);

        const newPixels = new Uint32Array(pixels.length);

        // Decrypt logic: Original[x_perm[x], y_perm[y]] = Shuffled[x, y]
        for (let y = 0; y < h; y++) {
            for (let x = 0; x < w; x++) {
                let srcIdx = y * w + x;
                let destX = x_perm[x];
                let destY = y_perm[y];
                let destIdx = destY * w + destX;
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
