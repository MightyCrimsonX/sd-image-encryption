(function() {
    // Utility: SHA256
    async function sha256(message) {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // Utility: GetRange
    function getRange(input, offset, rangeLen = 4) {
        offset = offset % input.length;
        return (input + input).substring(offset, offset + rangeLen);
    }

    // Utility: ShuffleArray
    async function shuffleArray(arr, key) {
        const shaKey = await sha256(key);
        const arrLen = arr.length;
        for (let i = 0; i < arrLen; i++) {
            const sIdx = arrLen - i - 1;
            const range = getRange(shaKey, i, 8);
            const val = parseInt(range, 16);
            const toIndex = val % (arrLen - i);

            // Swap
            const temp = arr[sIdx];
            arr[sIdx] = arr[toIndex];
            arr[toIndex] = temp;
        }
    }

    // Decrypt Image
    async function decryptImage(imgElement, password) {
         const canvas = document.createElement('canvas');
         const ctx = canvas.getContext('2d');
         // Use natural size
         canvas.width = imgElement.naturalWidth;
         canvas.height = imgElement.naturalHeight;
         ctx.drawImage(imgElement, 0, 0);

         const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
         const data = imageData.data; // RGBA array
         const w = canvas.width;
         const h = canvas.height;

         const x = Array.from({length: w}, (_, i) => i);
         await shuffleArray(x, password);

         const y = Array.from({length: h}, (_, i) => i);
         await shuffleArray(y, await sha256(password));

         const rowSize = w * 4;
         const tempBuffer = new Uint8ClampedArray(data); // Copy of source

         // Inverse Row Shuffle: Dest row y[v] gets Source row v
         for (let v = 0; v < h; v++) {
             const srcStart = v * rowSize;
             const destStart = y[v] * rowSize;
             for (let k = 0; k < rowSize; k++) {
                 data[destStart + k] = tempBuffer[srcStart + k];
             }
         }

         // Update temp buffer with row-decrypted data
         tempBuffer.set(data);

         // Inverse Column Shuffle: Dest col x[v] gets Source col v
         for (let r = 0; r < h; r++) {
             const rowOffset = r * rowSize;
             for (let v = 0; v < w; v++) {
                 const srcPixelIndex = rowOffset + v * 4;
                 const destPixelIndex = rowOffset + x[v] * 4;

                 data[destPixelIndex] = tempBuffer[srcPixelIndex];
                 data[destPixelIndex + 1] = tempBuffer[srcPixelIndex + 1];
                 data[destPixelIndex + 2] = tempBuffer[srcPixelIndex + 2];
                 data[destPixelIndex + 3] = tempBuffer[srcPixelIndex + 3];
             }
         }

         ctx.putImageData(imageData, 0, 0);
         return canvas.toDataURL();
    }

    // Check if image is encrypted (Parse PNG chunks)
    async function isEncrypted(src) {
        try {
            const resp = await fetch(src);
            const buf = await resp.arrayBuffer();
            const view = new DataView(buf);

            // Check PNG signature
            if (view.getUint32(0) !== 0x89504E47 || view.getUint32(4) !== 0x0D0A1A0A) return false;

            let offset = 8;
            while (offset < buf.byteLength) {
                const len = view.getUint32(offset);
                const type = new TextDecoder().decode(new Uint8Array(buf, offset + 4, 4));

                if (type === 'tEXt') {
                    const data = new Uint8Array(buf, offset + 8, len);
                    // key\0value
                    let nullByte = -1;
                    for(let i=0; i<len; i++) {
                        if (data[i] === 0) { nullByte = i; break; }
                    }
                    if (nullByte > 0) {
                        const key = new TextDecoder().decode(data.slice(0, nullByte));
                        if (key === 'Encrypt') {
                             const val = new TextDecoder().decode(data.slice(nullByte + 1));
                             if (val.includes('pixel_shuffle_3')) return true;
                        }
                    }
                }

                offset += 8 + len + 4; // Length + Type + Data + CRC
            }
            return false;
        } catch (e) {
            return false;
        }
    }

    // UI Injection
    function injectUI() {
        if (document.getElementById('sd_enc_ui')) return;

        const container = document.createElement('div');
        container.id = 'sd_enc_ui';
        container.style.position = 'fixed';
        container.style.bottom = '10px';
        container.style.right = '10px';
        container.style.zIndex = '99999';
        container.style.backgroundColor = 'rgba(0,0,0,0.8)';
        container.style.padding = '10px';
        container.style.color = 'white';
        container.style.borderRadius = '5px';
        container.style.fontFamily = 'sans-serif';

        container.innerHTML = `
            <div style="margin-bottom: 5px; font-weight: bold;">Image Decryption</div>
            <label style="display:block; margin-bottom:5px;">Password: <input type="password" id="sd_enc_pass" style="width: 100px;" /></label>
            <button id="sd_enc_btn" style="cursor: pointer; padding: 5px;">Decrypt Visible Images</button>
            <div id="sd_enc_status" style="margin-top: 5px; font-size: 0.8em;"></div>
        `;
        document.body.appendChild(container);

        document.getElementById('sd_enc_btn').onclick = async () => {
            const pass = document.getElementById('sd_enc_pass').value;
            const status = document.getElementById('sd_enc_status');

            if (!pass) {
                status.innerText = "Please enter password.";
                return;
            }

            status.innerText = "Scanning...";
            const imgs = document.querySelectorAll('img');
            let count = 0;

            for (const img of imgs) {
                 if (img.dataset.decrypted) continue;
                 // Skip small icons/thumbnails if possible, or check them too.
                 if (img.width < 64 || img.height < 64) continue;

                 if (await isEncrypted(img.src)) {
                     status.innerText = "Decrypting...";
                     const url = await decryptImage(img, pass);
                     img.src = url;
                     img.dataset.decrypted = "true";
                     count++;
                 }
            }
            status.innerText = count > 0 ? `Decrypted ${count} images.` : "No encrypted images found.";
        };
    }

    // Initialize
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', injectUI);
    } else {
        injectUI();
    }
})();
