# SD Image & Video Encryption

Añade cifrado transparente para imágenes y videos generados por Stable Diffusion WebUI Forge Neo.

## Configuración rápida

1. Asegúrate de tener instalada la dependencia `cryptography` (`pip install -r requirements.txt`). Sin ella la pestaña de video permanecerá deshabilitada.
2. Ejecuta WebUI con `--encrypt-pass=tu_clave` para activar el cifrado de imágenes (flujo existente).
3. En la pestaña **SD Encryption** dentro de la interfaz, habilita **Enable video encryption**.
4. Introduce la passphrase de video (no se guarda en disco) y ajusta:
   - **Encrypted output suffix** (`.enc` por defecto).
   - **Keep plain video copy** si deseas conservar el archivo sin cifrar.
5. Renderiza un video con WAN/WAN Neo. El archivo final `.mp4`/`.webm` se cifrará tras el render y se escribirá junto a un archivo con sufijo (por ejemplo `nombre.mp4.enc`).

> ⚠️ Si la passphrase está vacía, los videos **no** se cifrarán aunque la opción esté habilitada.

## Flujo de cifrado de video

1. WAN genera el video en el directorio de salida configurado.
2. El módulo observa la escritura final del archivo y aplica cifrado en streaming (`AES-CTR`).
3. Se genera una cabecera clara con metadatos (`SDE1`, versión, algoritmo, salt, nonce, HMAC).
4. El ciphertext se escribe por bloques (4 MiB por defecto) en `*.mp4.enc`/`*.webm.enc`.
5. Si **Keep plain video copy** está desactivado, el archivo original se elimina al completarse el cifrado.
6. Cualquier error durante el cifrado deja el archivo original sin modificaciones y registra el fallo en la consola.

Los frames temporales permanecen sin cifrar; únicamente se protege el contenedor final del video.

## Formato del archivo cifrado

- Cabecera en texto claro separada por `\n\n` con: `magic`, `versión`, `algoritmo`, `salt`, `nonce`, `hmac` (Base64).
- Cifrado con AES-CTR y claves derivadas por HKDF (salt aleatoria por archivo).
- HMAC-SHA256 calculado sobre todo el ciphertext para detectar corrupción o manipulación.
- Archivo resultante: `<original>.mp4.enc` (o sufijo configurado).

Perder la passphrase implica perder el acceso al video. No existe mecanismo de recuperación.

## Utilidad CLI: descifrar video

```
python tools/sdie_decrypt_video.py --in video.mp4.enc --out video.mp4 --passphrase "MiClaveSegura"
```

Opciones adicionales:

- `--chunk-size` para ajustar el tamaño de lectura en streaming.

Los errores de integridad (HMAC) devolverán código de salida `2` con un mensaje claro.

## Ejecución de pruebas

```
pip install -r requirements.txt
pytest
```

Las pruebas generan un video dummy con `imageio`/`ffmpeg`, verifican el cifrado/descifrado y comprueban que ficheros grandes (>64 MB) se procesan por bloques.

## Advertencias

- La passphrase de video solo vive en memoria; vuelve a introducirla cada vez que reinicies WebUI.
- El cifrado de imágenes permanece sin cambios respecto al flujo original.
- Mantén copia de seguridad de los videos cifrados y de la passphrase para evitar pérdidas permanentes.
