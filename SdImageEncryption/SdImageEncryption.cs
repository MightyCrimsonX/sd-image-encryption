using System;
using System.Text;
using System.Security.Cryptography;
using SwarmUI.Core;
using SwarmUI.Utils;
using SwarmUI.Text2Image;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp.Processing;
using SixLabors.ImageSharp.Formats.Png;

namespace SwarmUI.Extensions.SdImageEncryption;

public class SdImageEncryptionExtension : Extension
{
    public static T2IRegisteredParam<string> EncryptionPassword;

    public static T2IParamGroup GroupEncryption;

    public override void OnInit()
    {
        // Define the encryption group
        GroupEncryption = new("Encryption", Toggles: false, Open: true, OrderPriority: 15, Description: "Scramble images before saving.");

        // Register the "Encryption Password" parameter
        EncryptionPassword = T2IParamTypes.Register<string>(new T2IParamType(
            "Encryption Password",
            "Password to encrypt the image pixels and metadata with. If set, the image will be scrambled before saving.",
            "",
            FeatureFlag: null,
            OrderPriority: 1,
            Group: GroupEncryption
        ));

        // Register the JS viewer
        ScriptFiles.Add("Assets/decrypt_viewer.js");

        // Hook into the PostBatchEvent
        T2IEngine.PostBatchEvent += PostBatchEvent;
    }

    private void PostBatchEvent(T2IEngine.PostBatchEventParams e)
    {
        // Check if encryption password is set in the user input
        if (!e.UserInput.TryGet(EncryptionPassword, out string password) || string.IsNullOrWhiteSpace(password))
        {
            return;
        }

        foreach (var output in e.Images)
        {
            // The image might be null if it's not loaded or failed
            if (output.Img == null)
            {
                continue;
            }

            try
            {
                // Access the underlying ImageSharp image
                // output.Img is SwarmUI.Utils.Image, which has ToIS property returning SixLabors.ImageSharp.Image
                var img = output.Img.ToIS;

                // We need to cast it to Image<Rgba32> to process pixels efficiently
                // If it's not Rgba32, we clone it as such
                Image<Rgba32> imageToEncrypt = img.CloneAs<Rgba32>();

                // Encrypt the image
                EncryptImage(imageToEncrypt, password);

                // Update metadata
                var pngMeta = imageToEncrypt.Metadata.GetPngMetadata();

                // Encrypt existing tags
                var keys = pngMeta.TextData.Select(t => t.Keyword).ToList();
                var tagList = new[] { "parameters", "UserComment" };

                foreach (var tag in tagList)
                {
                    var existing = pngMeta.TextData.FirstOrDefault(t => t.Keyword == tag);
                    if (existing.Keyword == tag)
                    {
                        string encryptedVal = EncryptString(existing.Value, password);
                        pngMeta.TextData.Remove(existing);
                        pngMeta.TextData.Add(new(tag, $"OPPAI:{encryptedVal}", "", ""));
                    }
                }

                // Add encryption marker
                pngMeta.TextData.Add(new("Encrypt", "pixel_shuffle_3", "", ""));

                // Add EncryptPwdSha
                string pwdSha = GetSHA256(password);
                string verifySha = GetSHA256(pwdSha + "Encrypt");
                pngMeta.TextData.Add(new("EncryptPwdSha", verifySha, "", ""));

                // Replace the original image with the encrypted one
                // We wrap it back into SwarmUI.Utils.Image
                // We use Image.ISImgToPngBytes to get bytes, or just construct it?
                // SwarmUI.Utils.Image takes (ISImage) constructor.
                output.Img = new SwarmUI.Utils.Image(imageToEncrypt);

                // Dispose the temporary image
                // imageToEncrypt.Dispose(); // Wait, if we passed it to SwarmUI.Utils.Image, does it take ownership?
                // SwarmUI.Utils.Image(ISImage) converts it to PNG bytes immediately according to source code I read.
                // public Image(ISImage img) : this(ImageFile.ISImgToPngBytes(img), MediaType.ImagePng)
                // So it converts to bytes. So we can dispose our local copy.
                imageToEncrypt.Dispose();
            }
            catch (Exception ex)
            {
                Logs.Error($"Failed to encrypt image: {ex}");
            }
        }
    }

    // --- Helper Methods ---

    private string GetRange(string input, int offset, int range_len = 8)
    {
        offset = offset % input.Length;
        // (input * 2)[offset:offset + range_len]
        // Optimization: avoid string concat if possible, but string is short (64 chars usually).
        string doubled = input + input;
        return doubled.Substring(offset, range_len);
    }

    private string GetSHA256(string input)
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            byte[] bytes = Encoding.UTF8.GetBytes(input);
            byte[] hash = sha256.ComputeHash(bytes);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }
    }

    private int[] ShuffleArray(int length, string key)
    {
        string sha_key = GetSHA256(key);
        int[] arr = new int[length];
        for (int i = 0; i < length; i++) arr[i] = i;

        for (int i = 0; i < length; i++)
        {
            int s_idx = length - i - 1;
            // to_index = int(GetRange(sha_key, i, range_len=8), 16) % (arr_len - i)
            string rangeHex = GetRange(sha_key, i, 8);
            // Parse hex string to long first to avoid overflow, then modulo.
            // But wait, 8 hex chars = 32 bits. long is 64 bits.
            // int.Parse with NumberStyles.HexNumber
            long val = long.Parse(rangeHex, System.Globalization.NumberStyles.HexNumber);
            int to_index = (int)(val % (length - i));

            // Swap
            int temp = arr[s_idx];
            arr[s_idx] = arr[to_index];
            arr[to_index] = temp;
        }
        return arr;
    }

    private void EncryptImage(Image<Rgba32> image, string pw)
    {
        int w = image.Width;
        int h = image.Height;

        // Python:
        // x = np.arange(w)
        // ShuffleArray(x, pw)
        // y = np.arange(h)
        // ShuffleArray(y, GetSHA256(pw))

        int[] x_perm = ShuffleArray(w, pw);
        int[] y_perm = ShuffleArray(h, GetSHA256(pw));

        // Create a new image for the result
        // We cannot easily do this in-place without a buffer.
        // We will create a new image of the same size.
        var newImage = new Image<Rgba32>(w, h);

        // a[v] = p[y[v]] -> Shuffle Rows
        // a = np.transpose(a, axes=(1, 0, 2)) -> Transpose
        // a[v] = p[x[v]] -> Shuffle Rows (Columns)
        // a = np.transpose(a, axes=(1, 0, 2)) -> Transpose Back

        // Result: dest[x, y] = source[x_perm[x], y_perm[y]]

        // We need to be careful about matching the Python logic exactly.
        // In my thought process I derived: Final[x, y] = Original[x_perm[x], y_perm[y]]
        // Let's verify again.
        // Python:
        // 1. Row shuffle: Dest1[x, y] = Src[x, y_perm[y]]
        // 2. Transpose: Dest2[x, y] = Dest1[y, x] = Src[y, y_perm[x]]
        // 3. Row shuffle (using x_perm): Dest3[x, y] = Dest2[x, x_perm[y]] = Src[x_perm[y], y_perm[x]]
        // 4. Transpose: Dest4[x, y] = Dest3[y, x] = Src[x_perm[x], y_perm[y]]
        // Yes, Dest4[x, y] takes pixel from Src at (x_perm[x], y_perm[y]).

        // Wait, Python ShuffleArray(x, pw) shuffles the array x.
        // p = a.copy()
        // for v in range(w): a[v] = p[x[v]]
        // This sets row v of 'a' to row x[v] of 'p'.
        // So a[v] comes from p[x[v]].
        // Yes, my derivation is correct.

        for (int y = 0; y < h; y++)
        {
            for (int x = 0; x < w; x++)
            {
                newImage[x, y] = image[x_perm[x], y_perm[y]];
            }
        }

        // Copy back to original image
        for (int y = 0; y < h; y++)
        {
            for (int x = 0; x < w; x++)
            {
                image[x, y] = newImage[x, y];
            }
        }

        newImage.Dispose();
    }

    private string EncryptString(string input, string password)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < input.Length; i++)
        {
            char c = input[i];
            char p = password[i % password.Length];
            int xored = (int)c ^ (int)p;
            sb.Append((char)xored);
        }
        byte[] bytes = Encoding.UTF8.GetBytes(sb.ToString());
        return Convert.ToBase64String(bytes);
    }
}
