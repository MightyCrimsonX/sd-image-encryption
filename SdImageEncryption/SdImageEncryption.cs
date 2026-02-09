using System;
using System.Text;
using System.Security.Cryptography;
using SwarmUI.Core;
using SwarmUI.Utils;
using SwarmUI.Text2Image;
using SwarmUI.Media;
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
        T2IEngine.PostGenerateEvent += PostGenerateEvent;
    }

    private void PostGenerateEvent(T2IEngine.PostGenerationEventParams e)
    {
        // Check if encryption password is set in the user input
        if (!e.UserInput.TryGet(EncryptionPassword, out string password) || string.IsNullOrWhiteSpace(password))
        {
            return;
        }

        // Encrypt Pixels
        if (e.File is SwarmUI.Utils.Image img)
        {
            try
            {
                var isImg = img.ToIS;
                using var rgbaImg = isImg.CloneAs<Rgba32>();
                EncryptImage(rgbaImg, password);

                // Update the image data
                // We must use reflection or public field if available. RawData is public.
                img.RawData = ImageFile.ISImgToPngBytes(rgbaImg);
                img._CacheISImg = null; // Invalidate cache so it reloads from new RawData
            }
            catch (Exception ex)
            {
                Logs.Error($"Failed to encrypt image pixels: {ex}");
            }
        }

        // Encrypt Metadata
        // We modify the UserInput so that when metadata is generated later, it contains encrypted values.
        try
        {
            // Encrypt parameters
            var keys = e.UserInput.InternalSet.ValuesInput.Keys.ToList();
            foreach (var key in keys)
            {
                // Don't encrypt the password itself if it's there (it shouldn't be in metadata usually but just in case)
                // Also skip non-string values or complex objects?
                // Python version converts value to string and encrypts.
                // We should be careful not to break Swarm's internal logic if it relies on these values later (unlikely for PostGenerateEvent).

                if (e.UserInput.InternalSet.ValuesInput.TryGetValue(key, out object val))
                {
                    // Python: v = str(m[k]); ev = ...; t[k] = f'OPPAI:{ev}'
                    // We only encrypt if we can turn it into a string safely.
                    // And we should probably only encrypt keys that end up in metadata.
                    // T2IParamTypes.TryGetType checks if HideFromMetadata.

                    if (T2IParamTypes.TryGetType(key, out T2IParamType type, e.UserInput))
                    {
                        if (type.HideFromMetadata) continue;
                    }

                    // Convert to string same way metadata generator does
                    string valStr = $"{val}";
                    string encryptedVal = EncryptString(valStr, password);
                    e.UserInput.InternalSet.ValuesInput[key] = $"OPPAI:{encryptedVal}";
                }
            }

            // Also encrypt ExtraMeta
            var extraKeys = e.UserInput.ExtraMeta.Keys.ToList();
            foreach (var key in extraKeys)
            {
                if (e.UserInput.ExtraMeta.TryGetValue(key, out object val))
                {
                    string valStr = $"{val}";
                    string encryptedVal = EncryptString(valStr, password);
                    e.UserInput.ExtraMeta[key] = $"OPPAI:{encryptedVal}";
                }
            }

            // Add Encryption Markers
            e.UserInput.ExtraMeta["Encrypt"] = "pixel_shuffle_3";
            string pwdSha = GetSHA256(password);
            string verifySha = GetSHA256(pwdSha + "Encrypt");
            e.UserInput.ExtraMeta["EncryptPwdSha"] = verifySha;
        }
        catch (Exception ex)
        {
            Logs.Error($"Failed to encrypt metadata: {ex}");
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
