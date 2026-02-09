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

using ISImage = SixLabors.ImageSharp.Image;

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
            Group: GroupEncryption,
            HideFromMetadata: true // Do not store the password in the image metadata!
        ));

        // Register the JS viewer
        ScriptFiles.Add("Assets/decrypt_viewer.js");

        // Hook into the PostBatchEvent using Lambda to avoid type visibility issues
        T2IEngine.PostBatchEvent += (e) =>
        {
            // Check if encryption password is set in the user input
            if (!e.UserInput.TryGet(EncryptionPassword, out string password) || string.IsNullOrWhiteSpace(password))
            {
                return;
            }

            // Encrypt Pixels
            if (e.Images != null)
            {
                foreach (var imgOut in e.Images)
                {
                    // Access the SwarmUI Image object
                    // Note: Img property casts File to Image.
                    if (imgOut.Img is not SwarmUI.Utils.Image img) continue;

                    try
                    {
                        // Get the underlying ImageSharp image (cached)
                        ISImage isImg = img.ToIS;

                        // We need to modify pixels in-place.
                        // Assuming standard usage is Rgba32.
                        if (isImg is Image<Rgba32> rgbaImg)
                        {
                            EncryptImage(rgbaImg, password);
                        }
                        else
                        {
                            // If it's not Rgba32, we clone to Rgba32, encrypt, and unfortunately we can't easily swap it back
                            // without accessing private members or re-encoding.
                            // However, SwarmUI primarily uses Rgba32 for generation.
                            Logs.Warning($"SdImageEncryption: Image is not Rgba32 ({isImg.GetType().Name}), skipping pixel encryption.");
                        }
                    }
                    catch (Exception ex)
                    {
                        Logs.Error($"Failed to encrypt image pixels: {ex}");
                    }
                }
            }

            // Encrypt Metadata
            try
            {
                EncryptMetadata(e.UserInput, password);
            }
            catch (Exception ex)
            {
                Logs.Error($"Failed to encrypt metadata: {ex}");
            }
        };
    }

    private void EncryptMetadata(T2IParamInput userInput, string password)
    {
        // Encrypt parameters
        var keys = userInput.InternalSet.ValuesInput.Keys.ToList();
        foreach (var key in keys)
        {
            if (userInput.InternalSet.ValuesInput.TryGetValue(key, out object val))
            {
                if (T2IParamTypes.TryGetType(key, out T2IParamType type, userInput))
                {
                    if (type.HideFromMetadata) continue;
                }

                string valStr = $"{val}";
                string encryptedVal = EncryptString(valStr, password);
                userInput.InternalSet.ValuesInput[key] = $"OPPAI:{encryptedVal}";
            }
        }

        // Also encrypt ExtraMeta
        var extraKeys = userInput.ExtraMeta.Keys.ToList();
        foreach (var key in extraKeys)
        {
            if (userInput.ExtraMeta.TryGetValue(key, out object val))
            {
                string valStr = $"{val}";
                string encryptedVal = EncryptString(valStr, password);
                userInput.ExtraMeta[key] = $"OPPAI:{encryptedVal}";
            }
        }

        // Add Encryption Markers
        userInput.ExtraMeta["Encrypt"] = "pixel_shuffle_3";
        string pwdSha = GetSHA256(password);
        string verifySha = GetSHA256(pwdSha + "Encrypt");
        userInput.ExtraMeta["EncryptPwdSha"] = verifySha;
    }

    // --- Helper Methods ---

    private string GetRange(string input, int offset, int range_len = 8)
    {
        offset = offset % input.Length;
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
            string rangeHex = GetRange(sha_key, i, 8);
            long val = long.Parse(rangeHex, System.Globalization.NumberStyles.HexNumber);
            int to_index = (int)(val % (length - i));

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

        int[] x_perm = ShuffleArray(w, pw);
        int[] y_perm = ShuffleArray(h, GetSHA256(pw));

        // Create a new image for the result
        var newImage = new Image<Rgba32>(w, h);

        for (int y = 0; y < h; y++)
        {
            for (int x = 0; x < w; x++)
            {
                newImage[x, y] = image[x_perm[x], y_perm[y]];
            }
        }

        // Copy back to original image (In-Place Modification)
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
        // Safe Byte-XOR implementation
        byte[] inputBytes = Encoding.UTF8.GetBytes(input);
        byte[] pwdBytes = Encoding.UTF8.GetBytes(password);
        byte[] result = new byte[inputBytes.Length];

        for (int i = 0; i < inputBytes.Length; i++)
        {
            result[i] = (byte)(inputBytes[i] ^ pwdBytes[i % pwdBytes.Length]);
        }

        return Convert.ToBase64String(result);
    }
}
