using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Reflection;
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

        // Hook into the PostGenerateEvent (Lambda Syntax)
        // Using PostGenerateEvent instead of PostBatchEvent because PostBatchEvent fires AFTER the image is saved to disk,
        // making encryption impossible for the saved file. PostGenerateEvent fires right before saving.
        T2IEngine.PostGenerateEvent += (e) =>
        {
            // Check if encryption password is set in the user input
            if (!e.UserInput.TryGet(EncryptionPassword, out string password) || string.IsNullOrWhiteSpace(password))
            {
                return;
            }

            // Encrypt Pixels
            // e.File is MediaFile. Cast to SwarmUI.Utils.Image to access pixel data.
            if (e.File is SwarmUI.Utils.Image img)
            {
                try
                {
                    // Get the underlying ImageSharp image (cached)
                    ISImage isImg = img.ToIS;

                    // We need to handle generic Image<TPixel>
                    EncryptImage(isImg, password);
                }
                catch (Exception ex)
                {
                    Logs.Error($"Failed to encrypt image pixels: {ex}");
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

    private void EncryptImage(ISImage img, string pw)
    {
        // Use reflection to call the generic method for the specific pixel type
        try
        {
            var method = this.GetType().GetMethod("EncryptImageGeneric", BindingFlags.NonPublic | BindingFlags.Instance);
            if (method == null)
            {
                Logs.Error("SdImageEncryption: EncryptImageGeneric method not found via reflection.");
                return;
            }

            var type = img.GetType();
            // Assuming standard ImageSharp Image<TPixel>
            var genericArgs = type.GetGenericArguments();
            if (genericArgs.Length == 0)
            {
                Logs.Warning($"SdImageEncryption: Image type {type.Name} is not generic, cannot encrypt pixels.");
                return;
            }

            var genericMethod = method.MakeGenericMethod(genericArgs[0]);
            genericMethod.Invoke(this, new object[] { img, pw });
        }
        catch (Exception ex)
        {
            Logs.Error($"SdImageEncryption: Reflection failed for pixel encryption: {ex}");
        }
    }

    private void EncryptImageGeneric<TPixel>(Image<TPixel> image, string pw) where TPixel : unmanaged, IPixel<TPixel>
    {
        int w = image.Width;
        int h = image.Height;

        int[] x_perm = ShuffleArray(w, pw);
        int[] y_perm = ShuffleArray(h, GetSHA256(pw));

        // Create a new image for the result
        // We cannot use 'new Image<TPixel>(w, h)' easily without knowing TPixel at compile time (Wait, we do know TPixel here)
        // But we need to copy back.
        // Actually, we can just create a buffer array or clone the image?
        // Cloning is easiest.
        using var newImage = image.Clone();

        // Perform shuffle: image[x, y] = newImage[x_perm[x], y_perm[y]]
        // Note: We want to overwrite 'image' (in-place) with the shuffled pixels.

        for (int y = 0; y < h; y++)
        {
            for (int x = 0; x < w; x++)
            {
                image[x, y] = newImage[x_perm[x], y_perm[y]];
            }
        }
        // Done. 'image' is now encrypted. 'newImage' (clone) is disposed.
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
