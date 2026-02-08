using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using SwarmUI.Core;
using SwarmUI.Utils;
using SwarmUI.Text2Image;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp.Processing;

namespace SwarmUI.Extensions.SdImageEncryption
{
    public class SdImageEncryption : Extension
    {
        public static T2IParamType EncryptionPasswordParam;

        public override void OnInit()
        {
            // Register parameter
            EncryptionPasswordParam = T2IParamTypes.Register<string>(new T2IParamType(
                "Encryption Password",
                "Password to encrypt the saved image (Pixel Shuffle). Leave empty to disable.",
                "", // Default value
                Group: "Image Encryption",
                FeatureFlag: "encryption_password"
            ));

            // Register script
            ScriptFiles.Add("Assets/decrypt_viewer.js");

            // Add hook to intercept image generation and apply encryption
            WorkflowGenerator.AddStep(g =>
            {
                if (g.UserInput.TryGet(EncryptionPasswordParam, out string password) && !string.IsNullOrWhiteSpace(password))
                {
                    // Add a post-processing step to encrypt the image
                    g.PostProcessSteps.Add(image => EncryptImage(image, password));

                    // Add a metadata step to encrypt tags
                    // Assuming metadata is accessible via the image object or a separate hook.
                    // In SwarmUI, the Image object often carries metadata or there is a metadata dictionary passed around.
                    // If PostProcessStep only gives Image, we must modify the image's metadata directly.
                    // ImageSharp images have Metadata.
                }
            });
        }

        public static string GetSHA256(string input)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }

        public static string GetRange(string input, int offset, int range_len = 4)
        {
            offset = offset % input.Length;
            return (input + input).Substring(offset, range_len);
        }

        public static void ShuffleArray(int[] arr, string key)
        {
            string sha_key = GetSHA256(key);
            int arr_len = arr.Length;
            for (int i = 0; i < arr_len; i++)
            {
                int s_idx = arr_len - i - 1;
                string range = GetRange(sha_key, i, 8);
                long val = Convert.ToInt64(range, 16);
                int to_index = (int)(val % (arr_len - i));

                int temp = arr[s_idx];
                arr[s_idx] = arr[to_index];
                arr[to_index] = temp;
            }
        }

        public static List<int> GetCodePoints(string s)
        {
            var list = new List<int>();
            for (int i = 0; i < s.Length; i++)
            {
                if (char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]))
                {
                    list.Add(char.ConvertToUtf32(s[i], s[i + 1]));
                    i++;
                }
                else
                {
                    list.Add((int)s[i]);
                }
            }
            return list;
        }

        public static void EncryptTags(Image image, string password)
        {
            // Metadata keys to encrypt
            string[] tag_list = { "parameters", "UserComment" };

            // ImageSharp metadata access depends on format. Assuming PNG for now as per Python code.
            var pngMetadata = image.Metadata.GetPngMetadata();

            // We need to iterate and modify.
            // ImageSharp PngMetadata stores text chunks in TextData list.

            foreach (var key in tag_list)
            {
                // Find the text data
                var textData = pngMetadata.TextData.FirstOrDefault(t => t.Keyword == key);
                if (textData.Keyword != null) // Struct, check if valid
                {
                    string v = textData.Value;

                    var vPoints = GetCodePoints(v);
                    var pPoints = GetCodePoints(password);

                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < vPoints.Count; i++)
                    {
                        int c = vPoints[i];
                        int p = pPoints[i % pPoints.Count];
                        int xored = c ^ p;
                        try
                        {
                             sb.Append(char.ConvertFromUtf32(xored));
                        }
                        catch
                        {
                            // Fallback if invalid char
                            sb.Append(char.ConvertFromUtf32(c));
                        }
                    }
                    string xoredString = sb.ToString();

                    byte[] bytes = Encoding.UTF8.GetBytes(xoredString);
                    string ev = Convert.ToBase64String(bytes);

                    // Update metadata
                    // Remove old and add new
                    // pngMetadata.TextData is a List<PngTextData> ? No, it's IList.
                    // But we can't easily modify the list in place while iterating?
                    // Let's just remove and add.

                    // Actually, we can just replace the value if we find the object?
                    // PngTextData is a struct.

                    // We need to remove the old entry and add a new one.
                    // But wait, the list might be read-only or copy.

                    // Let's try:
                    // pngMetadata.TextData.Remove(textData); // Remove struct?
                    // This relies on equality.

                    // Better to rebuild the list or find index.
                    for (int i = 0; i < pngMetadata.TextData.Count; i++)
                    {
                        if (pngMetadata.TextData[i].Keyword == key)
                        {
                            pngMetadata.TextData.RemoveAt(i);
                            pngMetadata.TextData.Add(new SixLabors.ImageSharp.Formats.Png.PngTextData(key, $"OPPAI:{ev}", textData.LanguageTag, textData.TranslatedKeyword));
                            break;
                        }
                    }
                }
            }

            // Also add Encrypt and EncryptPwdSha tags
            pngMetadata.TextData.Add(new SixLabors.ImageSharp.Formats.Png.PngTextData("Encrypt", "pixel_shuffle_3", null, null));
            pngMetadata.TextData.Add(new SixLabors.ImageSharp.Formats.Png.PngTextData("EncryptPwdSha", GetSHA256($"{GetSHA256(password)}Encrypt"), null, null));
        }

        public static void EncryptImage(Image image, string pw)
        {
            if (image is Image<Rgba32> rgbaImage)
            {
                EncryptImageInternal(rgbaImage, pw);
            }
            else
            {
                // Convert to Rgba32 if not already
                using (var clone = image.CloneAs<Rgba32>())
                {
                    EncryptImageInternal(clone, pw);
                    // Copy back? This is inefficient.
                    // Ideally we operate on the image in place.
                    // SwarmUI images are usually Rgba32.

                    // If we can't replace the image object reference (passed by value to method),
                    // we must modify the content.

                    image.Mutate(x => x.DrawImage(clone, 1f));
                }
            }

            EncryptTags(image, pw);
        }

        private static void EncryptImageInternal(Image<Rgba32> image, string pw)
        {
            int w = image.Width;
            int h = image.Height;
            int[] x = Enumerable.Range(0, w).ToArray();
            ShuffleArray(x, pw);

            int[] y = Enumerable.Range(0, h).ToArray();
            ShuffleArray(y, GetSHA256(pw));

            using (var temp = image.Clone())
            {
                // Shuffle rows
                for (int v = 0; v < h; v++)
                {
                    var sourceRow = temp.Frames.RootFrame.PixelBuffer.DangerousGetRowSpan(y[v]);
                    var destRow = image.Frames.RootFrame.PixelBuffer.DangerousGetRowSpan(v);
                    sourceRow.CopyTo(destRow);
                }
            }

            using (var temp = image.Clone())
            {
                // Shuffle columns
                image.ProcessPixelRows(temp, (accessorDest, accessorSrc) =>
                {
                    for (int r = 0; r < h; r++)
                    {
                        var destRow = accessorDest.GetRowSpan(r);
                        var srcRow = accessorSrc.GetRowSpan(r);

                        for (int c = 0; c < w; c++)
                        {
                            destRow[c] = srcRow[x[c]];
                        }
                    }
                });
            }
        }
    }
}
