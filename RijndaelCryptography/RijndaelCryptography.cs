using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace PDFco.Security.Cryptography
{
    public class RijndaelCryptography
    {
        private readonly RijndaelManaged _rijndaelManaged;

        #region Propertyy

        public int FeedbackSize
        {
            get => _rijndaelManaged.FeedbackSize;
            set => _rijndaelManaged.FeedbackSize = value;
        }

        public int KeySize
        {
            get => _rijndaelManaged.KeySize;
            set => _rijndaelManaged.KeySize = value;
        }

        public byte[] Key
        {
            get => _rijndaelManaged.Key;
            set => _rijndaelManaged.Key = value;
        }

        public byte[] IV
        {
            get => _rijndaelManaged.IV;
            set => _rijndaelManaged.IV = value;
        }

        public int BlockSize
        {
            get => _rijndaelManaged.BlockSize;
            set => _rijndaelManaged.BlockSize = value;
        }

        public PaddingMode Padding
        {
            get => _rijndaelManaged.Padding;
            set => _rijndaelManaged.Padding = value;
        }

        public CipherMode Mode
        {
            get => _rijndaelManaged.Mode;
            set => _rijndaelManaged.Mode = value;
        }

        #endregion

        public RijndaelCryptography()
        {
            _rijndaelManaged = new RijndaelManaged();
        }

        public RijndaelCryptography(RijndaelManaged rijndaelManaged)
        {
            _rijndaelManaged = rijndaelManaged;
        }

        public void SetKey(string key, string iv = null)
        {
            Key = Convert.FromBase64String(key);

            if (iv != null)
            {
                IV = Convert.FromBase64String(iv);
            }
        }

        public bool Encrypt(string input, out string encryptedString)
        {
            try
            {

                var encrypt = _rijndaelManaged.CreateEncryptor(Key, IV);
                byte[] xBuff = null;
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, encrypt, CryptoStreamMode.Write))
                    {
                        byte[] xXml = Encoding.UTF8.GetBytes(input);
                        cs.Write(xXml, 0, xXml.Length);
                    }

                    xBuff = ms.ToArray();
                }

                encryptedString = Convert.ToBase64String(xBuff);
                return true;
            }
            catch (Exception)
            {
                encryptedString = string.Empty;
                return false;
            }
        }

        public bool GenerateKey(out string key, out string vector)
        {
            try
            {
                _rijndaelManaged.GenerateIV();
                var ivStr = Convert.ToBase64String(IV);
                _rijndaelManaged.GenerateKey();
                var keyStr = Convert.ToBase64String(Key);
                key = keyStr;
                vector = ivStr;
                return true;
            }
            catch (Exception)
            {
                key = string.Empty;
                vector = string.Empty;
                return false;
            }
        }

        public bool Decrypt(string input, out string decodedString)
        {
            try
            {
                var decrypt = _rijndaelManaged.CreateDecryptor();
                byte[] xBuff = null;
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, decrypt, CryptoStreamMode.Write))
                    {
                        byte[] xXml = Convert.FromBase64String(input);
                        cs.Write(xXml, 0, xXml.Length);
                    }

                    xBuff = ms.ToArray();
                }

                decodedString = Encoding.UTF8.GetString(xBuff);
                return true;
            }
            catch (Exception)
            {
                decodedString = string.Empty;
                return false;
            }
        }


    }
}
