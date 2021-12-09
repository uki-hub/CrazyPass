using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Serialization;

namespace CrazyPass
{
    class Program
    {
        public static void Main()
        {
            int? mode = null;

            do
            {
                Console.Clear();
                Console.WriteLine("CrazyPass v0.1Beta\n");

                Console.WriteLine("1. create\n2. unlock:");
                Console.Write("option: ");
                String userInput = Console.ReadLine();
                try
                {
                    mode = int.Parse(userInput);
                    if (mode < 1 || mode > 2) mode = null;
                }
                catch (Exception) { }
            } while (!mode.HasValue);

            try
            {
                if (mode == 1)
                {
                    int? peopleCount = null;
                    Console.Clear();
                    do
                    {
                        Console.Clear();
                        Console.Write("for how many people: ");
                        String userInput = Console.ReadLine();
                        try
                        {
                            peopleCount = int.Parse(userInput);
                            if (mode <= 0) mode = null;
                        }
                        catch (Exception) { }
                    } while (!peopleCount.HasValue);
                    create(peopleCount.Value);
                }
                else
                {
                    unlock();
                }
            }
            catch (Exception)
            {
                Console.Clear();
                Console.WriteLine("RUNTIME ERROR!!!");
                Console.ReadKey();
            }

        }

        static void create(int peopleCount)
        {
            AesManaged _aesManaged = new AesManaged();
            _aesManaged.GenerateIV();
            string path = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) + @"\crazzyPass.txt";
            List<PassOwner> passOwners = new List<PassOwner>();
            byte[] IV = _aesManaged.IV;

            for (int i = 0; i < peopleCount; i++)
            {
                Console.Clear();
                Console.Write("Owner #" + (i + 1).ToString());

                Console.Write("\nname: ");
                string name = Console.ReadLine();

                Console.Write("\npassword: ");
                string password = GetSecureString();

                Console.Write("\nprivate key: ");
                string privateKey = GetSecureString();

                using (AesManaged myAes = new AesManaged())
                {
                    //OPTIONS
                    myAes.KeySize = 256;
                    myAes.Mode = CipherMode.ECB;
                    myAes.Padding = PaddingMode.PKCS7;
                    myAes.Key = Encoding.ASCII.GetBytes(privateKey);

                    byte[] encrypted = EncryptStringToBytes_Aes(password, myAes.Key, IV);
                    passOwners.Add(new PassOwner
                    {
                        name = name,
                        publicKey = Convert.ToBase64String(encrypted),
                    });

                }
            }

            Console.Clear();
            using (StreamWriter sw = new StreamWriter(path))
            {
                sw.WriteLine(Stringfy(new CrazyPass
                {
                    IV = Convert.ToBase64String(IV),
                    crazyPasses = passOwners,
                }));
            }
            Console.WriteLine("password has been generated");
            Process.Start("explorer.exe", path);
            Console.ReadKey();
        }

        static void unlock()
        {
            var crazyPass = ParseFromFile<CrazyPass>(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) + @"\crazzyPass.txt");
            List<string> passwords = new List<string>();

            foreach (var pass in crazyPass.crazyPasses)
            {
                Console.Clear();
                Console.WriteLine("private key for owner (" + pass.name + ")");
                Console.Write("key: ");
                string privateKey = GetSecureString();

                passwords.Add(DecryptStringFromBytes_Aes(
                Convert.FromBase64String(pass.publicKey), Encoding.ASCII.GetBytes(privateKey), Convert.FromBase64String(crazyPass.IV)));
            }

            Shuffle(passwords, String.Join("", passwords.ToArray()).Length);

            var joinedPassowrd = String.Join("", passwords.ToArray());
            var listedJoinedPassword = joinedPassowrd.ToCharArray();
            Shuffle(listedJoinedPassword, (int)listedJoinedPassword[0] + int.Parse(Math.Round(Double.Parse(listedJoinedPassword.Length.ToString()) / 2).ToString()) + (int)listedJoinedPassword.Last());

            Console.Clear();
            Console.WriteLine(sha256(new String(listedJoinedPassword)));
            Console.ReadKey();
        }

        public static void Shuffle<T>(IList<T> list, int seed)
        {
            var rng = new Random(seed);
            int n = list.Count;

            while (n > 1)
            {
                n--;
                int k = rng.Next(n + 1);
                T value = list[k];
                list[k] = list[n];
                list[n] = value;
            }
        }

        public static String GetSecureString()
        {
            var pwd = new SecureString();
            while (true)
            {
                ConsoleKeyInfo i = Console.ReadKey(true);
                if (i.Key == ConsoleKey.Enter)
                {
                    break;
                }
                else if (i.Key == ConsoleKey.Backspace)
                {
                    if (pwd.Length > 0)
                    {
                        pwd.RemoveAt(pwd.Length - 1);
                        Console.Write("\b \b");
                    }
                }
                else if (i.KeyChar != '\u0000')
                {
                    pwd.AppendChar(i.KeyChar);
                    Console.Write("*");
                }
            }

            IntPtr valuePtr = IntPtr.Zero;
            try
            {
                valuePtr = Marshal.SecureStringToGlobalAllocUnicode(pwd);
                return Marshal.PtrToStringUni(valuePtr);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
            }
        }

        public static string Stringfy<T>(T objectValue)
        {
            string result = "";
            XmlSerializer xsSubmit = new XmlSerializer(typeof(T));

            try
            {
                using (var sww = new StringWriter())
                using (XmlWriter writer = XmlWriter.Create(sww))
                {
                    xsSubmit.Serialize(writer, objectValue);
                    result = sww.ToString();
                }

            }
            catch
            {
                throw new XmlException("Fail to stringfy the " + typeof(T).Name + " object");
            }

            return result;
        }

        public static T Parse<T>(string xmlString)
        {
            T result;

            XmlSerializer serializer = new XmlSerializer(typeof(T));

            try
            {
                using (StringReader reader = new StringReader(xmlString))
                    result = (T)(serializer.Deserialize(reader));
            }
            catch
            {
                throw new XmlException("Fail to parse XML string\ncontent: " + xmlString);
            }

            return result;
        }

        public static T ParseFromFile<T>(string fileLocation)
        {
            T result;

            if (!File.Exists(fileLocation)) throw new XmlException("File is not found\nfile path: " + fileLocation);

            using (StreamReader sr = new StreamReader(fileLocation))
                result = Parse<T>(sr.ReadToEnd());

            return result;
        }

        static string sha256(string randomString)
        {
            var crypt = new SHA256Managed();
            string hash = String.Empty;
            byte[] crypto = crypt.ComputeHash(Encoding.ASCII.GetBytes(randomString));
            foreach (byte theByte in crypto)
            {
                hash += theByte.ToString("x2");
            }
            return hash;
        }

        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0) throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0) throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0) throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an AesManaged object
            // with the specified key and IV.
            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0) throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0) throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0) throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an AesManaged object
            // with the specified key and IV.
            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

    }

    public class CrazyPass
    {
        public String IV
        {
            get;
            set;
        }
        public List<PassOwner> crazyPasses
        {
            get;
            set;
        }
    }

    public class PassOwner
    {
        public String name
        {
            get;
            set;
        }
        public String publicKey
        {
            get;
            set;
        }
    }

}