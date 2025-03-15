using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Data.SQLite;
using System.Runtime.InteropServices;
using System.Data;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Digests;

class Program
{
    private static object logMutex = new object();
    private static StreamWriter logFile;
    private static int counter = 0;
    private static bool stopFlag = false;

    static void Main(string[] args)
    {
        try
        {
            int maxThreads = Environment.ProcessorCount;
            Console.WriteLine($"Detected {maxThreads} logical processors.");

            int userThreads;
            while (true)
            {
                Console.Write("Enter the desired number of processors to use (minimum 2): ");
                if (int.TryParse(Console.ReadLine(), out userThreads))
                {
                    if (userThreads < 2)
                    {
                        Console.WriteLine($"Entered {userThreads} (less than 2), using 2 processors.");
                        userThreads = 2;
                        break;
                    }
                    else if (userThreads > maxThreads)
                    {
                        Console.WriteLine($"Entered {userThreads} logical processors, but only {maxThreads} are available. Using {maxThreads}.");
                        userThreads = maxThreads;
                        break;
                    }
                    else
                    {
                        break;
                    }
                }
                else
                {
                    Console.WriteLine("Please enter a valid number.");
                }
            }

            string dbPath = "database.db";
            while (!File.Exists(dbPath))
            {
                Console.Write("Database file database.db not found.\nEnter the path to the database (or press Enter to exit): ");
                string input = Console.ReadLine();
                
                if (string.IsNullOrEmpty(input))
                {
                    Console.WriteLine("Program terminated by user.");
                    return;
                }

                dbPath = input;
                
                if (!File.Exists(dbPath))
                {
                    Console.WriteLine($"File not found: {dbPath}");
                    continue;
                }

                try
                {
                    // Проверяем, можем ли мы открыть базу данных
                    using (var conn = new SQLiteConnection($"Data Source={dbPath};Version=3;"))
                    {
                        conn.Open();
                        using (var cmd = new SQLiteCommand("SELECT name FROM sqlite_master WHERE type='table' AND name='addresses'", conn))
                        {
                            if (cmd.ExecuteScalar() == null)
                            {
                                Console.WriteLine("Error: The database file does not contain the required 'addresses' table.");
                                dbPath = "database.db"; // Сбрасываем путь и просим ввести снова
                                continue;
                            }
                        }
                    }
                }
                catch (SQLiteException ex)
                {
                    Console.WriteLine($"Error opening database: {ex.Message}");
                    dbPath = "database.db"; // Сбрасываем путь и просим ввести снова
                    continue;
                }
            }

            string logPath = "log.txt";
            try
            {
                if (!File.Exists(logPath))
                {
                    Console.WriteLine("Log file log.txt not found, creating automatically.");
                    File.Create(logPath).Close();
                }
                else
                {
                    Console.WriteLine("Log file log.txt already exists, using it.");
                }

                logFile = new StreamWriter(logPath, true);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error creating/opening log file: {ex.Message}");
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey();
                return;
            }

            Console.WriteLine("Press Enter in the console to gracefully exit the program.");
            Console.WriteLine("Program started successfully!");

            DateTime startTime = DateTime.Now;
            Thread reportThread = new Thread(() =>
            {
                while (!stopFlag)
                {
                    double mins = (DateTime.Now - startTime).TotalMinutes;
                    int total = counter;
                    double speed = total / Math.Max(mins, 1e-9);
                    Console.Write($"\rSpeed: {speed:F2} addresses/minute");
                    Thread.Sleep(1000);
                }
            });

            Thread inputThread = new Thread(() =>
            {
                Console.ReadLine();
                stopFlag = true;
            });

            List<Thread> workers = new List<Thread>();
            for (int i = 0; i < userThreads; i++)
            {
                workers.Add(new Thread(() =>
                {
                    using (var connection = new SQLiteConnection($"Data Source={dbPath};Version=3;"))
                    {
                        connection.Open();
                        var command = new SQLiteCommand("SELECT 1 FROM addresses WHERE address = ?", connection);
                        command.Parameters.Add(new SQLiteParameter("@address", DbType.Binary));

                        while (!stopFlag)
                        {
                            try
                            {
                                var (mnemonic, seed) = GenerateMnemonicAndSeed();
                                var (addrHex, binAddr, privKeyHex) = GetWalletInfo(seed);

                                lock (logMutex)
                                {
                                    counter++;
                                }

                                command.Parameters["@address"].Value = binAddr;
                                var result = command.ExecuteNonQuery();

                                if (result > 0)
                                {
                                    lock (logMutex)
                                    {
                                        logFile.WriteLine($"Seed: {mnemonic}");
                                        logFile.WriteLine($"Address: {addrHex}");
                                        logFile.WriteLine($"Private: {privKeyHex}");
                                        logFile.Flush();
                                    }
                                }
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine($"Error: {e.Message}");
                            }
                        }
                    }
                }));
            }

            reportThread.Start();
            inputThread.Start();

            foreach (var worker in workers)
            {
                worker.Start();
            }

            foreach (var worker in workers)
            {
                worker.Join();
            }

            reportThread.Join();
            inputThread.Join();

            Console.WriteLine($"\nProgram completed. Log file {logPath} created (if it did not exist).");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Unexpected error occurred: {ex.Message}");
            Console.WriteLine(ex.StackTrace);
            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
        }
        finally
        {
            if (logFile != null)
            {
                logFile.Close();
            }
        }
    }

    static (string, byte[]) GenerateMnemonicAndSeed()
    {
        byte[] entropy = new byte[16]; // 128 bits of entropy for 12 words
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(entropy);
        }

        // Преобразуем байты в hex строку для временной реализации
        string entropyHex = BitConverter.ToString(entropy).Replace("-", "").ToLower();
        string mnemonic = entropyHex; // Временная реализация

        // Создаем seed из мнемоники (временная реализация)
        byte[] seed = new byte[64];
        using (var hmac = new HMACSHA512(Encoding.UTF8.GetBytes("mnemonic")))
        {
            seed = hmac.ComputeHash(Encoding.UTF8.GetBytes(mnemonic));
        }

        return (mnemonic, seed);
    }

    static (string, byte[], string) GetWalletInfo(byte[] seed)
    {
        // Создаем временный master key
        var master = new ext_key
        {
            privKey = new byte[33], // 32 bytes + 1 prefix byte
            pubKey = new byte[33],
            chainCode = new byte[32],
            depth = 0,
            childNum = 0,
            parentFingerprint = 0
        };

        // Копируем seed в privKey (временная реализация)
        Array.Copy(seed, 0, master.privKey, 1, Math.Min(32, seed.Length));

        using (var ecdsa = ECDsa.Create(ECCurve.CreateFromFriendlyName("secp256k1")))
        {
            byte[] privKeyForImport = new byte[32];
            Array.Copy(master.privKey, 1, privKeyForImport, 0, 32); // Пропускаем первый байт
            ecdsa.ImportParameters(new ECParameters
            {
                Curve = ECCurve.CreateFromFriendlyName("secp256k1"),
                D = privKeyForImport
            });

            byte[] publicKey = ecdsa.ExportParameters(false).Q.X.Concat(ecdsa.ExportParameters(false).Q.Y).ToArray();
            byte[] hash = Keccak256(publicKey);

            byte[] binAddr = hash.Skip(12).Take(20).ToArray();
            string addrHex = ToChecksumAddress(binAddr);
            string privKeyHex = "0x" + BitConverter.ToString(privKeyForImport).Replace("-", "").ToLower();

            return (addrHex, binAddr, privKeyHex);
        }
    }

    static string ToChecksumAddress(byte[] addr)
    {
        string hexAddr = BitConverter.ToString(addr).Replace("-", "").ToLower();
        string lowerHex = hexAddr;
        byte[] hash = Keccak256(Encoding.UTF8.GetBytes(lowerHex));
        string hashHex = BitConverter.ToString(hash).Replace("-", "").ToLower();

        StringBuilder outStr = new StringBuilder("0x");
        for (int i = 0; i < 40; i++)
        {
            if (hashHex[i] >= '8')
            {
                outStr.Append(hexAddr[i].ToString().ToUpper());
            }
            else
            {
                outStr.Append(hexAddr[i].ToString().ToLower());
            }
        }

        return outStr.ToString();
    }

    static byte[] Keccak256(byte[] input)
    {
        var keccak = new KeccakDigest(256);
        byte[] hash = new byte[32];
        keccak.BlockUpdate(input, 0, input.Length);
        keccak.DoFinal(hash, 0);
        return hash;
    }
}

public struct ext_key
{
    public byte[] privKey;
    public byte[] pubKey;
    public byte[] chainCode;
    public uint depth;
    public uint childNum;
    public uint parentFingerprint;
}