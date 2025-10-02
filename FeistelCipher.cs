using System;
using System.Collections.Generic;
using System.IO;

class FeistelCipher
{
    private static List<byte> roundKeys;
    private static int blockSize;

    
    static byte GF256Multiply(byte a, byte b) // 2^8 gf multiplying
    {
        int result = 0;
        int temp_b = b;
        int temp_a = a;

        while (temp_a != 0)// whole while loop is just the shift and xor method of bit multiplying
        {
            if ((temp_a & 1) != 0)
                result ^= temp_b;

            bool carry = (temp_b & 0x80) != 0;
            temp_b <<= 1;
            if (carry)
                temp_b ^= (0x11B & 0xFF); // 0x11B =irreducible

            temp_a >>= 1;
        }
        return (byte)result;
    }

    
    static byte GF16Multiply(byte a, byte b) // the 2^4 one, can probably be combined with the other eventually
    {
        a &= 0x0F;  //makes values 4 bit by only keeping the last 4 signifigant bits
        b &= 0x0F;

        int result = 0;
        int temp_b = b;
        int temp_a = a;

        while (temp_a != 0) // whole while loop is just the shift and xor method of bit multiplying
        {
            if ((temp_a & 1) != 0)
                result ^= temp_b;

            bool carry = (temp_b & 0x08) != 0;
            temp_b <<= 1;
            if (carry)
                temp_b ^= (0x13 & 0x0F);//0x13 = irreducible

            temp_a >>= 1;
        }
        return (byte)(result & 0x0F);
    }

    static int F(int halfBlock, int key) //just picks with galois field multiplication to use
    {
        if (blockSize == 16)
        {
            return GF256Multiply((byte)halfBlock, (byte)key);
        }
        else
        {
            return GF16Multiply((byte)halfBlock, (byte)key);
        }
    }

    static byte[] Encrypt(byte[] inputBytes)
    {
        List<byte> outputBytes = new List<byte>();
        int blockByteSize = blockSize / 8;
        int halfBlockMask = (blockSize == 16) ? 0xFF : 0x0F; //used later for removing things larger than 16 or 8 bits

        for (int i = 0; i < inputBytes.Length; i += blockByteSize)
        {
            if (i + blockByteSize > inputBytes.Length) break;

            int left, right;
            if (blockSize == 16)
            {
                left = inputBytes[i];
                right = inputBytes[i + 1];
            }
            else
            {
                // splitting the single byte into nibbles when using the 8 bit block size
                left = (inputBytes[i] >> 4) & 0x0F;
                right = inputBytes[i] & 0x0F;
            }

            for (int round = 0; round < roundKeys.Count; round++) // based on the number of round keys, itll do the swappage and xoring with the F function
            {
                int oldRight = right;
                right = left ^ F(right, roundKeys[round]) & halfBlockMask;
                left = oldRight;
            }

            if (blockSize == 16)
            {
                outputBytes.Add((byte)right);
                outputBytes.Add((byte)left);
            }
            else
            {
                //combine 4-bit halves back into a single byte, also swaps like normal
                outputBytes.Add((byte)((right << 4) | left));
            }
        }
        return outputBytes.ToArray();
    }

    static byte[] Decrypt(byte[] inputBytes)
    {
        List<byte> outputBytes = new List<byte>();
        List<byte> reversedKeys = new List<byte>(roundKeys);
        reversedKeys.Reverse();
        int blockByteSize = blockSize / 8;
        int halfBlockMask = (blockSize == 16) ? 0xFF : 0x0F;

        for (int i = 0; i < inputBytes.Length; i += blockByteSize)
        {
            if (i + blockByteSize > inputBytes.Length) break;

            int left, right;
            if (blockSize == 16)
            {
                left = inputBytes[i];
                right = inputBytes[i + 1];
            }
            else
            {
                // splits byte into nibbles if needed again
                left = (inputBytes[i] >> 4) & 0x0F;
                right = inputBytes[i] & 0x0F;
            }

            for (int round = 0; round < reversedKeys.Count; round++) // reversed keys bc decrypting, but same vibe
            {
                int oldRight = right;
                right = left ^ F(right, reversedKeys[round]) & halfBlockMask;
                left = oldRight;
            }

            if (blockSize == 16)
            {
                outputBytes.Add((byte)right);
                outputBytes.Add((byte)left);
            }
            else
            {
                outputBytes.Add((byte)((right << 4) | left));
            }
        }
        return outputBytes.ToArray();
    }

    static void Main(string[] args) // just handles menu functionality
    {
        while (true)
        {
            Console.WriteLine("Galois Feistel - Ethan Dingle");
            Console.WriteLine("1. Encrypt");
            Console.WriteLine("2. Decrypt");
            Console.WriteLine("3. Quit");
            Console.Write("Choose an option: ");
            string choice = Console.ReadLine();
            if (choice!="1" && choice != "2") return; //to quit
            string inputFile = "";
            string outputFile = "";

            if (choice == "1")
            {
                Console.Write("Enter plaintext file path: ");
                inputFile = Console.ReadLine();
                Console.Write("Enter output file path:\n(dont add a file type, just name (ex. /path/to/file/nameofoutput)\n"); 
                outputFile = Console.ReadLine();
            }
            else if (choice == "2")
            {
                Console.Write("Enter encrypted file path:\n(dont add a file type, just name (ex. /path/to/file/nameofoutput)\n");
                inputFile = Console.ReadLine();
                Console.Write("Enter output file path: "); 
                outputFile = Console.ReadLine();
            }

            Console.Write("Enter key string: ");
            string keyString = Console.ReadLine();

            Console.Write("Enter block size (8 or 16): ");
            blockSize = int.Parse(Console.ReadLine());

            if (blockSize != 8 && blockSize != 16)
            {
                Console.WriteLine("Invalid block size. Must be 8 or 16.");
                return;
            }

            // converts the inputted string into bytes
            roundKeys = new List<byte>();
            foreach (char c in keyString)
            {
                roundKeys.Add((byte)c);
            }

            try
            {
                byte[] fileBytes = File.ReadAllBytes(inputFile);
                byte[] processedBytes;

                if (choice == "1")
                {
                    processedBytes = Encrypt(fileBytes);
                    Console.WriteLine("File encrypted successfully.");
                }
                else if (choice == "2")
                {
                    processedBytes = Decrypt(fileBytes);
                    Console.WriteLine("File decrypted successfully.");
                }
                else
                {
                    Console.WriteLine("Invalid choice.");
                    return;
                }

                File.WriteAllBytes(outputFile, processedBytes);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
    }
}