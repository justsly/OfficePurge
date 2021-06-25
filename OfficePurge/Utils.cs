using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using Kavod.Vba.Compression;

namespace OfficePurge
{
    class Utils
    {
		public static int add_offset;
		public static Dictionary<string, string> ParseArgs(string[] args)
		{
			Dictionary<string, string> ret = new Dictionary<string, string>();
			if (args.Length > 0)
			{
				for (int i = 0; i < args.Length; i += 2)
				{
					if (args[i].Substring(1).ToLower() == "l")
					{
						ret.Add(args[i].Substring(1).ToLower(), "true");
					}
					else
					{
						ret.Add(args[i].Substring(1).ToLower(), args[i + 1]);
					}
				}
			}
			return ret;
		}
		public static void HelpMenu()
		{
			Console.WriteLine("\n  __  ____  ____  __  ___  ____  ____  _  _  ____   ___  ____ ");
			Console.WriteLine(" /  \\(  __)(  __)(  )/ __)(  __)(  _ \\/ )( \\(  _ \\ / __)(  __)");
			Console.WriteLine("(  O )) _)  ) _)  )(( (__  ) _)  ) __/) \\/ ( )   /( (_ \\ ) _) ");
			Console.WriteLine(" \\__/(__)  (__)  (__)\\___)(____)(__)  \\____/(__\\_) \\___/(____) v1.0");
			Console.WriteLine("\n\n Author: Andrew Oliveau\n\n");
			Console.WriteLine(" DESCRIPTION:");
			Console.WriteLine("\n\tOfficePurge is a C# tool that VBA purges malicious Office documents. ");
			Console.WriteLine("\n\tVBA purging removes P-code from module streams within Office documents. ");
			Console.WriteLine("\n\tDocuments that only contain source code and no compiled code are more");
			Console.WriteLine("\n\tlikely to evade AV detection and YARA rules.\n\n\t\n");
			Console.WriteLine(" USAGE:");
			Console.WriteLine("\n\t-d : Document type (word, excel, publisher)");
			Console.WriteLine("\n\t-f : Filename to VBA Purge");
			Console.WriteLine("\n\t-m : Module within document to VBA Purge");
			Console.WriteLine("\n\t-fuzz : Integer to Fuzz Office Version");
			Console.WriteLine("\n\t-r : Read Office Version");
			Console.WriteLine("\n\t-t : Target Office Version");
			Console.WriteLine("\n\t-l : List module streams in document");
			Console.WriteLine("\n\t-st : search for pattern in document (only usable with -rt)");
			Console.WriteLine("\n\t-rt : replace with pattern in document (only usable with -st)");
			Console.WriteLine("\n\t-h : Show help menu.\n\n");
			Console.WriteLine(" EXAMPLES:");
			Console.WriteLine("\n\t .\\OfficePurge.exe -d word -f .\\malicious.doc -m NewMacros");
			Console.WriteLine("\n\t .\\OfficePurge.exe -d excel -f .\\payroll.xls -m Module1");
			Console.WriteLine("\n\t .\\OfficePurge.exe -d publisher -f .\\donuts.pub -m ThisDocument");
			Console.WriteLine("\n\t .\\OfficePurge.exe -d word -f .\\malicious.doc -l\n\n");
		}
		public static List<ModuleInformation> ParseModulesFromDirStream(byte[] dirStream)
		{
			// 2.3.4.2 dir Stream: Version Independent Project Information
			// https://msdn.microsoft.com/en-us/library/dd906362(v=office.12).aspx
			// Dir stream is ALWAYS in little endian

			List<ModuleInformation> modules = new List<ModuleInformation>();

			int offset = 0;
			UInt16 tag;
			UInt32 wLength;
			ModuleInformation currentModule = new ModuleInformation { moduleName = "", textOffset = 0 };

			while (offset < dirStream.Length)
			{
				tag = GetWord(dirStream, offset);
				wLength = GetDoubleWord(dirStream, offset + 2);

				// taken from Pcodedmp
				if (tag == 9)
					wLength = 6;
				else if (tag == 3)
					wLength = 2;

				//Console.WriteLine("\n [+] DEBUG tag: " + tag);
				//Console.WriteLine("\n [+] DEBUG bytes of tag: " + BitConverter.GetBytes((UInt16)tag)[0]);
				//Console.WriteLine("\n [+] DEBUG wLength: " + wLength);

				switch (tag)
				{
					// MODULESTREAMNAME Record
					case 26:
						currentModule.moduleName = System.Text.Encoding.UTF8.GetString(dirStream, (int)offset + 6, (int)wLength);
						//Console.WriteLine("Case 26 offset: " + (int)offset + 6 + " | wLength: " + (int)wLength);
						//Console.WriteLine("Case 26 Name: " + currentModule.moduleName);
						break;

					// MODULEOFFSET Record
					case 49:
						currentModule.textOffset = GetDoubleWord(dirStream, offset + 6);
						//Console.WriteLine("Case 49 Offset: " + currentModule.textOffset);
						modules.Add(currentModule);
						currentModule = new ModuleInformation { moduleName = "", textOffset = 0 };
						break;
				}

				offset += 6;
				offset += (int)wLength;
			}

			return modules;
		}

		public static string HexDump(byte[] bytes, int bytesPerLine = 16)
		{
			if (bytes == null) return "<null>";
			int bytesLength = bytes.Length;

			char[] HexChars = "0123456789ABCDEF".ToCharArray();

			int firstHexColumn =
				8                   // 8 characters for the address
				+ 3;                  // 3 spaces

			int firstCharColumn = firstHexColumn
				+ bytesPerLine * 3       // - 2 digit for the hexadecimal value and 1 space
				+ (bytesPerLine - 1) / 8 // - 1 extra space every 8 characters from the 9th
				+ 2;                  // 2 spaces 

			int lineLength = firstCharColumn
				+ bytesPerLine           // - characters to show the ascii value
				+ Environment.NewLine.Length; // Carriage return and line feed (should normally be 2)

			char[] line = (new String(' ', lineLength - Environment.NewLine.Length) + Environment.NewLine).ToCharArray();
			int expectedLines = (bytesLength + bytesPerLine - 1) / bytesPerLine;
			StringBuilder result = new StringBuilder(expectedLines * lineLength);

			for (int i = 0; i < bytesLength; i += bytesPerLine)
			{
				line[0] = HexChars[(i >> 28) & 0xF];
				line[1] = HexChars[(i >> 24) & 0xF];
				line[2] = HexChars[(i >> 20) & 0xF];
				line[3] = HexChars[(i >> 16) & 0xF];
				line[4] = HexChars[(i >> 12) & 0xF];
				line[5] = HexChars[(i >> 8) & 0xF];
				line[6] = HexChars[(i >> 4) & 0xF];
				line[7] = HexChars[(i >> 0) & 0xF];

				int hexColumn = firstHexColumn;
				int charColumn = firstCharColumn;

				for (int j = 0; j < bytesPerLine; j++)
				{
					if (j > 0 && (j & 7) == 0) hexColumn++;
					if (i + j >= bytesLength)
					{
						line[hexColumn] = ' ';
						line[hexColumn + 1] = ' ';
						line[charColumn] = ' ';
					}
					else
					{
						byte b = bytes[i + j];
						line[hexColumn] = HexChars[(b >> 4) & 0xF];
						line[hexColumn + 1] = HexChars[b & 0xF];
						line[charColumn] = (b < 32 ? '·' : (char)b);
					}
					hexColumn += 3;
					charColumn++;
				}
				result.Append(line);
			}
			return result.ToString();
		}

		public static byte[] ReplaceOfficeVersionInVBAProject(byte[] moduleStream, string officeVersion, int fuzz)
		{
			byte[] version = new byte[2];

			if (fuzz != 0)
			{
				version[0] = Convert.ToByte(fuzz);
				version[1] = 0x00;
			}
			else
			{
				switch (officeVersion)
				{
					case "2010x86":
						version[0] = 0x97;
						version[1] = 0x00;
						break;
					case "2013x86":
						version[0] = 0xA3;
						version[1] = 0x00;
						break;
					case "2016x86":
						version[0] = 0xAF;
						version[1] = 0x00;
						break;
					case "2019x86":
						version[0] = 0xAF;
						version[1] = 0x00;
						break;
					case "2013x64":
						version[0] = 0xA6;
						version[1] = 0x00;
						break;
					case "2016x64":
						version[0] = 0xB2;
						version[1] = 0x00;
						break;
					case "2019x64":
						version[0] = 0xB2;
						version[1] = 0x00;
						break;
					default:
						Console.WriteLine("\n[!] ERROR: Incorrect MS Office version specified - skipping this step.");
						return moduleStream;
				}
			}

			Console.WriteLine("\n[*] Targeting pcode on Office version: " + officeVersion);

			moduleStream[2] = version[0];
			moduleStream[3] = version[1];

			return moduleStream;
		}

		public static void ReadOfficeVersionInVBAProject(byte[] moduleStream)
		{

			string officeVersion = "";

			switch (moduleStream[2])
			{
				case 0x97:
					officeVersion = "2010x86";
					break;
				case 0xA3:
					officeVersion = "2013x86";
					break;
				case 0xAF:
					officeVersion = "2016x86 / 2019x86";
					break;
				case 0xA6:
					officeVersion = "2013x64";
					break;
				case 0xB2:
					officeVersion = "2016x64 / 2019x64";
					break;
				default:
					Console.WriteLine("\n[!] ERROR: Office version could not be identified - skipping this step.");
					break;
			}

			Console.WriteLine("\n[*] Identified Office version: " + officeVersion);
		}

		public class ModuleInformation
		{
			// Name of VBA module stream
			public string moduleName;

			// Offset of VBA CompressedSourceCode in VBA module stream
			public UInt32 textOffset;
		}

		public static UInt16 GetWord(byte[] buffer, int offset)
		{
			var rawBytes = new byte[2];
			Array.Copy(buffer, offset, rawBytes, 0, 2);
			return BitConverter.ToUInt16(rawBytes, 0);
		}

		public static UInt32 GetDoubleWord(byte[] buffer, int offset)
		{
			var rawBytes = new byte[4];
			Array.Copy(buffer, offset, rawBytes, 0, 4);
			return BitConverter.ToUInt32(rawBytes, 0);
		}
		public static byte[] Compress(byte[] data)
		{
			var buffer = new DecompressedBuffer(data);
			var container = new CompressedContainer(buffer);
			return container.SerializeData();
		}
		public static byte[] Decompress(byte[] data)
		{
			var container = new CompressedContainer(data);
			var buffer = new DecompressedBuffer(container);
			return buffer.Data;
		}
		public static string GetVBATextFromModuleStream(byte[] moduleStream, UInt32 textOffset)
		{
			string vbaModuleText = Encoding.UTF8.GetString(Decompress(moduleStream.Skip((int)textOffset).ToArray()));
			return vbaModuleText;
		}
		public static string GetPcodeFromModuleStream(byte[] moduleStream, UInt32 textOffset)
		{
			string pCode = Encoding.UTF8.GetString(moduleStream.Skip(0).ToArray()).Substring(0, (int)textOffset-6);
			return pCode;
		}
		public static byte[] SetPcodeFromModuleStream(byte[] moduleStream, UInt32 textOffset, string pCode)
		{
			return Encoding.UTF8.GetBytes(pCode).ToArray();
		}
		public static byte[] PoC(byte[] moduleStream, string old_string, string new_string)
		{
			string vbaModuleAll = Encoding.Default.GetString(moduleStream.Skip(0).ToArray());
			vbaModuleAll = vbaModuleAll.Replace(old_string, new_string);
			byte[] old_b = BitConverter.GetBytes(Convert.ToUInt16(old_string.Length));
			byte[] pre_b = BitConverter.GetBytes(Convert.ToUInt16(46592));
			Array.Reverse(pre_b);
			string stringlen_old = ByteArrayToString(pre_b) + ByteArrayToString(old_b);
			byte[] new_b = BitConverter.GetBytes(Convert.ToUInt16(new_string.Length));
			string stringlen_new = ByteArrayToString(pre_b) + ByteArrayToString(new_b);
			add_offset = new_string.Length - old_string.Length;
			return Encoding.Default.GetBytes(vbaModuleAll.Replace(stringlen_old, stringlen_new)).ToArray();
		}
		public static byte[] PoC2(byte[] moduleStream)
		{
			string vbaModuleAll = Encoding.Default.GetString(moduleStream.Skip(0).ToArray());
			return Encoding.Default.GetBytes(vbaModuleAll.Replace("v\0e\0r\0s\0i\0o\0n\0 \0s\0a\0f\0e", "n\0o\0n\0o\0n\0o\0!\0 \0s\0a\0f\0e")).ToArray();
		}
		public static string ByteArrayToString(byte[] ba)
		{
			return Encoding.Default.GetString(ba);
		}
		public static byte[] RemovePcodeInModuleStream(byte[] moduleStream, UInt32 textOffset, string OG_VBACode)
		{
			return Compress(Encoding.UTF8.GetBytes(OG_VBACode)).ToArray();
		}
		public static string getOutFilename(String filename)
		{
			string fn = Path.GetFileNameWithoutExtension(filename);
			string ext = Path.GetExtension(filename);
			string path = Path.GetDirectoryName(filename);
			return Path.Combine(path, fn + "_PURGED" + ext);
		}
		public static byte[] HexToByte(string hex)
		{
			hex = hex.Replace("-", "");
			byte[] raw = new byte[hex.Length / 2];
			for (int i = 0; i < raw.Length; i++)
			{
				raw[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
			}
			return raw;
		}
		public static byte[] ChangeOffset(byte[] dirStream)
		{
			int offset = 0;
			UInt16 tag;
			UInt32 wLength;

			// Change MODULEOFFSET to 0
			//byte[] test = { 0x53, 0x00, 0x86, 0x1E };
			//string zeros = "\x53\x06\x00\x00";
			
			while (offset < dirStream.Length)
			{
				tag = GetWord(dirStream, offset);
				wLength = GetDoubleWord(dirStream, offset + 2);

				// taken from Pcodedmp
				if (tag == 9)
					wLength = 6;
				else if (tag == 3)
					wLength = 2;

				switch (tag)
				{
					// MODULEOFFSET Record
					case 49:
						uint offset_change = GetDoubleWord(dirStream, offset + 6);
						Console.WriteLine("\n[+] DEBUG Module offset_change val: " + offset_change);
						byte[] b = BitConverter.GetBytes(Convert.ToUInt32(offset_change + add_offset));
						string offset_new = ByteArrayToString(b);
						//uint test1 = GetDoubleWord(test, 0);
						UTF8Encoding encoding = new UTF8Encoding();
						encoding.GetBytes(offset_new, 0, (int)wLength, dirStream, (int)offset + 6);
						Console.WriteLine("\n[+] DEBUG Module offset changed to: " + BitConverter.ToUInt32(b,0));
						break;
				}

				offset += 6;
				offset += (int)wLength;
			}
			return dirStream;
		}
	}
}
