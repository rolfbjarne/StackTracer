using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using Xamarin.Bundler;

#nullable enable

namespace Xamarin {
	[Flags]
	public enum Abi {
		None = 0,
		i386 = 1,
		ARMv6 = 2,
		ARMv7 = 4,
		ARMv7s = 8,
		ARM64 = 16,
		x86_64 = 32,
		Thumb = 64,
		LLVM = 128,
		ARMv7k = 256,
		ARM64e = 512,
		ARM64_32 = 1024,
		SimulatorArchMask = i386 | x86_64,
		DeviceArchMask = ARMv6 | ARMv7 | ARMv7s | ARMv7k | ARM64 | ARM64e | ARM64_32,
	}

	public class MachO {
		/* definitions from: /usr/include/mach-o/loader.h */
		/* Constant for the magic field of the mach_header (32-bit architectures) */
		internal const uint MH_MAGIC = 0xfeedface; /* the mach magic number */
		internal const uint MH_CIGAM = 0xcefaedfe; /* NXSwapInt(MH_MAGIC) */

		/* Constant for the magic field of the mach_header_64 (64-bit architectures) */
		internal const uint MH_MAGIC_64 = 0xfeedfacf; /* the 64-bit mach magic number */
		internal const uint MH_CIGAM_64 = 0xcffaedfe; /* NXSwapInt(MH_MAGIC_64) */

		/* definitions from: /usr/include/mach-o/fat.h */
		internal const uint FAT_MAGIC = 0xcafebabe;
		internal const uint FAT_CIGAM = 0xbebafeca; /* NXSwapLong(FAT_MAGIC) */

		internal const uint MH_OBJECT = 0x1; /* relocatable object file */
		internal const uint MH_DYLIB = 0x6; /* dynamically bound shared library */

		// Values here match the corresponding values in the Abi enum.
		public enum Architectures {
			None = 0,
			i386 = 1,
			ARMv6 = 2,
			ARMv7 = 4,
			ARMv7s = 8,
			ARM64 = 16,
			x86_64 = 32,
			ARMv7k = 256,
			ARM64e = 512,
			ARM64_32 = 1024,
		}

		public enum LoadCommands : uint {
			//#define LC_REQ_DYLD 0x80000000
			ReqDyld = 0x80000000,
			//
			//			/* Constants for the cmd field of all load commands, the type */
			//#define	LC_SEGMENT	0x1	/* segment of this file to be mapped */
			//#define	LC_SYMTAB	0x2	/* link-edit stab symbol table info */
			//#define	LC_SYMSEG	0x3	/* link-edit gdb symbol table info (obsolete) */
			//#define	LC_THREAD	0x4	/* thread */
			//#define	LC_UNIXTHREAD	0x5	/* unix thread (includes a stack) */
			//#define	LC_LOADFVMLIB	0x6	/* load a specified fixed VM shared library */
			//#define	LC_IDFVMLIB	0x7	/* fixed VM shared library identification */
			//#define	LC_IDENT	0x8	/* object identification info (obsolete) */
			//#define LC_FVMFILE	0x9	/* fixed VM file inclusion (internal use) */
			//#define LC_PREPAGE      0xa     /* prepage command (internal use) */
			//#define	LC_DYSYMTAB	0xb	/* dynamic link-edit symbol table info */
			//#define	LC_LOAD_DYLIB	0xc	/* load a dynamically linked shared library */
			LoadDylib = 0xc,
			//#define	LC_ID_DYLIB	0xd	/* dynamically linked shared lib ident */
			IdDylib = 0xd,
			//#define LC_LOAD_DYLINKER 0xe	/* load a dynamic linker */
			//#define LC_ID_DYLINKER	0xf	/* dynamic linker identification */
			//#define	LC_PREBOUND_DYLIB 0x10	/* modules prebound for a dynamically */
			//			/*  linked shared library */
			//#define	LC_ROUTINES	0x11	/* image routines */
			//#define	LC_SUB_FRAMEWORK 0x12	/* sub framework */
			//#define	LC_SUB_UMBRELLA 0x13	/* sub umbrella */
			//#define	LC_SUB_CLIENT	0x14	/* sub client */
			//#define	LC_SUB_LIBRARY  0x15	/* sub library */
			//#define	LC_TWOLEVEL_HINTS 0x16	/* two-level namespace lookup hints */
			//#define	LC_PREBIND_CKSUM  0x17	/* prebind checksum */
			//
			//			/*
			//			* load a dynamically linked shared library that is allowed to be missing
			//			* (all symbols are weak imported).
			//			*/
			//#define	LC_LOAD_WEAK_DYLIB (0x18 | LC_REQ_DYLD)
			LoadWeakDylib = 0x18 | ReqDyld,
			//
			//#define	LC_SEGMENT_64	0x19	/* 64-bit segment of this file to be
			//			mapped */
			//#define	LC_ROUTINES_64	0x1a	/* 64-bit image routines */
			//#define LC_UUID		0x1b	/* the uuid */
			Uuid = 0x1b,
			//#define LC_RPATH       (0x1c | LC_REQ_DYLD)    /* runpath additions */
			//#define LC_CODE_SIGNATURE 0x1d	/* local of code signature */
			CodeSignature = 0x1d,
			//#define LC_SEGMENT_SPLIT_INFO 0x1e /* local of info to split segments */
			//#define LC_REEXPORT_DYLIB (0x1f | LC_REQ_DYLD) /* load and re-export dylib */
			ReexportDylib = 0x1f | ReqDyld,
			//#define	LC_LAZY_LOAD_DYLIB 0x20	/* delay load of dylib until first use */
			//#define	LC_ENCRYPTION_INFO 0x21	/* encrypted segment information */
			//#define	LC_DYLD_INFO 	0x22	/* compressed dyld information */
			//#define	LC_DYLD_INFO_ONLY (0x22|LC_REQ_DYLD)	/* compressed dyld information only */
			//#define	LC_LOAD_UPWARD_DYLIB (0x23 | LC_REQ_DYLD) /* load upward dylib */
			MinMacOSX = 0x24, //#define LC_VERSION_MIN_MACOSX 0x24   /* build for MacOSX min OS version */
			MiniPhoneOS = 0x25,//#define LC_VERSION_MIN_IPHONEOS 0x25 /* build for iPhoneOS min OS version */
							   //#define LC_FUNCTION_STARTS 0x26 /* compressed table of function start addresses */
							   //#define LC_DYLD_ENVIRONMENT 0x27 /* string for dyld to treat
							   //			like environment variable */
							   //#define LC_MAIN (0x28|LC_REQ_DYLD) /* replacement for LC_UNIXTHREAD */
							   //#define LC_DATA_IN_CODE 0x29 /* table of non-instructions in __text */
							   //#define LC_SOURCE_VERSION 0x2A /* source version used to build binary */
							   //#define LC_DYLIB_CODE_SIGN_DRS 0x2B /* Code signing DRs copied from linked dylibs */
							   //#define	LC_ENCRYPTION_INFO_64 0x2C /* 64-bit encrypted segment information */
							   //#define LC_LINKER_OPTION 0x2D /* linker options in MH_OBJECT files */
							   //#define LC_LINKER_OPTIMIZATION_HINT 0x2E /* optimization hints in MH_OBJECT files */
			MintvOS = 0x2f,//#define LC_VERSION_MIN_TVOS 0x2F /* build for AppleTV min OS version */
			MinwatchOS = 0x30,//#define LC_VERSION_MIN_WATCHOS 0x30 /* build for Watch min OS version */
							  //#define LC_NOTE 0x31 /* arbitrary data included within a Mach-O file */
			BuildVersion = 0x32,//#define LC_BUILD_VERSION 0x32 /* build for platform min OS version */
		}

		public enum Platform : uint {
			MacOS = 1,
			IOS = 2,
			TvOS = 3,
			WatchOS = 4,
			BridgeOS = 5,
			IOSSimulator = 7,
			TvOSSimulator = 8,
			WatchOSSimulator = 9,
		}

		internal static uint FromBigEndian (uint number)
		{
			return (((number >> 24) & 0xFF)
				| ((number >> 08) & 0xFF00)
				| ((number << 08) & 0xFF0000)
				| ((number << 24)));
		}

		internal static int FromBigEndian (int number)
		{
			return (((number >> 24) & 0xFF)
				| ((number >> 08) & 0xFF00)
				| ((number << 08) & 0xFF0000)
				| ((number << 24)));
		}

		internal static uint ToBigEndian (uint number)
		{
			return (((number >> 24) & 0xFF)
				| ((number >> 08) & 0xFF00)
				| ((number << 08) & 0xFF0000)
				| ((number << 24)));
		}

		internal static int ToBigEndian (int number)
		{
			return (((number >> 24) & 0xFF)
				| ((number >> 08) & 0xFF00)
				| ((number << 08) & 0xFF0000)
				| ((number << 24)));
		}

		static object? ReadFile (BinaryReader reader, string filename, bool throw_if_error = true)
		{
			var magic = reader.ReadUInt32 ();
			reader.BaseStream.Position = 0;
			switch (magic) {
			case MH_MAGIC:
			case MH_MAGIC_64:
				var mf = new MachOFile (filename);
				mf.Read (reader);
				return mf;
			case FAT_MAGIC: // little-endian fat binary
			case FAT_CIGAM: // big-endian fat binary
				{
				var f = new FatFile (filename);
				f.Read (reader);
				return f;
			}
			default:
				if (StaticLibrary.IsStaticLibrary (reader)) {
					var sl = new StaticLibrary ();
					sl.Read (filename, reader, reader.BaseStream.Length);
					return sl;
				}
				if (throw_if_error)
					throw new Exception (string.Format ("File format not recognized: {0} (magic: 0x{1})", filename, magic.ToString ("X")));
				return null;
			}
		}

		static object ReadFile (string filename)
		{
			using (var fs = new FileStream (filename, FileMode.Open, FileAccess.Read, FileShare.Read)) {
				using (var reader = new BinaryReader (fs)) {
					return ReadFile (reader, filename)!;
				}
			}
		}

		public static IEnumerable<MachOFile> Read (string filename)
		{
			var file = ReadFile (filename);
			var fatfile = file as FatFile;
			if (fatfile is not null) {
				foreach (var ff in fatfile.entries!) {
					if (ff.entry is not null)
						yield return ff.entry;
					if (ff.static_library is not null)
						foreach (var obj in ff.static_library.ObjectFiles)
							yield return obj;
				}
			} else {
				var mf = file as MachOFile;
				if (mf is not null) {
					yield return mf;
					yield break;
				}

				var sl = file as StaticLibrary;
				if (sl is not null) {
					foreach (var obj in sl.ObjectFiles)
						yield return obj;
					yield break;
				}

				throw ErrorHelper.CreateError (1604, Errors.MX1604, file.GetType ().Name, filename);
			}
		}

		static Dictionary<string, IEnumerable<string>> native_dependencies = new Dictionary<string, IEnumerable<string>> ();

		public static IEnumerable<string> GetNativeDependencies (string libraryName)
		{
			IEnumerable<string>? result;
			lock (native_dependencies) {
				if (native_dependencies.TryGetValue (libraryName, out result))
					return result;
			}

			var macho_files = Read (libraryName);
			var dependencies = new HashSet<string> ();
			foreach (var macho_file in macho_files) {
				foreach (var lc in macho_file.load_commands) {
					var dyld_lc = lc as Xamarin.DylibLoadCommand;
					if (dyld_lc?.name is not null) {
						dependencies.Add (dyld_lc.name);
					}
				}
			}
			result = dependencies;
			lock (native_dependencies)
				native_dependencies.Add (libraryName, result);
			return result;
		}

		public static List<Abi> GetArchitectures (string file)
		{
			var result = new List<Abi> ();

			// https://developer.apple.com/library/mac/#documentation/DeveloperTools/Conceptual/MachORuntime/Reference/reference.html

			using (var fs = File.OpenRead (file)) {
				using (var reader = new BinaryReader (fs)) {
					int magic = reader.ReadInt32 ();
					int architectures;
					switch ((uint) magic) {
					case 0xCAFEBABE: // little-endian fat binary
						architectures = reader.ReadInt32 ();
						for (int i = 0; i < architectures; i++) {
							result.Add (GetArch (reader.ReadInt32 (), reader.ReadInt32 ()));
							// skip to next entry
							reader.ReadInt32 (); // offset
							reader.ReadInt32 (); // size
							reader.ReadInt32 (); // align
						}
						break;
					case 0xBEBAFECA:
						architectures = System.Net.IPAddress.NetworkToHostOrder (reader.ReadInt32 ());
						for (int i = 0; i < architectures; i++) {
							result.Add (GetArch (System.Net.IPAddress.NetworkToHostOrder (reader.ReadInt32 ()), System.Net.IPAddress.NetworkToHostOrder (reader.ReadInt32 ())));
							// skip to next entry
							reader.ReadInt32 (); // offset
							reader.ReadInt32 (); // size
							reader.ReadInt32 (); // align
						}
						break;
					case 0xFEEDFACE: // little-endian mach-o header
					case 0xFEEDFACF: // little-endian 64-big mach-o header
						result.Add (GetArch (reader.ReadInt32 (), reader.ReadInt32 ()));
						break;
					case 0xCFFAEDFE:
					case 0xCEFAEDFE:
						result.Add (GetArch (System.Net.IPAddress.NetworkToHostOrder (reader.ReadInt32 ()), System.Net.IPAddress.NetworkToHostOrder (reader.ReadInt32 ())));
						break;
					default:
						Console.WriteLine ("File '{0}' is neither a Universal binary nor a Mach-O binary (magic: 0x{1})", file, magic.ToString ("x"));
						break;
					}
				}
			}

			return result;
		}

		public static Abi GetArch (int cputype, int cpusubtype)
		{
			cpusubtype &= 0x00ffffff; // remove any feature flags

			switch (cputype) {
			case 12: // arm
				switch (cpusubtype) {
				case 6:
					return Abi.ARMv6;
				case 9:
					return Abi.ARMv7;
				case 11:
					return Abi.ARMv7s;
				case 12:
					return Abi.ARMv7k;
				default:
					return Abi.None;
				}
			case 12 | 0x01000000:
				switch (cpusubtype) {
				case 2:
					return Abi.ARM64e;
				case 0:
				default:
					return Abi.ARM64;
				}
			case 12 | 0x02000000: // CPU_TYPE_ARM | CPU_ARCH_ABI64_32 (64-bit hardware with 32-bit types; LP32)
				switch (cpusubtype) {
				case 1: // CPU_SUBTYPE_ARM64_32_V8
					return Abi.ARM64_32;
				default:
					return Abi.None;
				}
			case 7: // x86
				return Abi.i386;
			case 7 | 0x01000000: // x64
				return Abi.x86_64;
			}

			return Abi.None;
		}

		public static bool IsStaticLibraryOrObjectFile (string filename, bool throw_if_error, out bool objectFile)
		{
			objectFile = false;
			using var fs = File.OpenRead (filename);
			using var reader = new BinaryReader (fs);
			if (StaticLibrary.IsStaticLibrary (reader, throw_if_error))
				return true;
			var f = ReadFile (reader, filename, throw_if_error);
			if (f is StaticLibrary)
				return true;
			var fat = f as FatFile;
			if (fat is null)
				return false;
			foreach (var entry in fat.entries!) {
				if (entry.IsStaticLibrary)
					return true;
				if (entry.entry?.IsObjectFile == true) {
					objectFile = true;
					return true;
				}
			}
			return false;
		}

		public static bool IsDynamicFramework (string filename)
		{
			var f = ReadFile (filename);
			if (f is StaticLibrary)
				return false;
			else if (f is MachOFile)
				return ((MachOFile) f).IsDynamicLibrary;

			var fat = f as FatFile;
			if (fat is null)
				return false;

			foreach (var entry in fat.entries!)
				if (!entry.IsDynamicLibrary)
					return false;

			return true;
		}

		public static bool IsMachOFile (string filename)
		{
			using (var fs = File.OpenRead (filename)) {
				if (fs.Length < 4)
					return false;
				using (var reader = new BinaryReader (fs)) {
					var magic = reader.ReadUInt32 ();
					switch (magic) {
					case MH_MAGIC:
					case MH_MAGIC_64:
					case FAT_MAGIC: // little-endian fat binary
					case FAT_CIGAM: // big-endian fat binary
						return true;
					default:
						return false;
					}
				}
			}
		}
	}

	public class StaticLibrary {
		List<MachOFile> object_files = new List<MachOFile> ();

		public IEnumerable<MachOFile> ObjectFiles { get { return object_files; } }

		static string ReadString (BinaryReader reader, int length)
		{
			var bytes = reader.ReadBytes (length);
			for (var i = 0; i < bytes.Length; i++) {
				if (bytes [i] == 0) {
					length = i;
					break;
				}
			}
			return Encoding.ASCII.GetString (bytes, 0, length);
		}

		static long ReadDecimal (BinaryReader reader, int length)
		{
			var str = ReadString (reader, length);
			str = str.TrimEnd (' ');
			return long.Parse (str);
		}

		static long ReadOctal (BinaryReader reader, int length)
		{
			var str = ReadString (reader, length);
			str = str.TrimEnd (' ');
			return Convert.ToInt64 (str, 8);
		}

		internal void Read (string filename, BinaryReader reader, long size)
		{
			IsStaticLibrary (reader, throw_if_error: true);

			var pos = reader.BaseStream.Position;
			reader.BaseStream.Position += 8; // header

			byte [] bytes;
			while (reader.BaseStream.Position < pos + size) {
				var fileIdentifier = ReadString (reader, 16);
				var fileModificationTimestamp = ReadDecimal (reader, 12);
				var ownerId = ReadDecimal (reader, 6);
				var groupId = ReadDecimal (reader, 6);
				var fileMode = ReadOctal (reader, 8);
				var fileSize = ReadDecimal (reader, 10);
				bytes = reader.ReadBytes (2); // ending characters
				if (bytes [0] != 0x60 && bytes [1] != 0x0A)
					throw ErrorHelper.CreateError (1605, Errors.MT1605, fileIdentifier, filename, bytes [0].ToString ("x"), bytes [1].ToString ("x"));

				if (fileIdentifier.StartsWith ("#1/", StringComparison.Ordinal)) {
					var nameLength = int.Parse (fileIdentifier.Substring (3).TrimEnd (' '));
					fileIdentifier = ReadString (reader, nameLength);
					fileSize -= nameLength;
				}

				var nextPosition = reader.BaseStream.Position + fileSize;
				if (MachOFile.IsMachOLibrary (null, reader)) {
					var file = new MachOFile (fileIdentifier);
					file.Read (reader);
					object_files.Add (file);
				}
				// byte position is always even after each file.
				if (nextPosition % 1 == 1)
					nextPosition++;
				reader.BaseStream.Position = nextPosition;
			}

		}

		public static bool IsStaticLibrary (BinaryReader reader, bool throw_if_error = false)
		{
			var pos = reader.BaseStream.Position;

			var bytes = reader.ReadBytes (8);
			bool rv;
			if (bytes.Length < 8) {
				rv = false;
			} else {
				rv = bytes [0] == '!' && bytes [1] == '<' && bytes [2] == 'a' && bytes [3] == 'r' && bytes [4] == 'c' && bytes [5] == 'h' && bytes [6] == '>' && bytes [7] == 0xa;
			}
			reader.BaseStream.Position = pos;

			if (throw_if_error && !rv)
				throw ErrorHelper.CreateError (1601, Errors.MT1601, System.Text.Encoding.ASCII.GetString (bytes, 0, 7));

			return rv;
		}

		public static bool IsStaticLibrary (string filename, bool throw_if_error = false)
		{
			using (var fs = File.OpenRead (filename)) {
				using (var reader = new BinaryReader (fs)) {
					return IsStaticLibrary (reader, throw_if_error);
				}
			}
		}
	}

	public class MachOFile {
		FatEntry? fat_parent;
		string? filename;

		public uint magic;
		int _cputype;
		int _cpusubtype;
		uint _filetype;
		uint _ncmds;
		uint _sizeofcmds;
		uint _flags;
		uint _reserved;

		bool is64bitheader;

		public int cputype { get { return is_big_endian ? MachO.ToBigEndian (_cputype) : _cputype; } }
		public int cpusubtype { get { return is_big_endian ? MachO.ToBigEndian (_cpusubtype) : _cpusubtype; } }
		public uint filetype { get { return is_big_endian ? MachO.ToBigEndian (_filetype) : _filetype; } }
		public uint ncmds { get { return is_big_endian ? MachO.ToBigEndian (_ncmds) : _ncmds; } }
		public uint sizeofcmds { get { return is_big_endian ? MachO.ToBigEndian (_sizeofcmds) : _sizeofcmds; } }
		public uint flags { get { return is_big_endian ? MachO.ToBigEndian (_flags) : _flags; } }
		public uint reserved { get { return is_big_endian ? MachO.ToBigEndian (_reserved) : _reserved; } }

		public List<LoadCommand> load_commands = new List<LoadCommand> ();

		public string? Filename { get { return filename; } }
		public FatEntry? Parent { get { return fat_parent; } }

		public MachOFile ()
		{
		}

		public MachOFile (FatEntry parent)
		{
			fat_parent = parent;
		}

		public MachOFile (string filename)
		{
			this.filename = filename;
		}

		internal bool is_big_endian {
			get {
				return magic == MachO.FAT_CIGAM || magic == MachO.MH_CIGAM_64;
			}
		}

		internal void WriteHeader (BinaryWriter writer)
		{
			writer.Write (magic);
			writer.Write (_cputype);
			writer.Write (_cpusubtype);
			writer.Write (_filetype);
			writer.Write (_ncmds);
			writer.Write (_sizeofcmds);
			writer.Write (_flags);
			if (is64bitheader)
				writer.Write (reserved);
		}

		internal static bool IsMachOLibrary (FatEntry? fat_entry, BinaryReader reader, bool throw_if_error = false)
		{
			var pos = reader.BaseStream.Position;

			var magic = reader.ReadUInt32 ();
			var rv = false;
			switch (magic) {
			case MachO.MH_CIGAM:
			case MachO.MH_MAGIC:
			case MachO.MH_CIGAM_64:
			case MachO.MH_MAGIC_64:
				rv = true;
				break;
			default:
				rv = false;
				break;
			}

			reader.BaseStream.Position = pos;

			if (throw_if_error && !rv)
				throw ErrorHelper.CreateError (1600, Errors.MX1600, magic.ToString ("x"), fat_entry?.Parent?.Filename);

			return rv;
		}

		public void Read (BinaryReader reader)
		{
			magic = reader.ReadUInt32 ();
			switch (magic) {
			case MachO.MH_CIGAM:
			case MachO.MH_MAGIC:
				is64bitheader = false;
				break;
			case MachO.MH_CIGAM_64:
			case MachO.MH_MAGIC_64:
				is64bitheader = true;
				break;
			default:
				throw ErrorHelper.CreateError (1602, Errors.MX1602, magic.ToString ("x"), fat_parent?.Parent?.Filename ?? filename);
			}
			_cputype = reader.ReadInt32 ();
			_cpusubtype = reader.ReadInt32 ();
			_filetype = reader.ReadUInt32 ();
			_ncmds = reader.ReadUInt32 ();
			_sizeofcmds = reader.ReadUInt32 ();
			_flags = reader.ReadUInt32 ();
			if (is64bitheader)
				_reserved = reader.ReadUInt32 ();
			var cmds = new List<LoadCommand> ((int) ncmds);
			for (int i = 0; i < ncmds; i++) {
				var cmd = (MachO.LoadCommands) reader.ReadUInt32 ();
				reader.BaseStream.Position -= 4;
				LoadCommand lc;
				switch (cmd) {
				case MachO.LoadCommands.LoadDylib:
				case MachO.LoadCommands.LoadWeakDylib:
				case MachO.LoadCommands.ReexportDylib: {
					var dlc = new DylibLoadCommand ();
					dlc.cmd = reader.ReadUInt32 ();
					dlc.cmdsize = reader.ReadUInt32 ();
					/*var nameofs = */
					reader.ReadUInt32 ();
					dlc.timestamp = reader.ReadUInt32 ();
					dlc.current_version = reader.ReadUInt32 ();
					dlc.compatibility_version = reader.ReadUInt32 ();
					var namelength = dlc.cmdsize - 6 * 4;
					var namechars = reader.ReadBytes ((int) namelength);
					// strip off any null characters at the end.
					for (int n = namechars.Length - 1; n >= 0; n--) {
						if (namechars [n] == 0)
							namelength--;
						else
							break;
					}
					dlc.name = System.Text.UTF8Encoding.UTF8.GetString (namechars, 0, (int) namelength);

					lc = dlc;
					break;
				}
				case MachO.LoadCommands.IdDylib: {
					var dlc = new DylibIdCommand ();
					dlc.cmd = reader.ReadUInt32 ();
					dlc.cmdsize = reader.ReadUInt32 ();
					/*var nameofs = */
					reader.ReadUInt32 ();
					dlc.timestamp = reader.ReadUInt32 ();
					dlc.current_version = reader.ReadUInt32 ();
					dlc.compatibility_version = reader.ReadUInt32 ();
					var namelength = dlc.cmdsize - 6 * 4;
					var namechars = reader.ReadBytes ((int) namelength);
					// strip off any null characters at the end.
					for (int n = namechars.Length - 1; n >= 0; n--) {
						if (namechars [n] == 0)
							namelength--;
						else
							break;
					}
					dlc.name = Encoding.UTF8.GetString (namechars, 0, (int) namelength);

					lc = dlc;
					break;
				}
				case MachO.LoadCommands.Uuid:
					var uuidCmd = new UuidCommand ();
					uuidCmd.cmd = reader.ReadUInt32 ();
					uuidCmd.cmdsize = reader.ReadUInt32 ();
					uuidCmd.uuid = reader.ReadBytes (16); // defined in the header as uint8_t uuid [16]
					lc = uuidCmd;
					break;
				case MachO.LoadCommands.MintvOS:
				case MachO.LoadCommands.MinMacOSX:
				case MachO.LoadCommands.MiniPhoneOS:
				case MachO.LoadCommands.MinwatchOS:
					var minCmd = new MinCommand ();
					minCmd.cmd = reader.ReadUInt32 ();
					minCmd.cmdsize = reader.ReadUInt32 ();
					minCmd.version = reader.ReadUInt32 ();
					minCmd.sdk = reader.ReadUInt32 ();
					lc = minCmd;
					break;
				case MachO.LoadCommands.BuildVersion:
					var buildVer = new BuildVersionCommand ();
					buildVer.cmd = reader.ReadUInt32 ();
					buildVer.cmdsize = reader.ReadUInt32 ();
					buildVer.platform = reader.ReadUInt32 ();
					buildVer.minos = reader.ReadUInt32 ();
					buildVer.sdk = reader.ReadUInt32 ();
					buildVer.ntools = reader.ReadUInt32 ();
					buildVer.tools = new BuildVersionCommand.BuildToolVersion [buildVer.ntools];
					for (int j = 0; j < buildVer.ntools; j++) {
						var buildToolVer = new BuildVersionCommand.BuildToolVersion ();
						buildToolVer.tool = reader.ReadUInt32 ();
						buildToolVer.version = reader.ReadUInt32 ();
						buildVer.tools [j] = buildToolVer;
					}
					lc = buildVer;
					break;
				default:
					lc = new LoadCommand ();
					lc.cmd = reader.ReadUInt32 ();
					lc.cmdsize = reader.ReadUInt32 ();
					reader.BaseStream.Position += lc.cmdsize - 8;
					break;
				}
				cmds.Add (lc);
			}
			load_commands = cmds;
		}

		public MachO.Architectures Architecture {
			get {
				return (MachO.Architectures) MachO.GetArch (cputype, cpusubtype);
			}
		}

		public bool IsDynamicLibrary {
			get { return filetype == MachO.MH_DYLIB; }
		}

		public bool IsObjectFile {
			get => filetype == MachO.MH_OBJECT;
		}
	}

	public class FatFile {
		public readonly string Filename;

		public uint magic;
		uint _nfat_arch;

		public FatFile (string filename)
		{
			Filename = filename;
		}

		public uint nfat_arch {
			get { return is_big_endian ? MachO.ToBigEndian (_nfat_arch) : _nfat_arch; }
			set { _nfat_arch = is_big_endian ? MachO.FromBigEndian (value) : value; }
		}

		public List<FatEntry>? entries;

		internal bool is_big_endian {
			get { return magic == MachO.FAT_CIGAM; }
		}

		internal void WriteHeader (BinaryWriter writer)
		{
			writer.Write (magic);
			writer.Write (_nfat_arch);
		}

		internal void WriteHeaders (BinaryWriter writer)
		{
			WriteHeader (writer);
			for (int i = 0; i < entries!.Count; i++) {
				entries [i].WriteHeader (writer);
			}
		}

		internal void Read (BinaryReader reader)
		{
			magic = reader.ReadUInt32 ();
			_nfat_arch = reader.ReadUInt32 ();

			entries = new List<FatEntry> ((int) nfat_arch);
			for (int i = 0; i < (int) nfat_arch; i++) {
				var entry = new FatEntry ();
				entry.Read (this, reader);
				entries.Add (entry);
			}
			foreach (var entry in entries)
				entry.ReadEntry (reader);
		}
	}

	public class FatEntry {
		FatFile? parent;
		public int cputype;
		public int cpusubtype;
		public uint offset;
		public uint size;
		public uint align;

		public MachOFile? entry;
		public StaticLibrary? static_library;

		public bool IsDynamicLibrary { get { return entry?.IsDynamicLibrary == true; } }
		public bool IsStaticLibrary { get => static_library is not null; }
		public FatFile Parent { get { return parent!; } }

		internal void WriteHeader (BinaryWriter writer)
		{
			if (Parent.is_big_endian) {
				writer.Write (MachO.ToBigEndian (cputype));
				writer.Write (MachO.ToBigEndian (cpusubtype));
				writer.Write (MachO.ToBigEndian (offset));
				writer.Write (MachO.ToBigEndian (size));
				writer.Write (MachO.ToBigEndian (align));
			} else {
				writer.Write (cputype);
				writer.Write (cpusubtype);
				writer.Write (offset);
				writer.Write (size);
				writer.Write (align);
			}
		}

		internal void Write (BinaryWriter writer, BinaryReader reader, uint reader_offset)
		{
			writer.BaseStream.Position = offset;
			// write data
			WriteFile (writer, reader, reader_offset);
		}

		internal void WriteFile (BinaryWriter writer, BinaryReader reader, uint reader_offset)
		{
			// write data
			var ofs = writer.BaseStream.Position;
			reader.BaseStream.Position = reader_offset;
			var buffer = new byte [1 << (int) align];
			var left = (int) size;
			while (left > 0) {
				var read = reader.Read (buffer, 0, Math.Min (buffer.Length, left));
				writer.Write (buffer, 0, read);
				left -= read;
			}
			writer.BaseStream.Position = ofs; // restore to the post-header location.
		}

		internal void Read (FatFile parent, BinaryReader reader)
		{
			this.parent = parent;
			cputype = reader.ReadInt32 ();
			cpusubtype = reader.ReadInt32 ();
			offset = reader.ReadUInt32 ();
			size = reader.ReadUInt32 ();
			align = reader.ReadUInt32 ();

			if (parent.is_big_endian) {
				cputype = MachO.FromBigEndian (cputype);
				cpusubtype = MachO.FromBigEndian (cpusubtype);
				offset = MachO.FromBigEndian (offset);
				size = MachO.FromBigEndian (size);
				align = MachO.FromBigEndian (align);
			}
		}

		internal void ReadEntry (BinaryReader reader)
		{
			reader.BaseStream.Position = offset;

			if (MachOFile.IsMachOLibrary (this, reader)) {
				entry = new MachOFile (this);
				entry.Read (reader);
			} else if (StaticLibrary.IsStaticLibrary (reader)) {
				static_library = new StaticLibrary ();
				static_library.Read (parent?.Filename!, reader, size);
			} else {
				throw ErrorHelper.CreateError (1603, Errors.MX1603, offset, parent?.Filename);
			}
		}
	}

	public class LoadCommand {
		public uint cmd;
		public uint cmdsize;

		public MachO.LoadCommands Command {
			get { return (MachO.LoadCommands) cmd; }
		}
	}

	public class DylibLoadCommand : LoadCommand {
		public string name = string.Empty;
		public uint timestamp;
		public uint current_version;
		public uint compatibility_version;
	}

	public class DylibIdCommand : LoadCommand {
		public string name = string.Empty;
		public uint timestamp;
		public uint current_version;
		public uint compatibility_version;
	}

	public class UuidCommand : LoadCommand {
		public byte []? uuid;

		public string AsString (bool withDashes)
		{
			if (uuid is null)
				return string.Empty;
			var rv = uuid.Select (b => b.ToString ("x2")).ToList ();
			if (withDashes) {
				rv.Insert (10, "-");
				rv.Insert (8, "-");
				rv.Insert (6, "-");
				rv.Insert (4, "-");
			}
			return string.Join ("", rv);
		}
	}

	public class MinCommand : LoadCommand {
		public uint version; /* X.Y.Z is encoded in nibbles xxxx.yy.zz */
		public uint sdk; /* X.Y.Z is encoded in nibbles xxxx.yy.zz */

		Version DeNibble (uint value)
		{
			return new Version ((int) (value >> 16), (int) ((value >> 8) & 0xFF), (int) (value & 0xFF));
		}

		public Version Version {
			get { return DeNibble (version); }
		}

		public Version Sdk {
			get { return DeNibble (sdk); }
		}
	}

	public class BuildVersionCommand : LoadCommand {
		public uint platform;
		public uint minos; /* X.Y.Z is encoded in nibbles xxxx.yy.zz */
		public uint sdk; /* X.Y.Z is encoded in nibbles xxxx.yy.zz */
		public uint ntools;
		public BuildToolVersion []? tools;

		public class BuildToolVersion {
			public uint tool;
			public uint version;
		}

		Version DeNibble (uint value)
		{
			return new Version ((int) (value >> 16), (int) ((value >> 8) & 0xFF), (int) (value & 0xFF));
		}

		public Version MinOS {
			get { return DeNibble (minos); }
		}

		public Version Sdk {
			get { return DeNibble (sdk); }
		}

		public MachO.Platform Platform {
			get { return (MachO.Platform) platform; }
		}
	}
}

static class ErrorHelper {
	public static Exception CreateError (int code, string message, params object [] args)
	{
		return new Exception (string.Format (message, args));
	}
}

static class Errors {
	public const string MX1600 = "File format not recognized: {0} (magic: {1})";
	public const string MX1601 = "File format not recognized: {0}";
	public const string MX1602 = "File format not recognized: {0} (magic: {1})";
	public const string MX1603 = "File format not recognized: {0} (offset: {1})";
	public const string MX1604 = "File format not recognized: {0} (offset: {1})";
	public const string MT1601 = "File format not recognized: {0}";
	public const string MT1605 = "File format not recognized: {0} (filename: {1}, byte 0x{2}, byte 0x{3})";
}
