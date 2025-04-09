
namespace StackTracer {
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Text;
    
#if !__MACOS__
    using UIKit;
#endif

    using ObjCRuntime;
    using Xamarin;

    public static class StackReport {
        /// <summary>
        /// Create both a stack report and a script that can be used to symbolicate the stack trace.
        /// They're both written to the temp directory.
        /// </summary>
        public static void TestMe ()
        {
            // Create a stack report
            try {
                var report = StackReport.Create ();
                var fn = Environment.GetEnvironmentVariable ("CRASH_REPORT_FILE");
                if (string.IsNullOrEmpty (fn))
                    fn = Path.Combine (Path.GetTempPath (), "crash.txt");
                if (!string.IsNullOrEmpty (fn)) {
                    File.WriteAllText (fn, report);
                    Console.WriteLine ($"Wrote report to: {fn}");
                }
            } catch (Exception ex) {
                Console.WriteLine ($"Error creating stack report: {ex}");
            }

            // Create a script that can be used to symbolicate the stack trace
            try {
                var report = CreateScript ();
                var fn = Environment.GetEnvironmentVariable ("CRASH_REPORT_SCRIPT");
                if (string.IsNullOrEmpty (fn))
                    fn = Path.Combine (Path.GetTempPath (), "crash.sh");
                if (!string.IsNullOrEmpty (fn)) {
                    File.WriteAllText (fn, report);
                    Console.WriteLine ($"Wrote script to: {fn}");
                }
            } catch (Exception ex) {
                Console.WriteLine ($"Error creating stack script: {ex}");
            }
        }

        /// <summary>
        /// Capture the current stack, and create a script with the stack trace that can print a symbolicated version of itself.
        /// </summary>
        /// <returns></returns>
        public static string CreateScript ()
        {
            var sb = new StringBuilder();

            sb.AppendLine ("""
#!/bin/zsh -eu

maxLibraryLength=0
declare -A dsyms
declare -A baseaddresses
declare -A architectures

function trace ()
{
	printf "%s\n" "$@" >&2
}

function load_dsym ()
{
	local libraryPath=$1
	local libraryUuid=$2
	local libraryBaseAddress=$3
    local libraryArchitecture=$4

    libraryName=$(basename "$libraryPath")

	dsym=$(mdfind "com_apple_xcode_dsym_uuids == $libraryUuid")
	if test -z "$dsym"; then
        trace "    Unable to find the dSYM archive for the library '$libraryName' (with UUID=$libraryUuid)"

        deviceSupport="$HOME/Library/Developer/Xcode/$systemName DeviceSupport/$hardwareModel $osVersion/Symbols/$libraryPath"

        if test -f "$deviceSupport"; then
            dsym="$deviceSupport"
		    trace "    Located a device support archive for the library '$libraryName' (with UUID=$libraryUuid): $dsym"
        else
            trace "    Unable to locate the device support archive for the library '$libraryName' (with UUID=$libraryUuid), it does not exist: $deviceSupport"
            dsym=""
        fi
	else
		trace "    Located the dSYM archive for the library '$libraryName' (with UUID=$libraryUuid): $dsym"
	fi
	dsyms[$libraryName]=$dsym
	baseaddresses[$libraryName]=$libraryBaseAddress
    architectures[$libraryName]=$libraryArchitecture

	#echo "${maxLibraryLength} ${#libraryName}"
	if [[ ${#libraryName} -gt $maxLibraryLength ]]; then
		maxLibraryLength=${#libraryName}
	fi
}

function symbolicate_frame ()
{
	local frame=$1
	local libraryName=$2
	local address=$3
	local frameInfo=$4

    if test -z "$libraryName"; then
        printf "%-3s %-${maxLibraryLength}s  %18s  %s\n" "$frame" "$libraryName" "$address" "# $frameInfo"
    else
        local dsym=$dsyms[$libraryName]
        local libraryBaseAddress=$baseaddresses[$libraryName]
        local arch=$architectures[$libraryName]

        if test -z "$dsym"; then
            printf "%-3s %-${maxLibraryLength}s  %18s  %s\n" "$frame" "$libraryName" "$address" "# $frameInfo"
        else
            # echo atos -arch $arch -l $libraryBaseAddress -o "$dsym" $address
            symbolicatedFrame=$(atos -arch $arch -l $libraryBaseAddress -o "$dsym" $address | tr -d '\n')
            printf "%-3s %-${maxLibraryLength}s  %18s  %s %s\n" "$frame" "$libraryName" "$address" "$symbolicatedFrame" "# $frameInfo"
        fi
    fi
}
""");

            sb.AppendLine ();
            sb.AppendLine ($"printf 'Report Version:      104\\n'");
            sb.AppendLine ($"printf 'OS Version:          {GetSystemName ()} {GetOSVersion ()}\\n'");
            sb.AppendLine ($"printf 'Hardware Model:      {GetModel ()}\\n'");
            sb.AppendLine ();

            sb.AppendLine ($"systemName='{GetSystemName ()}'");
            sb.AppendLine ($"osVersion='{GetOSVersion ()}'");
            sb.AppendLine ($"hardwareModel='{GetModel ()}'");

			var array = new IntPtr [512];
			var size = backtrace (array, array.Length);
            Array.Resize (ref array, size);

            var infos = new Dl_info [size];
            var libraries = new Dictionary<string, nint> ();
            for (var i = 0; i < size; i++) {
                var rv = dladdr (array [i], out var info);
                infos [i] = info;
                if (!string.IsNullOrEmpty (info.LibraryPath))
                    libraries [info.LibraryPath] = info.LibraryBaseAddress;
            }

            sb.AppendLine ();
            sb.AppendLine ("trace 'Locating dSYMs...'");
            var maxLength = libraries.Keys.Select (v => v.Length).Max ();
            foreach (var kv in libraries.OrderBy (v => v.Key)) {
                var libname = kv.Key;
                var uuid = GetUuid (kv.Value, true, out var architecture, out var _);
                sb.AppendLine ($"load_dsym '{libname}'{new string (' ', maxLength - libname.Length)} '{uuid}' 0x{kv.Value:x16} {architecture}");
            }
            sb.AppendLine ("trace ''");

            sb.AppendLine ();
            sb.AppendLine ("trace 'Thread 9999:'");
            for (var i = 0; i < infos.Length; i++) {
                var info = infos [i];
                var libname = info.LibraryPath is null ? "" : Path.GetFileName (info.LibraryPath);
                sb.AppendLine ($"symbolicate_frame {i,-3} '{libname}'{new string (' ', maxLength - libname.Length)}  0x{array[i]:x16} '{info.NearestSymbol}'");
            }

            return sb.ToString();
      }

/// <summary>
/// Create a stack report for the current thread. Captures both a native stack trace and a managed stack trace.
/// </summary>
/// <returns></returns>
        public static string Create ()
        {
            var sb = new StringBuilder();

            sb.AppendLine ($"Report Version:      104");
            sb.AppendLine ($"OS Version:          {GetSystemName ()} {GetOSVersion ()}");
            sb.AppendLine ($"Hardware Model:      {GetModel ()}");

            sb.AppendLine ();
            sb.AppendLine("Managed stack trace:");
            sb.AppendLine(Environment.StackTrace.Replace ("\n", "\n    "));

			var array = new IntPtr [512];
			var size = backtrace (array, array.Length);
            Array.Resize (ref array, size);

            var infos = new Dl_info [size];

            sb.AppendLine ();
            sb.AppendLine ($"Thread 9999:");
            for (var i = 0; i < size; i++) {
                var rv = dladdr (array [i], out var info);
                infos [i] = info;

                var libname = info.LibraryPath is null ? "-" : Path.GetFileName (info.LibraryPath);
                var offset = array[i] - info.NearestSymbolAddress;
                sb.AppendLine ($"{i,-3} {libname,-30} 0x{array[i]:x16} 0x{info.LibraryBaseAddress:x16} {(offset < 0 ? $"- {offset}" : $"+ {offset}")} // {info.NearestSymbol} ");
            }

            sb.AppendLine ();
            sb.AppendLine ($"Binary Images:");

            var libraryProcessed = new HashSet<string> ();
            foreach (var info in infos.OrderBy (v => v.LibraryBaseAddress)) {
                if (string.IsNullOrEmpty (info.LibraryPath))
                    continue;
                if (libraryProcessed.Contains (info.LibraryPath))
                    continue;
                libraryProcessed.Add (info.LibraryPath);
                var uuid = GetUuid (info.LibraryBaseAddress, false, out var architecture, out var librarySize);
                var startAddress = $"{$"0x{info.LibraryBaseAddress:x}",16}";
                var endAddress = $"{$"0x{info.LibraryBaseAddress + (nint) librarySize:x}",16}";
                sb.AppendLine ($"  {startAddress} - {endAddress} {Path.GetFileName (info.LibraryPath)} {architecture} <{uuid}> {info.LibraryPath}");
            }

            return sb.ToString();
        }

    static string GetSystemName ()
    {
#if __MACOS__ || __MACCATALYST__
            return "macOS";
#elif __IOS__
            return "iOS";
#else
#error Unsupported platform
#endif
    }

     static string GetOSVersion ()
      {
#if __MACOS__ || __MACCATALYST__
            return $"{NSProcessInfo.ProcessInfo.OperatingSystemVersionString.Replace ("Version ", "").Replace ("Build ", "")}";
#elif __IOS__
            return $"{UIDevice.CurrentDevice.SystemVersion} ({GetBuildVersion ()})";
#else
#error Unsupported platform
#endif
       }

        static string GetModel ()
        {
#if __MACOS__ || __MACCATALYST__
            var os_version_string = new byte [256];
            nint os_version_string_len = os_version_string.Length - 1;
            sysctlbyname("hw.model", os_version_string, ref os_version_string_len, IntPtr.Zero, 0);
            return Encoding.UTF8.GetString (os_version_string, 0, (int) os_version_string_len - 1);
#else
            var uts = new Utsname ();
            uname (ref uts);
            Console.WriteLine ($"uname: Sysname={uts.Sysname} Nodename={uts.Nodename} Release={uts.Release} Version={uts.Version} Machine={uts.Machine}");
            return uts.Machine ?? "Unknown";
#endif
        }
        static string GetBuildVersion ()
        {
            var os_version_string = new byte [256];
            nint os_version_string_len = os_version_string.Length - 1;
            sysctlbyname("kern.osversion", os_version_string, ref os_version_string_len, IntPtr.Zero, 0);
            return Encoding.UTF8.GetString (os_version_string, 0, (int) os_version_string_len - 1);
        }

		[DllImport (Constants.libcLibrary)]
		static extern int backtrace (IntPtr [] array, int size);

   		[DllImport (Constants.libcLibrary)]
		static extern int dladdr (IntPtr addr, out Dl_info info);

   		[DllImport (Constants.libcLibrary)]
		static extern int uname (ref Utsname value);

   		[DllImport (Constants.libcLibrary)]
		static extern int sysctlbyname (/* const char */ [MarshalAs (UnmanagedType.LPStr)] string property, byte[] oldp, ref nint oldlenp, IntPtr newp, /* size_t */ long newlen);
    
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        struct Utsname {
            [MarshalAs (UnmanagedType.ByValTStr, SizeConst = 256)]
            string sysname;
            [MarshalAs (UnmanagedType.ByValTStr, SizeConst = 256)]
            string nodename;
            [MarshalAs (UnmanagedType.ByValTStr, SizeConst = 256)]
            string release;
            [MarshalAs (UnmanagedType.ByValTStr, SizeConst = 256)]
            string version;
            [MarshalAs (UnmanagedType.ByValTStr, SizeConst = 256)]
            string machine;

            public string? Sysname {
                get {
                    return sysname;
                }
            }
            public string? Nodename {
                get {
                    return nodename;
                }
            }
            public string? Release {
                get {
                    return release;
                }
            }
            public string? Version {
                get {
                    return version;
                }
            }
            public string? Machine {
                get {
                    return machine;
                }
            }
        }

		struct Dl_info {
			IntPtr dli_fname; /* Pathname of shared object */
			IntPtr dli_fbase; /* Base address of shared object */
			IntPtr dli_sname; /* Name of nearest symbol */
			IntPtr dli_saddr; /* Address of nearest symbol */

            public string? LibraryPath {
                get {
                    return Marshal.PtrToStringUTF8 (dli_fname);
                }
            }

            public IntPtr LibraryBaseAddress{
                get {
                    return dli_fbase;
                }
            }

            public string? NearestSymbol {
                get {
                    return Marshal.PtrToStringUTF8 (dli_sname);
                }
            }

            public IntPtr NearestSymbolAddress {
                get {
                    return dli_saddr;
                }
            }
		}

        static string GetUuid (IntPtr libraryLoadAddress, bool withDashes, out string architecture, out nuint librarySize)
        {
            librarySize = 0;
            architecture = "";

            if (libraryLoadAddress == IntPtr.Zero)
                return "<?>";

            using var reader = new MemoryReader (libraryLoadAddress);
            using var binaryReader = new BinaryReader (reader);
            var machoFile = new MachOFile ();
            machoFile.Read (binaryReader);
            architecture = machoFile.Architecture.ToString ().ToLowerInvariant ();
            librarySize = machoFile.sizeofcmds;
            var uuid = machoFile.load_commands.OfType<UuidCommand> ().FirstOrDefault ();
            return uuid?.AsString (withDashes).ToUpperInvariant () ?? string.Empty;
        }
    }

    class MemoryReader : Stream {
        IntPtr ptr;
        IntPtr current;

        public MemoryReader (IntPtr pointer)
        {
            this.ptr = pointer;
            this.current = ptr;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position {
            get => current - ptr;
            set => current = ptr + (nint) value;
        }

        public override void Flush()
        {
            throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            Marshal.Copy (current, buffer, offset, count);
            current += count;
            return count;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }
    }
}