
namespace Utilities {
    using System.Diagnostics;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Text;

    using Foundation;
    using ObjCRuntime;

    static class StackReport {
        public static string Create ()
        {
            var sb = new StringBuilder();
            sb.AppendLine("CreateStackReport");
            sb.AppendLine(Environment.StackTrace);

			var array = new IntPtr [512];
			var size = backtrace (array, array.Length);
            Array.Resize (ref array, size);

            var infos = new Dl_info [size];

            for (var i = 0; i < size; i++) {
                var rv = dladdr (array [i], out var info);
                infos [i] = info;

                var libname = info.LibraryPath is null ? "-" : Path.GetFileName (info.LibraryPath);
                sb.AppendLine ($"{i,3} {libname,-30} 0x{array[i]:x16} {info.NearestSymbol} + {(info.NearestSymbolAddress - array[i])} :LibBaseAddress=0x{info.LibraryBaseAddress:x}");
            }

            sb.AppendLine ();
            sb.AppendLine ($"Binary Images:");

            var libraryProcessed = new HashSet<string> ();
            foreach (var info in infos.OrderBy (v => v.LibraryBaseAddress)) {
                if (libraryProcessed.Contains (info.LibraryPath))
                    continue;
                libraryProcessed.Add (info.LibraryPath);

                sb.AppendLine ($"       0x{info.LibraryBaseAddress,16} - 0x00 {info.LibraryPath} (*) <UUID>{info.LibraryBaseAddress}");
            }

            return sb.ToString();
        }

		[DllImport (Constants.libcLibrary)]
		static extern int backtrace (IntPtr [] array, int size);

   		[DllImport (Constants.libcLibrary)]
		static extern int dladdr (IntPtr addr, out Dl_info info);

		struct Dl_info {
			IntPtr dli_fname; /* Pathname of shared object */
			IntPtr dli_fbase; /* Base address of shared object */
			IntPtr dli_sname; /* Name of nearest symbol */
			IntPtr dli_saddr; /* Address of nearest symbol */

            public string LibraryPath {
                get {
                    return Marshal.PtrToStringUTF8 (dli_fname);
                }
            }

            public IntPtr LibraryBaseAddress{
                get {
                    return dli_fbase;
                }
            }

            public string NearestSymbol {
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

    }
}