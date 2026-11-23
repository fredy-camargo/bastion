using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;

[assembly: AssemblyDescription("Bastion Desktop Launcher [FC-AGY-01]")]

namespace BastionDesktop
{
    internal static class Program
    {
        private const int DefaultPort = 4173;
        private const string MutexName = "Local\\BastionVaultDesktopLauncher";

        [STAThread]
        private static int Main(string[] args)
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string distDir = Path.GetFullPath(Path.Combine(baseDir, "dist"));
            string indexPath = Path.Combine(distDir, "index.html");

            bool isSelfTest = (args != null && args.Length > 0 && string.Equals(args[0], "--self-test", StringComparison.Ordinal));

            if (!File.Exists(indexPath))
            {
                if (isSelfTest)
                {
                    return 1;
                }
                MessageBox.Show(
                    "No se encontró la compilación de producción en:\n" + distDir + "\n\nEjecuta \"npm run build\" o \"scripts\\build-desktop.ps1\" antes de abrir Bastión.",
                    "Bastión — Compilación requerida",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
                return 1;
            }

            if (isSelfTest)
            {
                return RunSelfTest(distDir);
            }

            string browserPath = FindBrowserExecutable();
            if (string.IsNullOrEmpty(browserPath))
            {
                MessageBox.Show(
                    "No se encontró Microsoft Edge ni Google Chrome en este equipo.\nInstala uno de los dos navegadores para ejecutar Bastión en modo aislado.",
                    "Bastión — Navegador requerido",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
                return 1;
            }

            string profileDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Bastion",
                "Profile"
            );
            Directory.CreateDirectory(profileDir);

            bool createdNew = false;
            Mutex instanceMutex = null;
            try
            {
                instanceMutex = new Mutex(true, MutexName, out createdNew);
                if (!createdNew)
                {
                    LaunchBrowserWindow(browserPath, profileDir);
                    return 0;
                }

                using (StaticVaultServer server = new StaticVaultServer(distDir, DefaultPort))
                {
                    try
                    {
                        server.Start();
                    }
                    catch (SocketException ex)
                    {
                        MessageBox.Show(
                            "No se pudo iniciar el servidor local seguro en 127.0.0.1:" + DefaultPort + ".\nDetalle: " + ex.Message,
                            "Bastión — Puerto ocupado",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Error
                        );
                        return 1;
                    }

                    using (BastionAppContext context = new BastionAppContext(server, browserPath, profileDir))
                    {
                        Application.Run(context);
                    }
                }
            }
            finally
            {
                if (instanceMutex != null)
                {
                    if (createdNew)
                    {
                        try
                        {
                            instanceMutex.ReleaseMutex();
                        }
                        catch
                        {
                        }
                    }
                    instanceMutex.Dispose();
                }
            }

            return 0;
        }

        private static int RunSelfTest(string distDir)
        {
            try
            {
                using (StaticVaultServer server = new StaticVaultServer(distDir, 0))
                {
                    server.Start();
                    int port = server.Port;

                    string homeResponse = SendRawHttp(port, "GET", "/", null, null);
                    if (homeResponse.IndexOf("HTTP/1.1 200 OK", StringComparison.Ordinal) < 0 ||
                        homeResponse.IndexOf("Content-Security-Policy:", StringComparison.OrdinalIgnoreCase) < 0 ||
                        homeResponse.IndexOf("X-Frame-Options: DENY", StringComparison.OrdinalIgnoreCase) < 0 ||
                        homeResponse.IndexOf("Bastión", StringComparison.Ordinal) < 0)
                    {
                        return 1;
                    }

                    string traversalResponse = SendRawHttp(port, "GET", "/../package.json", null, null);
                    if (traversalResponse.IndexOf("HTTP/1.1 403 Forbidden", StringComparison.Ordinal) < 0)
                    {
                        return 1;
                    }

                    // Anti-CSRF check 1: missing Origin / X-Bastion-Desktop
                    string csrfNoHeaders = SendRawHttp(port, "POST", "/__bastion/clipboard/clear", null, "");
                    if (csrfNoHeaders.IndexOf("HTTP/1.1 403 Forbidden", StringComparison.Ordinal) < 0)
                    {
                        return 1;
                    }

                    // Anti-CSRF check 2: evil Origin
                    Dictionary<string, string> evilHeaders = new Dictionary<string, string>();
                    evilHeaders["Origin"] = "https://evil.example";
                    evilHeaders["X-Bastion-Desktop"] = "1";
                    string csrfEvilOrigin = SendRawHttp(port, "POST", "/__bastion/clipboard/clear", evilHeaders, "");
                    if (csrfEvilOrigin.IndexOf("HTTP/1.1 403 Forbidden", StringComparison.Ordinal) < 0)
                    {
                        return 1;
                    }

                    // Valid native clipboard copy & clear
                    Dictionary<string, string> validHeaders = new Dictionary<string, string>();
                    validHeaders["Origin"] = "http://127.0.0.1:" + port;
                    validHeaders["X-Bastion-Desktop"] = "1";
                    validHeaders["Sec-Fetch-Site"] = "same-origin";

                    string copyOk = SendRawHttp(port, "POST", "/__bastion/clipboard/copy", validHeaders, "bastion-selftest-token");
                    if (copyOk.IndexOf("HTTP/1.1 200 OK", StringComparison.Ordinal) < 0 ||
                        copyOk.IndexOf("\"ok\":true", StringComparison.Ordinal) < 0)
                    {
                        return 1;
                    }

                    string clearOk = SendRawHttp(port, "POST", "/__bastion/clipboard/clear", validHeaders, "");
                    if (clearOk.IndexOf("HTTP/1.1 200 OK", StringComparison.Ordinal) < 0 ||
                        clearOk.IndexOf("\"cleared\":true", StringComparison.Ordinal) < 0)
                    {
                        return 1;
                    }
                }
                return 0;
            }
            catch
            {
                return 1;
            }
        }

        private static string SendRawHttp(int port, string method, string path, Dictionary<string, string> extraHeaders, string bodyText)
        {
            using (TcpClient client = new TcpClient())
            {
                client.ReceiveTimeout = 5000;
                client.SendTimeout = 5000;
                client.Connect(IPAddress.Loopback, port);
                using (NetworkStream stream = client.GetStream())
                {
                    byte[] bodyBytes = string.IsNullOrEmpty(bodyText) ? new byte[0] : Encoding.UTF8.GetBytes(bodyText);
                    StringBuilder sb = new StringBuilder();
                    sb.Append(method).Append(' ').Append(path).Append(" HTTP/1.1\r\n");
                    sb.Append("Host: 127.0.0.1:").Append(port).Append("\r\n");
                    if (extraHeaders != null)
                    {
                        foreach (KeyValuePair<string, string> kv in extraHeaders)
                        {
                            sb.Append(kv.Key).Append(": ").Append(kv.Value).Append("\r\n");
                        }
                    }
                    if (method == "POST")
                    {
                        sb.Append("Content-Type: text/plain; charset=utf-8\r\n");
                        sb.Append("Content-Length: ").Append(bodyBytes.Length).Append("\r\n");
                    }
                    sb.Append("Connection: close\r\n\r\n");

                    byte[] headBytes = Encoding.ASCII.GetBytes(sb.ToString());
                    stream.Write(headBytes, 0, headBytes.Length);
                    if (bodyBytes.Length > 0)
                    {
                        stream.Write(bodyBytes, 0, bodyBytes.Length);
                    }
                    stream.Flush();

                    using (MemoryStream ms = new MemoryStream())
                    {
                        byte[] buffer = new byte[4096];
                        int read;
                        while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            ms.Write(buffer, 0, read);
                        }
                        return Encoding.UTF8.GetString(ms.ToArray());
                    }
                }
            }
        }

        internal static Process LaunchBrowserWindow(string browserPath, string profileDir)
        {
            string url = "http://127.0.0.1:" + DefaultPort + "/";
            string arguments =
                "--app=\"" + url + "\" " +
                "--user-data-dir=\"" + profileDir + "\" " +
                "--disable-extensions " +
                "--disable-background-mode " +
                "--no-first-run " +
                "--no-default-browser-check " +
                "--window-size=1280,820";

            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = browserPath;
            startInfo.Arguments = arguments;
            startInfo.UseShellExecute = false;
            return Process.Start(startInfo);
        }

        private static string FindBrowserExecutable()
        {
            string programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

            string[] candidates = new string[]
            {
                Path.Combine(programFilesX86, "Microsoft", "Edge", "Application", "msedge.exe"),
                Path.Combine(programFiles, "Microsoft", "Edge", "Application", "msedge.exe"),
                Path.Combine(localAppData, "Microsoft", "Edge", "Application", "msedge.exe"),
                Path.Combine(programFiles, "Google", "Chrome", "Application", "chrome.exe"),
                Path.Combine(programFilesX86, "Google", "Chrome", "Application", "chrome.exe"),
                Path.Combine(localAppData, "Google", "Chrome", "Application", "chrome.exe")
            };

            for (int i = 0; i < candidates.Length; i++)
            {
                if (!string.IsNullOrEmpty(candidates[i]) && File.Exists(candidates[i]))
                {
                    return candidates[i];
                }
            }
            return null;
        }
    }

    internal static class NativeClipboard
    {
        private const uint CF_UNICODETEXT = 13;
        private const uint GMEM_MOVEABLE = 0x0002;
        private const uint GMEM_ZEROINIT = 0x0040;
        private static readonly object ClipboardLock = new object();

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool OpenClipboard(IntPtr hWndNewOwner);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool CloseClipboard();

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool EmptyClipboard();

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr SetClipboardData(uint uFormat, IntPtr hMem);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint RegisterClipboardFormat(string lpszFormat);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GlobalAlloc(uint uFlags, UIntPtr dwBytes);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GlobalLock(IntPtr hMem);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GlobalUnlock(IntPtr hMem);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GlobalFree(IntPtr hMem);

        private static bool OpenWithRetry()
        {
            for (int attempt = 0; attempt < 12; attempt++)
            {
                if (OpenClipboard(IntPtr.Zero))
                {
                    return true;
                }
                Thread.Sleep(25);
            }
            return false;
        }

        private static void SetDwordFormat(string formatName, int value)
        {
            uint formatId = RegisterClipboardFormat(formatName);
            if (formatId == 0)
            {
                return;
            }

            IntPtr hMem = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, new UIntPtr(4));
            if (hMem == IntPtr.Zero)
            {
                return;
            }

            IntPtr ptr = GlobalLock(hMem);
            if (ptr == IntPtr.Zero)
            {
                GlobalFree(hMem);
                return;
            }

            try
            {
                Marshal.WriteInt32(ptr, value);
            }
            finally
            {
                GlobalUnlock(hMem);
            }

            if (SetClipboardData(formatId, hMem) == IntPtr.Zero)
            {
                GlobalFree(hMem);
            }
        }

        public static bool SetSensitiveText(string text)
        {
            string safeText = text ?? string.Empty;
            char[] chars = safeText.ToCharArray();

            lock (ClipboardLock)
            {
                bool opened = false;
                try
                {
                    opened = OpenWithRetry();
                    if (!opened)
                    {
                        return false;
                    }

                    if (!EmptyClipboard())
                    {
                        return false;
                    }

                    UIntPtr byteCount = new UIntPtr((uint)((chars.Length + 1) * 2));
                    IntPtr hGlobal = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, byteCount);
                    if (hGlobal == IntPtr.Zero)
                    {
                        return false;
                    }

                    IntPtr ptr = GlobalLock(hGlobal);
                    if (ptr == IntPtr.Zero)
                    {
                        GlobalFree(hGlobal);
                        return false;
                    }

                    try
                    {
                        if (chars.Length > 0)
                        {
                            Marshal.Copy(chars, 0, ptr, chars.Length);
                        }
                    }
                    finally
                    {
                        GlobalUnlock(hGlobal);
                    }

                    if (SetClipboardData(CF_UNICODETEXT, hGlobal) == IntPtr.Zero)
                    {
                        GlobalFree(hGlobal);
                        return false;
                    }

                    // Prevent Windows Clipboard History (Win+V), Cloud Sync, and monitors from capturing secrets
                    SetDwordFormat("ExcludeClipboardContentFromMonitorProcessing", 1);
                    SetDwordFormat("CanIncludeInClipboardHistory", 0);
                    SetDwordFormat("CanUploadToCloudClipboard", 0);

                    return true;
                }
                finally
                {
                    Array.Clear(chars, 0, chars.Length);
                    if (opened)
                    {
                        CloseClipboard();
                    }
                }
            }
        }

        public static bool Clear()
        {
            lock (ClipboardLock)
            {
                bool opened = false;
                try
                {
                    opened = OpenWithRetry();
                    if (!opened)
                    {
                        return false;
                    }
                    return EmptyClipboard();
                }
                finally
                {
                    if (opened)
                    {
                        CloseClipboard();
                    }
                }
            }
        }
    }

    internal sealed class BastionAppContext : ApplicationContext
    {
        private readonly StaticVaultServer _server;
        private readonly string _browserPath;
        private readonly string _profileDir;
        private readonly NotifyIcon _trayIcon;
        private readonly System.Windows.Forms.Timer _watchdogTimer;
        private readonly DateTime _startedUtc;
        private bool _windowSeen;
        private int _missingWindowTicks;
        private bool _exiting;

        public BastionAppContext(StaticVaultServer server, string browserPath, string profileDir)
        {
            _server = server;
            _browserPath = browserPath;
            _profileDir = profileDir;
            _startedUtc = DateTime.UtcNow;

            ContextMenuStrip menu = new ContextMenuStrip();
            ToolStripMenuItem openItem = new ToolStripMenuItem("Abrir Bastión");
            openItem.Click += new EventHandler(OnOpenClicked);
            ToolStripMenuItem exitItem = new ToolStripMenuItem("Salir de Bastión");
            exitItem.Click += new EventHandler(OnExitClicked);
            menu.Items.Add(openItem);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(exitItem);

            _trayIcon = new NotifyIcon();
            _trayIcon.Text = "Bastión — Bóveda Criptográfica Local (127.0.0.1:4173)";
            _trayIcon.ContextMenuStrip = menu;
            _trayIcon.DoubleClick += new EventHandler(OnOpenClicked);
            try
            {
                _trayIcon.Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
            }
            catch
            {
                _trayIcon.Icon = SystemIcons.Shield;
            }
            _trayIcon.Visible = true;

            Process proc = Program.LaunchBrowserWindow(_browserPath, _profileDir);
            if (proc != null)
            {
                proc.Dispose();
            }
            else
            {
                MessageBox.Show(
                    "No se pudo iniciar la ventana aislada de Bastión.",
                    "Bastión — Error de arranque",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
                Shutdown();
                return;
            }

            _watchdogTimer = new System.Windows.Forms.Timer();
            _watchdogTimer.Interval = 1500;
            _watchdogTimer.Tick += new EventHandler(OnWatchdogTick);
            _watchdogTimer.Start();
        }

        private void OnOpenClicked(object sender, EventArgs e)
        {
            Process proc = Program.LaunchBrowserWindow(_browserPath, _profileDir);
            if (proc != null)
            {
                proc.Dispose();
            }
        }

        private void OnExitClicked(object sender, EventArgs e)
        {
            Shutdown();
        }

        private void OnWatchdogTick(object sender, EventArgs e)
        {
            if (_exiting)
            {
                return;
            }

            bool hasWindow = WindowDetector.IsBastionWindowOpen();
            if (hasWindow)
            {
                _windowSeen = true;
                _missingWindowTicks = 0;
                return;
            }

            double secondsSinceStart = (DateTime.UtcNow - _startedUtc).TotalSeconds;
            double secondsSinceRequest = (DateTime.UtcNow - _server.LastRequestUtc).TotalSeconds;

            if (_windowSeen)
            {
                _missingWindowTicks++;
                if (_missingWindowTicks >= 2 && secondsSinceRequest >= 3.0)
                {
                    Shutdown();
                }
                return;
            }

            if (secondsSinceStart >= 30.0 && secondsSinceRequest >= 10.0)
            {
                Shutdown();
            }
        }

        private void Shutdown()
        {
            if (_exiting)
            {
                return;
            }
            _exiting = true;

            if (_server != null && _server.HasCopiedSecret)
            {
                NativeClipboard.Clear();
                _server.ClearCopiedSecretFlag();
            }

            if (_watchdogTimer != null)
            {
                _watchdogTimer.Stop();
                _watchdogTimer.Dispose();
            }

            if (_trayIcon != null)
            {
                _trayIcon.Visible = false;
                _trayIcon.Dispose();
            }

            _server.Dispose();
            ExitThread();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_watchdogTimer != null)
                {
                    _watchdogTimer.Stop();
                    _watchdogTimer.Dispose();
                }
                if (_trayIcon != null)
                {
                    _trayIcon.Visible = false;
                    _trayIcon.Dispose();
                }
            }
            base.Dispose(disposing);
        }
    }

    internal static class WindowDetector
    {
        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

        public static bool IsBastionWindowOpen()
        {
            bool found = false;
            EnumWindows(delegate(IntPtr hWnd, IntPtr lParam)
            {
                if (!IsWindowVisible(hWnd))
                {
                    return true;
                }

                StringBuilder classBuilder = new StringBuilder(128);
                GetClassName(hWnd, classBuilder, classBuilder.Capacity);
                string className = classBuilder.ToString();
                if (!string.Equals(className, "Chrome_WidgetWin_1", StringComparison.Ordinal))
                {
                    return true;
                }

                StringBuilder titleBuilder = new StringBuilder(256);
                GetWindowText(hWnd, titleBuilder, titleBuilder.Capacity);
                string title = titleBuilder.ToString();
                if (title.StartsWith("Bastión", StringComparison.OrdinalIgnoreCase) ||
                    title.IndexOf("127.0.0.1", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    found = true;
                    return false;
                }

                return true;
            }, IntPtr.Zero);
            return found;
        }
    }

    internal sealed class StaticVaultServer : IDisposable
    {
        private const int MaxHeaderBytes = 16384;
        private const int MaxClipboardBodyBytes = 65536;

        private static readonly Dictionary<string, string> MimeTypes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { ".html", "text/html; charset=utf-8" },
            { ".js", "application/javascript; charset=utf-8" },
            { ".mjs", "application/javascript; charset=utf-8" },
            { ".css", "text/css; charset=utf-8" },
            { ".svg", "image/svg+xml" },
            { ".png", "image/png" },
            { ".ico", "image/x-icon" },
            { ".json", "application/json; charset=utf-8" },
            { ".webmanifest", "application/manifest+json; charset=utf-8" },
            { ".woff", "font/woff" },
            { ".woff2", "font/woff2" }
        };

        private readonly string _distDir;
        private readonly string _distRootWithSep;
        private readonly TcpListener _listener;
        private readonly object _stateLock = new object();
        private DateTime _lastRequestUtc;
        private bool _hasCopiedSecret;
        private Thread _acceptThread;
        private volatile bool _running;

        public StaticVaultServer(string distDir, int port)
        {
            _distDir = Path.GetFullPath(distDir);
            _distRootWithSep = _distDir.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
                ? _distDir
                : _distDir + Path.DirectorySeparatorChar;
            _listener = new TcpListener(IPAddress.Loopback, port);
            _lastRequestUtc = DateTime.UtcNow;
        }

        public int Port
        {
            get { return ((IPEndPoint)_listener.LocalEndpoint).Port; }
        }

        public DateTime LastRequestUtc
        {
            get
            {
                lock (_stateLock)
                {
                    return _lastRequestUtc;
                }
            }
        }

        public bool HasCopiedSecret
        {
            get
            {
                lock (_stateLock)
                {
                    return _hasCopiedSecret;
                }
            }
        }

        public void ClearCopiedSecretFlag()
        {
            lock (_stateLock)
            {
                _hasCopiedSecret = false;
            }
        }

        private void SetCopiedSecretFlag(bool value)
        {
            lock (_stateLock)
            {
                _hasCopiedSecret = value;
            }
        }

        private void TouchRequestTime()
        {
            lock (_stateLock)
            {
                _lastRequestUtc = DateTime.UtcNow;
            }
        }

        public void Start()
        {
            _listener.Start();
            _running = true;
            _acceptThread = new Thread(AcceptLoop);
            _acceptThread.IsBackground = true;
            _acceptThread.Name = "BastionHttpLoop";
            _acceptThread.Start();
        }

        private void AcceptLoop()
        {
            while (_running)
            {
                try
                {
                    TcpClient client = _listener.AcceptTcpClient();
                    ThreadPool.QueueUserWorkItem(HandleClient, client);
                }
                catch (SocketException)
                {
                    if (!_running) break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
            }
        }

        private void HandleClient(object state)
        {
            TcpClient client = (TcpClient)state;
            TouchRequestTime();
            try
            {
                client.ReceiveTimeout = 5000;
                client.SendTimeout = 10000;
                using (NetworkStream stream = client.GetStream())
                {
                    byte[] headerBuffer;
                    byte[] leftoverBody;
                    if (!ReadHeaderBlock(stream, out headerBuffer, out leftoverBody))
                    {
                        return;
                    }

                    string headerText = Encoding.ASCII.GetString(headerBuffer);
                    string[] lines = headerText.Split(new string[] { "\r\n" }, StringSplitOptions.None);
                    if (lines.Length == 0 || string.IsNullOrEmpty(lines[0]))
                    {
                        WriteStatus(stream, 400, "Bad Request", "Bad Request", false);
                        return;
                    }

                    string[] parts = lines[0].Split(' ');
                    if (parts.Length < 2)
                    {
                        WriteStatus(stream, 400, "Bad Request", "Bad Request", false);
                        return;
                    }

                    string method = parts[0].ToUpperInvariant();
                    string rawTarget = parts[1];
                    int queryIdx = rawTarget.IndexOf('?');
                    if (queryIdx >= 0)
                    {
                        rawTarget = rawTarget.Substring(0, queryIdx);
                    }

                    Dictionary<string, string> reqHeaders = ParseHeaders(lines);

                    if (string.Equals(rawTarget, "/__bastion/clipboard/copy", StringComparison.Ordinal) ||
                        string.Equals(rawTarget, "/__bastion/clipboard/clear", StringComparison.Ordinal))
                    {
                        HandleClipboardEndpoint(stream, method, rawTarget, reqHeaders, leftoverBody);
                        return;
                    }

                    if (method != "GET" && method != "HEAD")
                    {
                        WriteStatus(stream, 405, "Method Not Allowed", "Method Not Allowed", false);
                        return;
                    }

                    bool headOnly = (method == "HEAD");
                    string decodedPath;
                    try
                    {
                        decodedPath = Uri.UnescapeDataString(rawTarget);
                    }
                    catch
                    {
                        WriteStatus(stream, 400, "Bad Request", "Invalid URI", headOnly);
                        return;
                    }

                    if (decodedPath.IndexOf('\0') >= 0 || decodedPath.IndexOf("..", StringComparison.Ordinal) >= 0)
                    {
                        WriteStatus(stream, 403, "Forbidden", "Forbidden", headOnly);
                        return;
                    }

                    string relativePath = decodedPath.TrimStart('/').Replace('/', Path.DirectorySeparatorChar);
                    if (string.IsNullOrEmpty(relativePath))
                    {
                        relativePath = "index.html";
                    }

                    string candidatePath = Path.GetFullPath(Path.Combine(_distDir, relativePath));
                    if (!candidatePath.StartsWith(_distRootWithSep, StringComparison.OrdinalIgnoreCase))
                    {
                        WriteStatus(stream, 403, "Forbidden", "Forbidden", headOnly);
                        return;
                    }

                    if (!File.Exists(candidatePath))
                    {
                        if (!Path.HasExtension(candidatePath))
                        {
                            candidatePath = Path.Combine(_distDir, "index.html");
                        }
                        else
                        {
                            WriteStatus(stream, 404, "Not Found", "Not Found", headOnly);
                            return;
                        }
                    }

                    byte[] body = File.ReadAllBytes(candidatePath);
                    string ext = Path.GetExtension(candidatePath);
                    string contentType;
                    if (!MimeTypes.TryGetValue(ext, out contentType))
                    {
                        contentType = "application/octet-stream";
                    }

                    string cacheControl = "no-cache";
                    if (string.Equals(ext, ".html", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(Path.GetFileName(candidatePath), "sw.js", StringComparison.OrdinalIgnoreCase))
                    {
                        cacheControl = "no-store";
                    }
                    else if (decodedPath.StartsWith("/assets/", StringComparison.OrdinalIgnoreCase))
                    {
                        cacheControl = "public, max-age=31536000, immutable";
                    }

                    WriteResponse(stream, 200, "OK", contentType, cacheControl, body, headOnly);
                }
            }
            catch
            {
            }
            finally
            {
                try
                {
                    client.Close();
                }
                catch
                {
                }
            }
        }

        private void HandleClipboardEndpoint(
            NetworkStream stream,
            string method,
            string route,
            Dictionary<string, string> reqHeaders,
            byte[] leftoverBody)
        {
            if (method != "POST")
            {
                WriteJsonStatus(stream, 405, "Method Not Allowed", "{\"error\":\"method_not_allowed\"}");
                return;
            }

            if (!IsTrustedDesktopRequest(reqHeaders))
            {
                WriteJsonStatus(stream, 403, "Forbidden", "{\"error\":\"forbidden\"}");
                return;
            }

            if (string.Equals(route, "/__bastion/clipboard/clear", StringComparison.Ordinal))
            {
                bool cleared = NativeClipboard.Clear();
                if (cleared)
                {
                    SetCopiedSecretFlag(false);
                    WriteJsonStatus(stream, 200, "OK", "{\"cleared\":true}");
                }
                else
                {
                    WriteJsonStatus(stream, 503, "Service Unavailable", "{\"cleared\":false}");
                }
                return;
            }

            string lenHeader;
            int contentLength = 0;
            if (!reqHeaders.TryGetValue("Content-Length", out lenHeader) ||
                !int.TryParse(lenHeader, NumberStyles.Integer, CultureInfo.InvariantCulture, out contentLength) ||
                contentLength < 0)
            {
                WriteJsonStatus(stream, 400, "Bad Request", "{\"error\":\"invalid_content_length\"}");
                return;
            }

            if (contentLength > MaxClipboardBodyBytes)
            {
                WriteJsonStatus(stream, 413, "Payload Too Large", "{\"error\":\"payload_too_large\"}");
                return;
            }

            byte[] bodyBytes = new byte[contentLength];
            try
            {
                int copied = 0;
                if (leftoverBody != null && leftoverBody.Length > 0)
                {
                    copied = Math.Min(contentLength, leftoverBody.Length);
                    Buffer.BlockCopy(leftoverBody, 0, bodyBytes, 0, copied);
                    Array.Clear(leftoverBody, 0, leftoverBody.Length);
                }

                while (copied < contentLength)
                {
                    int read = stream.Read(bodyBytes, copied, contentLength - copied);
                    if (read <= 0)
                    {
                        WriteJsonStatus(stream, 400, "Bad Request", "{\"error\":\"incomplete_body\"}");
                        return;
                    }
                    copied += read;
                }

                string secretText = Encoding.UTF8.GetString(bodyBytes);
                bool ok = NativeClipboard.SetSensitiveText(secretText);
                if (ok)
                {
                    SetCopiedSecretFlag(true);
                    WriteJsonStatus(stream, 200, "OK", "{\"ok\":true}");
                }
                else
                {
                    WriteJsonStatus(stream, 503, "Service Unavailable", "{\"ok\":false}");
                }
            }
            finally
            {
                Array.Clear(bodyBytes, 0, bodyBytes.Length);
            }
        }

        private bool IsTrustedDesktopRequest(Dictionary<string, string> headers)
        {
            string expectedHost = "127.0.0.1:" + this.Port.ToString(CultureInfo.InvariantCulture);
            string expectedOrigin = "http://" + expectedHost;

            string host;
            if (!headers.TryGetValue("Host", out host) || !string.Equals(host, expectedHost, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            string origin;
            if (!headers.TryGetValue("Origin", out origin) || !string.Equals(origin, expectedOrigin, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            string marker;
            if (!headers.TryGetValue("X-Bastion-Desktop", out marker) || !string.Equals(marker, "1", StringComparison.Ordinal))
            {
                return false;
            }

            string secFetchSite;
            if (headers.TryGetValue("Sec-Fetch-Site", out secFetchSite) &&
                !string.Equals(secFetchSite, "same-origin", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return true;
        }

        private static bool ReadHeaderBlock(NetworkStream stream, out byte[] headerBytes, out byte[] leftoverBody)
        {
            headerBytes = null;
            leftoverBody = null;

            byte[] buffer = new byte[MaxHeaderBytes];
            int totalRead = 0;

            while (totalRead < MaxHeaderBytes)
            {
                int read = stream.Read(buffer, totalRead, MaxHeaderBytes - totalRead);
                if (read <= 0)
                {
                    break;
                }
                totalRead += read;

                int endIdx = FindHeaderEnd(buffer, totalRead);
                if (endIdx >= 0)
                {
                    headerBytes = new byte[endIdx];
                    Buffer.BlockCopy(buffer, 0, headerBytes, 0, endIdx);

                    int bodyStart = endIdx + 4;
                    int leftoverCount = totalRead - bodyStart;
                    leftoverBody = new byte[leftoverCount];
                    if (leftoverCount > 0)
                    {
                        Buffer.BlockCopy(buffer, bodyStart, leftoverBody, 0, leftoverCount);
                    }
                    Array.Clear(buffer, 0, totalRead);
                    return true;
                }
            }

            Array.Clear(buffer, 0, totalRead);
            return false;
        }

        private static int FindHeaderEnd(byte[] buffer, int length)
        {
            for (int i = 0; i <= length - 4; i++)
            {
                if (buffer[i] == 13 && buffer[i + 1] == 10 && buffer[i + 2] == 13 && buffer[i + 3] == 10)
                {
                    return i;
                }
            }
            return -1;
        }

        private static Dictionary<string, string> ParseHeaders(string[] lines)
        {
            Dictionary<string, string> headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 1; i < lines.Length && i <= 64; i++)
            {
                string line = lines[i];
                if (string.IsNullOrEmpty(line))
                {
                    continue;
                }
                int colon = line.IndexOf(':');
                if (colon <= 0)
                {
                    continue;
                }
                string name = line.Substring(0, colon).Trim();
                string value = line.Substring(colon + 1).Trim();
                headers[name] = value;
            }
            return headers;
        }

        private static void WriteJsonStatus(NetworkStream stream, int statusCode, string reason, string json)
        {
            byte[] body = Encoding.UTF8.GetBytes(json);
            WriteResponse(stream, statusCode, reason, "application/json; charset=utf-8", "no-store", body, false);
        }

        private static void WriteStatus(NetworkStream stream, int statusCode, string reason, string text, bool headOnly)
        {
            byte[] body = Encoding.UTF8.GetBytes(text);
            WriteResponse(stream, statusCode, reason, "text/plain; charset=utf-8", "no-store", body, headOnly);
        }

        private static void WriteResponse(
            NetworkStream stream,
            int statusCode,
            string reason,
            string contentType,
            string cacheControl,
            byte[] body,
            bool headOnly)
        {
            StringBuilder headers = new StringBuilder();
            headers.Append("HTTP/1.1 ").Append(statusCode).Append(' ').Append(reason).Append("\r\n");
            headers.Append("Content-Type: ").Append(contentType).Append("\r\n");
            headers.Append("Content-Length: ").Append(body.Length).Append("\r\n");
            headers.Append("Cache-Control: ").Append(cacheControl).Append("\r\n");
            headers.Append("X-Content-Type-Options: nosniff\r\n");
            headers.Append("X-Frame-Options: DENY\r\n");
            headers.Append("Referrer-Policy: no-referrer\r\n");
            headers.Append("Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()\r\n");
            headers.Append("Cross-Origin-Opener-Policy: same-origin\r\n");
            headers.Append("Cross-Origin-Resource-Policy: same-origin\r\n");
            headers.Append("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; worker-src 'self'; manifest-src 'self'; object-src 'none'; frame-src 'none'; frame-ancestors 'none'; media-src 'none'; base-uri 'self'; form-action 'none';\r\n");
            headers.Append("Connection: close\r\n\r\n");

            byte[] headerBytes = Encoding.ASCII.GetBytes(headers.ToString());
            stream.Write(headerBytes, 0, headerBytes.Length);
            if (!headOnly && body.Length > 0)
            {
                stream.Write(body, 0, body.Length);
            }
            stream.Flush();
        }

        public void Dispose()
        {
            _running = false;
            try
            {
                _listener.Stop();
            }
            catch
            {
            }
        }
    }
}
