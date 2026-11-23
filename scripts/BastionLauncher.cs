using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;

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

            if (!File.Exists(indexPath))
            {
                if (args != null && args.Length > 0 && args[0] == "--self-test")
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

            if (args != null && args.Length > 0 && args[0] == "--self-test")
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

                    string homeResponse = SendRawHttpGet(port, "/");
                    if (homeResponse.IndexOf("HTTP/1.1 200 OK", StringComparison.Ordinal) < 0 ||
                        homeResponse.IndexOf("Content-Security-Policy:", StringComparison.OrdinalIgnoreCase) < 0 ||
                        homeResponse.IndexOf("X-Frame-Options: DENY", StringComparison.OrdinalIgnoreCase) < 0 ||
                        homeResponse.IndexOf("Bastión", StringComparison.Ordinal) < 0)
                    {
                        return 1;
                    }

                    string traversalResponse = SendRawHttpGet(port, "/../package.json");
                    if (traversalResponse.IndexOf("HTTP/1.1 403 Forbidden", StringComparison.Ordinal) < 0)
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

        private static string SendRawHttpGet(int port, string path)
        {
            using (TcpClient client = new TcpClient())
            {
                client.ReceiveTimeout = 5000;
                client.SendTimeout = 5000;
                client.Connect(IPAddress.Loopback, port);
                using (NetworkStream stream = client.GetStream())
                {
                    string request = "GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1:" + port + "\r\nConnection: close\r\n\r\n";
                    byte[] reqBytes = Encoding.ASCII.GetBytes(request);
                    stream.Write(reqBytes, 0, reqBytes.Length);
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
        private readonly object _timeLock = new object();
        private DateTime _lastRequestUtc;
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
                lock (_timeLock)
                {
                    return _lastRequestUtc;
                }
            }
        }

        private void TouchRequestTime()
        {
            lock (_timeLock)
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
                using (StreamReader reader = new StreamReader(stream, Encoding.ASCII, false, 1024, true))
                {
                    string requestLine = reader.ReadLine();
                    if (string.IsNullOrEmpty(requestLine))
                    {
                        return;
                    }

                    int headerCount = 0;
                    string headerLine;
                    while ((headerLine = reader.ReadLine()) != null && headerLine.Length > 0 && headerCount < 64)
                    {
                        headerCount++;
                    }

                    string[] parts = requestLine.Split(' ');
                    if (parts.Length < 2)
                    {
                        WriteStatus(stream, 400, "Bad Request", "Bad Request", false);
                        return;
                    }

                    string method = parts[0].ToUpperInvariant();
                    if (method != "GET" && method != "HEAD")
                    {
                        WriteStatus(stream, 405, "Method Not Allowed", "Method Not Allowed", false);
                        return;
                    }

                    bool headOnly = (method == "HEAD");
                    string rawTarget = parts[1];
                    int queryIdx = rawTarget.IndexOf('?');
                    if (queryIdx >= 0)
                    {
                        rawTarget = rawTarget.Substring(0, queryIdx);
                    }

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
