using BridgeToFreedom.Services;
using System.Text;
using System.Web;

namespace BridgeToFreedom;

public partial class MainPage : ContentPage
{
    private readonly TunnelService _tunnel;
    private readonly StringBuilder _logBuffer = new();
    private bool _isRunning;

    public bool IsNotRunning => !_isRunning;

    public MainPage(TunnelService tunnel)
    {
        InitializeComponent();
        BindingContext = this;
        _tunnel = tunnel;
        _tunnel.OnLog += OnTunnelLog;
        _tunnel.OnProbeStatusChanged += OnProbeStatusChanged;

        // Load saved settings
        BridgeUrlEntry.Text = Preferences.Default.Get("BridgeUrl", "wss://");
        LoadSecrets();
        ListenAddressEntry.Text = Preferences.Default.Get("ListenAddress", "127.123.45.67");
        ListenPortEntry.Text = Preferences.Default.Get("ListenPort", "5080");
        RelaySwitch.IsToggled = Preferences.Default.Get("Relay", false);
        CoalesceSwitch.IsToggled = Preferences.Default.Get("WriteCoalescing", false);

        // Restore UI state if tunnel is already running (e.g. after activity recreate from background)
        if (_tunnel.IsRunning)
        {
            _isRunning = true;
            ConnectButton.Text = "DISCONNECT";
            ConnectButton.BackgroundColor = Color.FromArgb("#D32F2F");
            OnPropertyChanged(nameof(IsNotRunning));
            _tunnel.OnStopped += OnTunnelStopped;
            AddLog("[resumed — tunnel is running in background]");
        }
    }

    // Secrets live in the platform keystore (SecureStorage) instead of plain
    // Preferences. SecureStorage isn't implemented on every head (e.g. the
    // Linux GTK preview), so fall back to Preferences there. Values saved in
    // Preferences by older versions are migrated on first load.
    private const string KeyAuth = "AuthToken";
    private const string KeyE2E = "E2EKey";

    private async void LoadSecrets()
    {
        AuthTokenEntry.Text = await ReadSecret(KeyAuth);
        E2EKeyEntry.Text = await ReadSecret(KeyE2E);
    }

    private static async Task<string> ReadSecret(string key)
    {
        try
        {
            var v = await SecureStorage.Default.GetAsync(key);
            if (!string.IsNullOrEmpty(v)) return v;
            var legacy = Preferences.Default.Get(key, "");
            if (!string.IsNullOrEmpty(legacy))
            {
                await SecureStorage.Default.SetAsync(key, legacy);
                Preferences.Default.Remove(key);
            }
            return legacy;
        }
        catch
        {
            return Preferences.Default.Get(key, "");
        }
    }

    private static async Task WriteSecret(string key, string value)
    {
        try
        {
            if (string.IsNullOrEmpty(value)) SecureStorage.Default.Remove(key);
            else await SecureStorage.Default.SetAsync(key, value);
            Preferences.Default.Remove(key);
        }
        catch
        {
            Preferences.Default.Set(key, value);
        }
    }

    private async void OnExportClicked(object? sender, EventArgs e)
    {
        try
        {
            var url = BridgeUrlEntry.Text?.Trim() ?? "";
            if (!url.StartsWith("wss://"))
            {
                await DisplayAlertAsync("Error", "Bridge URL must start with wss://", "OK");
                return;
            }

            // btf://host/path?token=X&listen=addr:port&relay=1
            var bridgeUri = new Uri(url);
            var qs = HttpUtility.ParseQueryString("");
            qs["token"] = AuthTokenEntry.Text?.Trim() ?? "";
            var e2e = E2EKeyEntry.Text?.Trim() ?? "";
            if (e2e != "") qs["e2e"] = e2e;
            qs["listen"] = $"{ListenAddressEntry.Text?.Trim()}:{ListenPortEntry.Text?.Trim()}";
            if (RelaySwitch.IsToggled) qs["relay"] = "1";
            if (CoalesceSwitch.IsToggled) qs["coalesce"] = "1";

            var btfUrl = $"btf://{bridgeUri.Host}{bridgeUri.AbsolutePath}?{qs}";
            await Clipboard.Default.SetTextAsync(btfUrl);
            AddLog("Config exported to clipboard. It contains your secrets — share it only over a private channel and clear the clipboard afterwards.");
        }
        catch (Exception ex)
        {
            AddLog($"Export failed: {ex.Message}");
        }
    }

    private async void OnImportClicked(object? sender, EventArgs e)
    {
        try
        {
            var text = await Clipboard.Default.GetTextAsync();
            if (string.IsNullOrWhiteSpace(text) || !text.StartsWith("btf://"))
            {
                await DisplayAlertAsync("Import", "No btf:// URL found in clipboard", "OK");
                return;
            }

            // btf://host/path?token=X&listen=addr:port&relay=1  ->  wss://host/path
            var uri = new Uri(text);
            var qs = HttpUtility.ParseQueryString(uri.Query);

            BridgeUrlEntry.Text = $"wss://{uri.Host}{uri.AbsolutePath}";
            AuthTokenEntry.Text = qs["token"] ?? "";
            E2EKeyEntry.Text = qs["e2e"] ?? "";

            var listen = qs["listen"] ?? "";
            var colonIdx = listen.LastIndexOf(':');
            if (colonIdx > 0)
            {
                ListenAddressEntry.Text = listen[..colonIdx];
                ListenPortEntry.Text = listen[(colonIdx + 1)..];
            }

            RelaySwitch.IsToggled = qs["relay"] == "1";
            CoalesceSwitch.IsToggled = qs["coalesce"] == "1";
            AddLog("Config imported from clipboard");
        }
        catch (Exception ex)
        {
            AddLog($"Import failed: {ex.Message}");
        }
    }

    private async void OnConnectClicked(object? sender, EventArgs e)
    {
        if (_isRunning)
        {
            // Stop — this triggers OnDestroy in the service which calls Tunnel.Stop()
            StopPlatformService();
            _tunnel.Stop();
            _isRunning = false;
            ConnectButton.Text = "CONNECT";
            ConnectButton.BackgroundColor = Color.FromArgb("#512BD4");
            OnPropertyChanged(nameof(IsNotRunning));
            AddLog("Stopped by user.");
            return;
        }

        // Validate
        var url = BridgeUrlEntry.Text?.Trim();
        var token = AuthTokenEntry.Text?.Trim();
        var e2eKey = E2EKeyEntry.Text?.Trim() ?? "";
        var addr = ListenAddressEntry.Text?.Trim();
        var portStr = ListenPortEntry.Text?.Trim();

        if (string.IsNullOrEmpty(url) || !url.StartsWith("wss://"))
        {
            await DisplayAlertAsync("Error", "Bridge URL must start with wss://", "OK");
            return;
        }
        if (string.IsNullOrEmpty(token) || token.Length < Services.SecureKeys.MinSecretLen)
        {
            await DisplayAlertAsync("Error", $"Auth token is required (at least {Services.SecureKeys.MinSecretLen} characters)", "OK");
            return;
        }
        if (e2eKey != "" && (e2eKey.Length < Services.SecureKeys.MinSecretLen || e2eKey == token))
        {
            await DisplayAlertAsync("Error", $"E2E key must be at least {Services.SecureKeys.MinSecretLen} characters and differ from the auth token", "OK");
            return;
        }
        if (!int.TryParse(portStr, out var port) || port < 1 || port > 65535)
        {
            await DisplayAlertAsync("Error", "Port must be 1-65535", "OK");
            return;
        }

        _tunnel.BridgeUrl = url;
        _tunnel.AuthToken = token;
        _tunnel.E2EKey = e2eKey;
        _tunnel.ListenAddress = addr ?? "127.123.45.67";
        _tunnel.ListenPort = port;
        _tunnel.Relay = RelaySwitch.IsToggled;
        _tunnel.WriteCoalescing = CoalesceSwitch.IsToggled;

        // Save settings
        Preferences.Default.Set("BridgeUrl", url);
        await WriteSecret(KeyAuth, token);
        await WriteSecret(KeyE2E, e2eKey);
        Preferences.Default.Set("ListenAddress", addr ?? "127.123.45.67");
        Preferences.Default.Set("ListenPort", portStr!);
        Preferences.Default.Set("Relay", RelaySwitch.IsToggled);
        Preferences.Default.Set("WriteCoalescing", CoalesceSwitch.IsToggled);

        _isRunning = true;
        ConnectButton.Text = "DISCONNECT";
        ConnectButton.BackgroundColor = Color.FromArgb("#D32F2F");
        OnPropertyChanged(nameof(IsNotRunning));

        _logBuffer.Clear();
        LogLabel.Text = "";

        // Start: on Android the foreground service runs the tunnel;
        // on other platforms we run it in a Task.
        StartPlatformService();

        _tunnel.OnStopped += OnTunnelStopped;
    }

    private void OnTunnelStopped()
    {
        _tunnel.OnStopped -= OnTunnelStopped;
        StopPlatformService();
        // Use the page's own Dispatcher (works on every platform incl. Linux/GTK4)
        // instead of the static MainThread facade, which has no implementation on
        // Linux and throws NotImplementedInReferenceAssemblyException.
        Dispatcher.Dispatch(() =>
        {
            _isRunning = false;
            ConnectButton.Text = "CONNECT";
            ConnectButton.BackgroundColor = Color.FromArgb("#512BD4");
            OnPropertyChanged(nameof(IsNotRunning));
        });
    }

    private void OnTunnelLog(string line)
    {
        Dispatcher.Dispatch(() => AddLog(line));
    }

    /// <summary>
    /// Updates the probe status pill below the Connect button. Called from
    /// arbitrary threads — marshals to the UI thread itself.
    /// </summary>
    private void OnProbeStatusChanged(ProbeStatus status, string detail)
    {
        // Diagnostic: confirm we actually receive the event (we have seen
        // cases where the probe runs but the UI doesn't update).
        Dispatcher.Dispatch(() => AddLog($"[ui] probe status -> {status}: {detail}"));

        Dispatcher.Dispatch(() =>
        {
            switch (status)
            {
                case ProbeStatus.Idle:
                    ProbeStatusBorder.IsVisible = false;
                    return;

                case ProbeStatus.Testing:
                    ProbeStatusBorder.IsVisible = true;
                    ProbeStatusBorder.BackgroundColor = Color.FromArgb("#FFF3CD"); // amber
                    ProbeStatusIcon.TextColor   = Color.FromArgb("#856404");
                    ProbeStatusLabel.TextColor  = Color.FromArgb("#856404");
                    ProbeStatusIcon.Text  = "⧗"; // hourglass-ish dot
                    ProbeStatusLabel.Text = string.IsNullOrEmpty(detail) ? "Testing connection..." : detail;
                    return;

                case ProbeStatus.Ok:
                    ProbeStatusBorder.IsVisible = true;
                    ProbeStatusBorder.BackgroundColor = Color.FromArgb("#2E7D32"); // vivid green
                    ProbeStatusIcon.TextColor   = Color.FromArgb("#FFFFFF");
                    ProbeStatusLabel.TextColor  = Color.FromArgb("#FFFFFF");
                    ProbeStatusIcon.Text  = "✓";
                    ProbeStatusLabel.Text = string.IsNullOrEmpty(detail) ? "Connection verified" : detail;
                    return;

                case ProbeStatus.Failed:
                    ProbeStatusBorder.IsVisible = true;
                    ProbeStatusBorder.BackgroundColor = Color.FromArgb("#F8D7DA"); // red
                    ProbeStatusIcon.TextColor   = Color.FromArgb("#721C24");
                    ProbeStatusLabel.TextColor  = Color.FromArgb("#721C24");
                    ProbeStatusIcon.Text  = "✕";
                    ProbeStatusLabel.Text = string.IsNullOrEmpty(detail) ? "Connection test failed" : detail;
                    return;
            }
        });
    }

    private void AddLog(string line)
    {
        _logBuffer.AppendLine(line);
        // Keep last 200 lines
        var lines = _logBuffer.ToString().Split('\n');
        if (lines.Length > 200)
        {
            _logBuffer.Clear();
            foreach (var l in lines[^200..])
                _logBuffer.AppendLine(l);
        }
        LogLabel.Text = _logBuffer.ToString();
        try { LogScrollView.ScrollToAsync(LogLabel, ScrollToPosition.End, false); }
        catch { }
    }

    private void StartPlatformService()
    {
#if ANDROID
        Platforms.Android.TunnelForegroundService.Tunnel = _tunnel;
        var context = Android.App.Application.Context;
        var intent = new Android.Content.Intent(context, typeof(Platforms.Android.TunnelForegroundService));
        context.StartForegroundService(intent);
#else
        // iOS, macOS, Windows: run the tunnel in a background task.
        // iOS stays alive via beginBackgroundTask + BGProcessingTask in AppDelegate.
        _ = Task.Run(async () =>
        {
            try { await _tunnel.StartAsync(); }
            catch (Exception ex) { AddLog($"Fatal: {ex.Message}"); }
            finally { OnTunnelStopped(); }
        });
#endif
    }

    private static void StopPlatformService()
    {
#if ANDROID
        var context = Android.App.Application.Context;
        var intent = new Android.Content.Intent(context, typeof(Platforms.Android.TunnelForegroundService));
        context.StopService(intent);
        Platforms.Android.TunnelForegroundService.Tunnel = null;
#endif
        // iOS/macOS/Windows: tunnel stops via _tunnel.Stop() called before this
    }
}
