using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using BridgeToFreedom.Services;

if (args.Length > 0 && args[0] == "e2e") return await E2E.Run(args[1..]);

var root = AppContext.GetData("RepoRoot") as string ?? FindRoot();
var v = JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "testdata", "vectors.json"))).RootElement;
string S(string k) => v.GetProperty(k).GetString()!;
byte[] H(string k) => Convert.FromHexString(S(k));
int fails = 0;
void Check(string name, bool ok) { Console.WriteLine($"{(ok ? "PASS" : "FAIL")}  {name}"); if (!ok) fails++; }

var k = SecureKeys.Derive(S("authToken"), S("e2eKey"));
var k0 = SecureKeys.Derive(S("authToken"), "");
var ts = DateTimeOffset.FromUnixTimeMilliseconds(v.GetProperty("tsMs").GetInt64());

Check("HELLO payload (helper) matches Go", Convert.ToHexString(k.HelloPayload("helper", ts)).ToLower() == S("helloHelper"));
Check("HELLO payload (adapter) matches Go", Convert.ToHexString(k.HelloPayload("adapter", ts)).ToLower() == S("helloAdapter"));
Check("ticket matches Go", Convert.ToHexString(k.Ticket("helper", S("ticketConnId"))).ToLower() == S("ticketHelper"));
var ctl = k.VerifyCtl(S("ctlDest"), H("ctlSigned"));
Check("ctl signature verifies", ctl != null && ctl.SequenceEqual(H("ctlFrame")));
Check("ctl signature rejected for other connection", k.VerifyCtl("other", H("ctlSigned")) == null);

var frame = H("peerFrame"); var iv = H("peerIv");
Check("seal H matches Go", Convert.ToHexString(k.SealWithIv(SecureKeys.DirHelperToAdapter, frame, iv)).ToLower() == S("peerSealedH"));
Check("seal A matches Go", Convert.ToHexString(k.SealWithIv(SecureKeys.DirAdapterToHelper, frame, iv)).ToLower() == S("peerSealedA"));
Check("seal without e2eKey matches Go", Convert.ToHexString(k0.SealWithIv(SecureKeys.DirHelperToAdapter, frame, iv)).ToLower() == S("peerSealedNoE2E"));
var opened = k.Open(SecureKeys.DirAdapterToHelper, H("peerSealedA"));
Check("open Go-sealed A frame", opened != null && opened.SequenceEqual(frame));
Check("reject reflected direction", k.Open(SecureKeys.DirHelperToAdapter, H("peerSealedA")) == null);
Check("reject other e2eKey", k0.Open(SecureKeys.DirAdapterToHelper, H("peerSealedA")) == null);
var tampered = H("peerSealedA"); tampered[30] ^= 1;
Check("reject tampered frame", k.Open(SecureKeys.DirAdapterToHelper, tampered) == null);
foreach (var n in new[] { 0, 1, 16, 17, 100000 })
{
    var f = new byte[9 + n]; f[0] = 0x20; Random.Shared.NextBytes(f.AsSpan(9));
    var o = k.Open(SecureKeys.DirHelperToAdapter, k.Seal(SecureKeys.DirHelperToAdapter, f));
    Check($"round trip {n} bytes", o != null && o.SequenceEqual(f));
}
// Protocol additions
var (tok, sid) = Protocol.DecodePong(new byte[] { 0, 2, (byte)'a', (byte)'b', 7 });
Check("PONG with trailing shortId", tok == "ab" && sid == 7);
var (_, _, psid) = Protocol.DecodePeerConn(new byte[] { 0, 1, (byte)'x', 0, 0, 3 });
Check("PEER_CONN with trailing shortId", psid == 3);
Check("claim encoding", Protocol.EncodeClaim(5).SequenceEqual(new byte[] { 5 }) && Protocol.EncodeClaim(0).Length == 0);

Console.WriteLine(fails == 0 ? "ALL PASSED" : $"{fails} FAILED");
return fails == 0 ? 0 : 1;

static string FindRoot()
{
    var d = new DirectoryInfo(AppContext.BaseDirectory);
    while (d != null && !File.Exists(Path.Combine(d.FullName, "testdata", "vectors.json"))) d = d.Parent;
    return d?.FullName ?? throw new Exception("repo root not found");
}

// End-to-end: runs the real TunnelService against tests/e2e/sim.js + adapter.
// args: <bridgeUrl> <listenPort> <relay:true|false> <authToken> <e2eKey> <echoPort>
static class E2E
{
    public static async Task<int> Run(string[] a)
    {
        var (url, port, relay, auth, e2e, echoPort) = (a[0], int.Parse(a[1]), bool.Parse(a[2]), a[3], a[4], int.Parse(a[5]));
        var echo = new TcpListener(IPAddress.Loopback, echoPort);
        echo.Start();
        _ = Task.Run(async () =>
        {
            while (true)
            {
                var c = await echo.AcceptTcpClientAsync();
                _ = Task.Run(async () => { using (c) { try { await c.GetStream().CopyToAsync(c.GetStream()); } catch { } } });
            }
        });

        var t = new TunnelService { BridgeUrl = url, AuthToken = auth, E2EKey = e2e, ListenAddress = "127.0.0.1", ListenPort = port, Relay = relay, WriteCoalescing = true };
        var probe = new TaskCompletionSource<(ProbeStatus, string)>();
        t.OnProbeStatusChanged += (st, d) => { if (st is ProbeStatus.Ok or ProbeStatus.Failed) probe.TrySetResult((st, d)); };
        var logs = new List<string>();
        t.OnLog += l => { lock (logs) logs.Add(l); };
        var run = Task.Run(t.StartAsync);

        int fails = 0;
        void Check(string name, bool ok, string extra = "") { Console.WriteLine($"{(ok ? "PASS" : "FAIL")}  MAUI {(relay ? "relay" : "direct")}: {name}{(extra != "" ? "  (" + extra + ")" : "")}"); if (!ok) fails++; }

        var done = await Task.WhenAny(probe.Task, Task.Delay(40000));
        var (pst, pd) = done == probe.Task ? probe.Task.Result : (ProbeStatus.Failed, "timeout");
        Check("connectivity probe OK", pst == ProbeStatus.Ok, pd);

        var results = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => EchoOnce(port, 256 * 1024)));
        Check("4 parallel streams x 256 KiB echoed intact", results.All(x => x), $"{results.Count(x => x)}/4");

        await t.StopAsync();
        echo.Stop();
        if (fails > 0) lock (logs) foreach (var l in logs.TakeLast(40)) Console.WriteLine("   | " + l);
        return fails == 0 ? 0 : 1;
    }

    static async Task<bool> EchoOnce(int port, int size)
    {
        try
        {
            using var c = new TcpClient();
            await c.ConnectAsync(IPAddress.Loopback, port);
            var s = c.GetStream();
            var data = RandomNumberGenerator.GetBytes(size);
            var writer = s.WriteAsync(data).AsTask();
            var got = new byte[size];
            int n = 0;
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            while (n < size)
            {
                int r = await s.ReadAsync(got.AsMemory(n), cts.Token);
                if (r == 0) break;
                n += r;
            }
            await writer;
            return n == size && got.AsSpan().SequenceEqual(data);
        }
        catch { return false; }
    }
}
