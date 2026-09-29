using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace BridgeToFreedom.Services;

/// <summary>
/// v5 authentication / encryption layer. Byte-for-byte identical to
/// adapter-and-helper/internal/secure/secure.go and bridge-cloud/index.js
/// (checked against testdata/vectors.json by maui-client-tests).
///
/// Only HMAC-SHA256 and AES (ECB used to build CTR) are used, both available
/// on every .NET platform MAUI targets (Android, iOS, macOS, Windows, Linux).
/// </summary>
public sealed class SecureKeys
{
    public const byte HelloVersion = 0x05;
    public const int TagLen = 16;
    public const int IvLen = 16;
    public const int HeaderLen = 9;
    public const byte DirHelperToAdapter = (byte)'H';
    public const byte DirAdapterToHelper = (byte)'A';
    public const string RoleHelper = "helper";
    public const int MinSecretLen = 16;

    private readonly byte[] _hello, _ticket, _ctl, _enc, _mac;

    /// <summary>True when a separate end-to-end key is configured.</summary>
    public bool E2E { get; }

    private SecureKeys(string authToken, string e2eKey)
    {
        var peerSecret = string.IsNullOrEmpty(e2eKey) ? authToken : e2eKey;
        _hello = Kdf(authToken, "hello");
        _ticket = Kdf(authToken, "ticket");
        _ctl = Kdf(authToken, "ctl");
        _enc = Kdf(peerSecret, "peer-enc");
        _mac = Kdf(peerSecret, "peer-mac");
        E2E = !string.IsNullOrEmpty(e2eKey);
    }

    public static SecureKeys Derive(string authToken, string? e2eKey) =>
        new(authToken, e2eKey ?? "");

    private static byte[] Kdf(string secret, string label) =>
        HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes("btf5/" + label));

    private static byte[] Mac(byte[] key, params byte[][] parts)
    {
        using var h = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key);
        foreach (var p in parts) h.AppendData(p);
        return h.GetHashAndReset();
    }

    private static readonly byte[] Zero = [0];

    // --- HELLO: [ver][8B unix-ms BE][32B HMAC(hello, role||0||ts)] ---
    public byte[] HelloPayload(string role, DateTimeOffset now)
    {
        var ts = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(ts, (ulong)now.ToUnixTimeMilliseconds());
        var mac = Mac(_hello, Encoding.UTF8.GetBytes(role), Zero, ts);
        var outp = new byte[1 + 8 + 32];
        outp[0] = HelloVersion;
        ts.CopyTo(outp, 1);
        mac.CopyTo(outp, 9);
        return outp;
    }

    // --- Ticket appended to every non-HELLO upstream message ---
    public byte[] Ticket(string role, string connId) =>
        Mac(_ticket, Encoding.UTF8.GetBytes(role), Zero, Encoding.UTF8.GetBytes(connId))[..TagLen];

    // --- Control-frame signature from the cloud function ---
    /// <summary>Returns the frame without its tag, or null if the signature is invalid.</summary>
    public byte[]? VerifyCtl(string ownConnId, byte[] msg)
    {
        if (msg.Length < HeaderLen + TagLen) return null;
        var frame = msg[..^TagLen];
        var want = Mac(_ctl, Encoding.UTF8.GetBytes(ownConnId), Zero, frame).AsSpan(0, TagLen);
        return CryptographicOperations.FixedTimeEquals(want, msg.AsSpan(msg.Length - TagLen)) ? frame : null;
    }

    // --- Peer frames: header || iv || AES-256-CTR(payload) || HMAC(dir||header||iv||ct)[:16] ---
    public byte[] Seal(byte dir, byte[] frame)
    {
        var iv = RandomNumberGenerator.GetBytes(IvLen);
        return SealWithIv(dir, frame, iv);
    }

    public byte[] SealWithIv(byte dir, byte[] frame, byte[] iv)
    {
        if (frame.Length < HeaderLen) throw new ArgumentException("frame too short");
        var outp = new byte[frame.Length + IvLen + TagLen];
        Buffer.BlockCopy(frame, 0, outp, 0, HeaderLen);
        Buffer.BlockCopy(iv, 0, outp, HeaderLen, IvLen);
        var ct = Ctr(iv, frame.AsSpan(HeaderLen));
        ct.CopyTo(outp, HeaderLen + IvLen);
        var tag = Mac(_mac, [dir], outp[..^TagLen]);
        Buffer.BlockCopy(tag, 0, outp, outp.Length - TagLen, TagLen);
        return outp;
    }

    /// <summary>Verifies and decrypts a sealed peer frame; null if forged/corrupt.</summary>
    public byte[]? Open(byte dir, byte[] msg)
    {
        if (msg.Length < HeaderLen + IvLen + TagLen) return null;
        var body = msg[..^TagLen];
        var want = Mac(_mac, [dir], body).AsSpan(0, TagLen);
        if (!CryptographicOperations.FixedTimeEquals(want, msg.AsSpan(msg.Length - TagLen))) return null;
        var iv = body[HeaderLen..(HeaderLen + IvLen)];
        var pt = Ctr(iv, body.AsSpan(HeaderLen + IvLen));
        var outp = new byte[HeaderLen + pt.Length];
        Buffer.BlockCopy(body, 0, outp, 0, HeaderLen);
        pt.CopyTo(outp, HeaderLen);
        return outp;
    }

    // AES-256-CTR with a 128-bit big-endian counter starting at iv (same as
    // Go's cipher.NewCTR and OpenSSL/Node 'aes-256-ctr').
    private byte[] Ctr(byte[] iv, ReadOnlySpan<byte> input)
    {
        var output = new byte[input.Length];
        if (input.Length == 0) return output;
        int blocks = (input.Length + 15) / 16;
        var counters = new byte[blocks * 16];
        var ctr = (byte[])iv.Clone();
        for (int b = 0; b < blocks; b++)
        {
            Buffer.BlockCopy(ctr, 0, counters, b * 16, 16);
            for (int i = 15; i >= 0; i--) { if (++ctr[i] != 0) break; }
        }
        using var aes = Aes.Create();
        aes.Key = _enc;
        var ks = aes.EncryptEcb(counters, PaddingMode.None);
        for (int i = 0; i < input.Length; i++) output[i] = (byte)(input[i] ^ ks[i]);
        return output;
    }
}
