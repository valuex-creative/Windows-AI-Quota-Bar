using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace QuotaBar.Core.Providers;

/// <summary>
/// Cursor: signs in through the user's browser with PKCE (cursor.com/loginDeepControl → api2.cursor.sh/auth/poll)
/// and stores its OAuth tokens DPAPI-encrypted in <see cref="SecretStore"/>. Never reads %APPDATA%\Cursor.
/// </summary>
public sealed class CursorProvider : IUsageProvider
{
    public string Kind => "cursor";
    public string Name => "Cursor";

    public const string TokenSecret = "cursor:auth";
    const string ClientId = "KbZUR41cY7W6zRSdpSUJ7I7mLYBKOCmB";
    const string ApiBase = "https://api2.cursor.sh";
    public const string Dashboard = "https://cursor.com/dashboard?tab=usage";
    public const string StatusPage = "https://status.cursor.com";

    public static bool HasSession => SecretStore.Get(TokenSecret) is { Length: > 0 };
    public static void SignOut() => SecretStore.Set(TokenSecret, null);

    public async Task<IReadOnlyList<ProviderSnapshot>> FetchAsync(CancellationToken ct)
    {
        var (access, refresh) = LoadTokens();
        if (string.IsNullOrEmpty(access) && string.IsNullOrEmpty(refresh))
            return new[] { Fail(ProviderStatus.NeedsLogin, "Sign in to Cursor from Windows AI Quota Bar (Settings → Cursor → Sign in).") };

        try
        {
            var refreshed = false;
            if ((string.IsNullOrEmpty(access) || IsExpiringSoon(access)) && !string.IsNullOrEmpty(refresh))
            {
                (access, refresh) = await RefreshAsync(refresh, ct);
                refreshed = true;
            }
            if (string.IsNullOrEmpty(access))
                return new[] { Fail(ProviderStatus.NeedsLogin, "Cursor session expired. Sign in again from QuotaBar.") };

            string usageJson;
            while (true)
            {
                try
                {
                    usageJson = await PostDashboardAsync(access, "GetCurrentPeriodUsage", ct);
                    break;
                }
                catch (Http.HttpError e) when (e.Code is 401 or 403)
                {
                    if (refreshed || string.IsNullOrEmpty(refresh))
                    {
                        SignOut();
                        return new[] { Fail(ProviderStatus.NeedsLogin, "Cursor session expired. Sign in again from QuotaBar.") };
                    }
                    (access, refresh) = await RefreshAsync(refresh, ct);
                    refreshed = true;
                }
            }

            string? planJson = null;
            try { planJson = await PostDashboardAsync(access, "GetPlanInfo", ct); }
            catch (Exception) when (!ct.IsCancellationRequested) { /* secondary endpoint: keep usage even if plan info fails */ }

            var snap = ParseUsage(usageJson, planJson);
            if (snap.Account is null && Jwt.Payload(access)?.Str("email") is { Length: > 0 } email)
                snap.Account = email;
            return new[] { snap };
        }
        catch (SessionExpiredException e)
        {
            return new[] { Fail(ProviderStatus.NeedsLogin, e.Message) };
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception e)
        {
            return new[] { Fail(ProviderStatus.Error, e.GetBaseException().Message) };
        }
    }

    static ProviderSnapshot Fail(ProviderStatus status, string message) => new()
    {
        Id = "cursor", ProviderKind = "cursor", DisplayName = "Cursor",
        Status = status, Message = message, DashboardUrl = Dashboard, StatusUrl = StatusPage,
    };

    sealed class SessionExpiredException(string message) : Exception(message);

    // ---- PKCE browser login ------------------------------------------------------------------------

    public static string Base64Url(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static string PkceChallenge(string verifier) =>
        Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

    public static (string verifier, string challenge, string uuid, string loginUrl) StartLogin()
    {
        var verifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        var challenge = PkceChallenge(verifier);
        var uuid = Guid.NewGuid().ToString("D").ToLowerInvariant();
        var url = $"https://cursor.com/loginDeepControl?challenge={challenge}&uuid={uuid}&mode=login";
        return (verifier, challenge, uuid, url);
    }

    /// <summary>Polls every 2 s for up to 3 minutes until the browser login finishes.</summary>
    public static async Task<bool> PollLoginAsync(string uuid, string verifier, CancellationToken ct)
    {
        var url = $"{ApiBase}/auth/poll?uuid={Uri.EscapeDataString(uuid)}&verifier={Uri.EscapeDataString(verifier)}";
        var deadline = DateTimeOffset.UtcNow.AddMinutes(3);
        while (DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(TimeSpan.FromSeconds(2), ct);
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, url);
                using var res = await Http.Client.SendAsync(req, ct);
                if (!res.IsSuccessStatusCode) continue;
                var body = await res.Content.ReadAsStringAsync(ct);
                if (string.IsNullOrWhiteSpace(body)) continue;
                using var doc = JsonDocument.Parse(body);
                var access = doc.RootElement.Str("accessToken");
                if (string.IsNullOrEmpty(access)) continue;
                ct.ThrowIfCancellationRequested();
                SaveTokens(access, doc.RootElement.Str("refreshToken"));
                return true;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (OperationCanceledException) { /* single poll request timed out */ }
            catch (JsonException) { /* non-JSON body while waiting */ }
            catch (Exception e) when (e is HttpRequestException or IOException) { /* transient network hiccup while polling */ }
        }
        return false;
    }

    // ---- Token storage & refresh -------------------------------------------------------------------

    static (string? access, string? refresh) LoadTokens()
    {
        var raw = SecretStore.Get(TokenSecret);
        if (string.IsNullOrWhiteSpace(raw)) return (null, null);
        if (raw.TrimStart().StartsWith('{'))
        {
            try
            {
                using var doc = JsonDocument.Parse(raw);
                return (doc.RootElement.Str("accessToken"), doc.RootElement.Str("refreshToken"));
            }
            catch { return (null, null); }
        }
        return (raw.Trim(), null);
    }

    public static void SaveTokens(string accessToken, string? refreshToken)
    {
        var obj = new JsonObject { ["accessToken"] = accessToken };
        if (!string.IsNullOrEmpty(refreshToken)) obj["refreshToken"] = refreshToken;
        SecretStore.Set(TokenSecret, obj.ToJsonString());
    }

    static bool IsExpiringSoon(string accessToken) =>
        Jwt.Payload(accessToken)?.Num("exp") is { } exp
        && DateTimeOffset.FromUnixTimeSeconds((long)exp) <= DateTimeOffset.UtcNow.AddMinutes(5);

    static async Task<(string access, string? refresh)> RefreshAsync(string refreshToken, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, $"{ApiBase}/oauth/token")
        {
            Content = JsonContent.Create(new
            {
                grant_type = "refresh_token",
                client_id = ClientId,
                refresh_token = refreshToken,
            }),
        };
        JsonElement r;
        try
        {
            r = await Http.SendJson(req, ct);
        }
        catch (Http.HttpError e) when (e.Code is 400 or 401 or 403)
        {
            SignOut();
            throw new SessionExpiredException("Cursor session expired. Sign in again from QuotaBar.");
        }

        var access = r.Str("access_token");
        var shouldLogout = r.Prop("shouldLogout")?.ValueKind == JsonValueKind.True;
        if (shouldLogout || string.IsNullOrEmpty(access))
        {
            SignOut();
            throw new SessionExpiredException("Cursor session expired. Sign in again from QuotaBar.");
        }
        var nextRefresh = r.Str("refresh_token") is { Length: > 0 } nr ? nr : refreshToken;
        SaveTokens(access, nextRefresh);
        return (access, nextRefresh);
    }

    // ---- Dashboard RPCs & parsing ------------------------------------------------------------------

    static async Task<string> PostDashboardAsync(string accessToken, string method, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, $"{ApiBase}/aiserver.v1.DashboardService/{method}")
        {
            Content = new StringContent("{}", Encoding.UTF8, "application/json"),
        };
        req.Headers.Authorization = new("Bearer", accessToken);
        req.Headers.TryAddWithoutValidation("Connect-Protocol-Version", "1");

        using var res = await Http.Client.SendAsync(req, ct);
        var body = await res.Content.ReadAsStringAsync(ct);
        if (res.StatusCode == HttpStatusCode.TooManyRequests)
        {
            var wait = res.Headers.RetryAfter?.Delta
                ?? (res.Headers.RetryAfter?.Date is { } d ? d - DateTimeOffset.UtcNow : null);
            var suffix = wait is { TotalSeconds: > 0 } w ? $" (retry after {(int)Math.Ceiling(w.TotalSeconds)}s)" : "";
            throw new Http.HttpError(429, $"Rate limited by Cursor{suffix}.");
        }
        if (!res.IsSuccessStatusCode) throw new Http.HttpError((int)res.StatusCode, body);
        return body;
    }

    /// <summary>Pure parser for GetCurrentPeriodUsage (+ optional GetPlanInfo) JSON responses.</summary>
    public static ProviderSnapshot ParseUsage(string usageJson, string? planJson = null)
    {
        if (string.IsNullOrWhiteSpace(usageJson))
            return Fail(ProviderStatus.Error, "Unexpected Cursor usage response: empty body.");

        JsonDocument usageDoc;
        try { usageDoc = JsonDocument.Parse(usageJson); }
        catch (JsonException) { return Fail(ProviderStatus.Error, "Unexpected Cursor usage response: invalid JSON."); }

        using (usageDoc)
        {
            var root = usageDoc.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || root.Prop("planUsage") is not { ValueKind: JsonValueKind.Object } planUsage
                || planUsage.Num("totalPercentUsed") is not { } totalRaw
                || double.IsNaN(totalRaw) || double.IsInfinity(totalRaw))
            {
                return Fail(ProviderStatus.Error, "Unexpected Cursor usage response: missing planUsage.totalPercentUsed.");
            }

            string? planName = null;
            string? periodHint = null;
            long? planResetMs = null;
            if (!string.IsNullOrWhiteSpace(planJson))
            {
                try
                {
                    using var planDoc = JsonDocument.Parse(planJson);
                    var pi = planDoc.RootElement.Prop("planInfo") ?? planDoc.RootElement;
                    if (pi.ValueKind == JsonValueKind.Object)
                    {
                        planName = pi.Str("planName");
                        periodHint = pi.Str("includedUsagePeriod");
                        planResetMs = Ms(pi, "includedUsageResetsAt") ?? Ms(pi, "billingCycleEnd");
                    }
                }
                catch (JsonException) { /* optional secondary payload */ }
            }

            var startMs = Ms(root, "billingCycleStart");
            var endMs = Ms(root, "billingCycleEnd") ?? planResetMs;
            long? windowSecs = startMs is { } sMs && endMs is { } eMs && eMs > sMs ? (eMs - sMs) / 1000 : null;

            bool isWeekly = periodHint == "INCLUDED_USAGE_PERIOD_WEEKLY"
                || (periodHint != "INCLUDED_USAGE_PERIOD_MONTHLY" && windowSecs is >= 5 * 86400 and <= 9 * 86400);
            var key = isWeekly ? "weekly" : "monthly";
            var label = isWeekly ? "Weekly" : "Monthly";
            if (windowSecs is null && isWeekly) windowSecs = 7 * 86400;

            var resetsAt = endMs is { } resetMs ? DateTimeOffset.FromUnixTimeMilliseconds(resetMs).ToLocalTime() : (DateTimeOffset?)null;
            var totalUsed = Math.Clamp(totalRaw, 0, 100);

            var snap = new ProviderSnapshot
            {
                Id = "cursor",
                ProviderKind = "cursor",
                DisplayName = "Cursor",
                Plan = string.IsNullOrWhiteSpace(planName) ? null : planName,
                Status = ProviderStatus.Ok,
                DashboardUrl = Dashboard,
                StatusUrl = StatusPage,
                Windows =
                {
                    new UsageWindow
                    {
                        Key = key,
                        Label = label,
                        UsedPercent = totalUsed,
                        ResetsAt = resetsAt,
                        WindowSeconds = windowSecs,
                    },
                },
            };

            var autoUsed = planUsage.Num("autoPercentUsed");
            var apiUsed = planUsage.Num("apiPercentUsed");
            if (apiUsed is > 0.05 || (autoUsed is { } au && Math.Abs(au - totalRaw) >= 0.5))
            {
                static string Pct(double v) => string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{Math.Clamp(v, 0, 100):0.#}% used");
                if (autoUsed is { } a) snap.Info.Add(new("Auto", Pct(a)));
                if (apiUsed is > 0) snap.Info.Add(new("API", Pct(apiUsed.Value)));
            }

            return snap;
        }
    }

    static long? Ms(JsonElement e, string name)
    {
        if (e.Prop(name) is not { } v) return null;
        if (v.ValueKind == JsonValueKind.Number)
        {
            if (v.TryGetInt64(out var l)) return l > 0 ? l : null;
            if (v.TryGetDouble(out var d) && d > 0) return (long)d;
        }
        else if (v.ValueKind == JsonValueKind.String && v.GetString() is { } s)
        {
            if (long.TryParse(s, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var l)) return l > 0 ? l : null;
            if (double.TryParse(s, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var d) && d > 0) return (long)d;
        }
        return null;
    }
}
