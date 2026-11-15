using QuotaBar.Core.Providers;

namespace QuotaBar.Tests;

public class CursorTests
{
    const string LiveUsageJson = """
        {"billingCycleStart":"1794571743688","billingCycleEnd":"1795176543688",
         "planUsage":{"remainingBonus":false,"bonusTooltip":"We work with model providers to give you free usage beyond what you've purchased. Amounts may vary.","autoPercentUsed":39.61538461538461,"totalPercentUsed":39.61538461538461},
         "spendLimitUsage":{"limitType":"user"},"displayThreshold":200,"enabled":true,
         "displayMessage":"You've used 40% of your included usage",
         "autoModelSelectedDisplayMessage":"You've used 40% of your included total usage",
         "namedModelSelectedDisplayMessage":"You've used 40% of your included total usage",
         "autoBucketModels":["default","composer-2"]}
        """;

    const string LivePlanJson = """
        {"planInfo":{"planName":"Plus","billingCycleEnd":"1796082954937","includedUsagePeriod":"INCLUDED_USAGE_PERIOD_WEEKLY","includedUsageResetsAt":"1795176543688"}}
        """;

    [Fact]
    public void Parses_live_weekly_usage_and_plan_info()
    {
        var s = CursorProvider.ParseUsage(LiveUsageJson, LivePlanJson);
        Assert.Equal(ProviderStatus.Ok, s.Status);
        Assert.Equal("Plus", s.Plan);
        Assert.Equal("https://cursor.com/dashboard?tab=usage", s.DashboardUrl);
        Assert.Equal("https://status.cursor.com", s.StatusUrl);

        var w = Assert.Single(s.Windows);
        Assert.Equal("weekly", w.Key);
        Assert.Equal("Weekly", w.Label);
        Assert.Equal(39.6, w.UsedPercent, 1);
        Assert.NotNull(w.ResetsAt);
        Assert.Equal(1795176543688L, w.ResetsAt!.Value.ToUnixTimeMilliseconds());
        Assert.Equal(7 * 86400L, w.WindowSeconds);
    }

    [Fact]
    public void Omits_auto_breakdown_when_api_is_absent_and_auto_matches_total()
    {
        var s = CursorProvider.ParseUsage(LiveUsageJson);
        Assert.Equal(ProviderStatus.Ok, s.Status);
        Assert.Single(s.Windows);
        Assert.DoesNotContain(s.Info, i => i.Label == "Auto");
        Assert.Empty(s.Info);

        var withApi = """
            {"billingCycleStart":1794571743688,"billingCycleEnd":1795176543688,
             "planUsage":{"autoPercentUsed":25.0,"apiPercentUsed":14.5,"totalPercentUsed":39.5}}
            """;
        var s2 = CursorProvider.ParseUsage(withApi);
        Assert.Contains(s2.Info, i => i.Label == "Auto" && i.Value == "25% used");
        Assert.Contains(s2.Info, i => i.Label == "API" && i.Value == "14.5% used");
    }

    [Fact]
    public void Accepts_string_and_number_millisecond_timestamps()
    {
        var asStrings = """{"billingCycleStart":"1794571743688","billingCycleEnd":"1795176543688","planUsage":{"totalPercentUsed":39.6}}""";
        var asNumbers = """{"billingCycleStart":1794571743688,"billingCycleEnd":1795176543688,"planUsage":{"totalPercentUsed":39.6}}""";

        var s1 = CursorProvider.ParseUsage(asStrings);
        var s2 = CursorProvider.ParseUsage(asNumbers);

        Assert.Equal(1795176543688L, s1.Windows.Single().ResetsAt!.Value.ToUnixTimeMilliseconds());
        Assert.Equal(1795176543688L, s2.Windows.Single().ResetsAt!.Value.ToUnixTimeMilliseconds());
        Assert.Equal(7 * 86400L, s1.Windows.Single().WindowSeconds);
        Assert.Equal(7 * 86400L, s2.Windows.Single().WindowSeconds);

        var monthly = """{"billingCycleStart":1794571743688,"billingCycleEnd":1797163743688,"planUsage":{"totalPercentUsed":50}}""";
        var sm = CursorProvider.ParseUsage(monthly);
        Assert.Equal("Monthly", sm.Windows.Single().Label);
        Assert.Equal(30 * 86400L, sm.Windows.Single().WindowSeconds);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("{}")]
    [InlineData("""{"planUsage":{}}""")]
    [InlineData("""{"planUsage":{"autoPercentUsed":10}}""")]
    public void Missing_totalPercentUsed_returns_unexpected_format_error(string json)
    {
        var s = CursorProvider.ParseUsage(json);
        Assert.Equal(ProviderStatus.Error, s.Status);
        Assert.Empty(s.Windows);
        Assert.NotNull(s.Message);
    }

    [Fact]
    public void Pkce_challenge_matches_rfc7636_vector()
    {
        const string verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        const string expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        Assert.Equal(expected, CursorProvider.PkceChallenge(verifier));

        var (v, c, uuid, url) = CursorProvider.StartLogin();
        Assert.Equal(43, v.Length);
        Assert.DoesNotContain("=", v);
        Assert.Equal(CursorProvider.PkceChallenge(v), c);
        Assert.True(Guid.TryParseExact(uuid, "D", out _));
        Assert.Equal(uuid.ToLowerInvariant(), uuid);
        Assert.Equal($"https://cursor.com/loginDeepControl?challenge={c}&uuid={uuid}&mode=login", url);
    }
}
