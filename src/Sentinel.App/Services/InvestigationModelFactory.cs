using System.Net.Http;
using Sentinel.Engine.Agent;

namespace Sentinel.App.Services;

// Chooses the investigation model for one scan (P1-01). Live cloud
// ONLY when BOTH an endpoint is configured AND a key exists in
// Credential Manager; every other case is an honest offline model
// whose Description says exactly why. The key value never leaves
// this call except into the adapter's Authorization header.
public sealed record ModelSource(
    IInvestigationModel Model, string Description, bool IsLive);

public static class InvestigationModelFactory
{
    public static ModelSource Create(
        string? apiKey,
        IReadOnlyList<IInvestigationTool> tools,
        HttpClient http,
        PayloadLog payloads,
        InvestigationBudgets budgets)
    {
        if (apiKey is null)
        {
            return new ModelSource(
                new OfflineModel("NoKey"),
                "offline (no cloud key saved)",
                false);
        }

        return new ModelSource(
            new MetaApiAdapter(
                apiKey, MetaApiAdapter.DefaultEndpoint, http, tools,
                payloads, budgets),
            "cloud (Meta Model API)",
            true);
    }
}
