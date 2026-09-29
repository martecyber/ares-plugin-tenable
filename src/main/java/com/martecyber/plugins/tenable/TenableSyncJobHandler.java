package com.martecyber.plugins.tenable;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.imports.IngestFacade;
import com.martecyber.ares.imports.IngestResult;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.integrations.GrantView;
import com.martecyber.ares.integrations.IntegrationFacade;
import com.martecyber.ares.integrations.IntegrationView;
import com.martecyber.ares.jobs.JobFacade;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Does the actual work of a Tenable VM sync — shared by both the "tenable" and "tenable-mssp"
 * types (see {@link #resolveSyncCredentials}'s mode branch, keyed off {@code
 * IntegrationView.type()}, unchanged from ares-core).
 *
 * SYNC_ASSETS:  GET /workbenches/assets?date_range=90 → parse assets
 * SYNC_VULNS:   POST /vulns/export (state=open,reopened) → poll → chunks → parse as detections
 *               Each vuln record also contains embedded asset data → assets are created too.
 *
 * <p>A plain object, not a Spring bean — {@link TenableIntegrationActionHandler}/
 * {@link TenableMsspIntegrationActionHandler} (the plugin's two Spring-managed classes) each
 * construct their own instance directly. Runs {@link #syncAssets}/{@link #syncVulns} via a plain
 * {@code CompletableFuture.runAsync(...)} instead of the original {@code @Async} + self-injection
 * trick, which needs a Spring AOP proxy this plugin's hand-constructed objects don't have.
 *
 * <p><b>SOURCE_TYPE stays {@code "tenable"} even for tenable-mssp syncs</b> — unconditionally,
 * exactly as core's version did — so already-imported Detections/AssetExternalIds keep their
 * existing {@code source_type}/{@code tool} value regardless of which of the two integration
 * types produced them.
 */
public class TenableSyncJobHandler {

    private static final Logger log = LoggerFactory.getLogger(TenableSyncJobHandler.class);
    private static final String SOURCE_TYPE = "tenable";

    private final JobFacade jobFacade;
    private final IntegrationFacade integrationFacade;
    private final TenableClient tenableClient;
    private final TenableAssetParser assetParser;
    private final TenableVulnParser vulnParser;
    private final IngestFacade ingestFacade;
    private final ObjectMapper objectMapper;

    public TenableSyncJobHandler(JobFacade jobFacade,
                                  IntegrationFacade integrationFacade,
                                  TenableClient tenableClient,
                                  TenableAssetParser assetParser,
                                  TenableVulnParser vulnParser,
                                  IngestFacade ingestFacade,
                                  ObjectMapper objectMapper) {
        this.jobFacade = jobFacade;
        this.integrationFacade = integrationFacade;
        this.tenableClient = tenableClient;
        this.assetParser = assetParser;
        this.vulnParser = vulnParser;
        this.ingestFacade = ingestFacade;
        this.objectMapper = objectMapper;
    }

    // ── Asset sync ────────────────────────────────────────────────────────────

    public void syncAssets(Long jobId, Long integrationId, Long projectId, Long orgId) {
        setStatus(jobId, "running", 0);
        try {
            IntegrationView integration = integrationFacade.get(integrationId);
            Map<String, String> creds = resolveSyncCredentials(integration, projectId, orgId);

            log.info("Tenable asset sync start job={} integration={} project={} credsKeys={}",
                jobId, integrationId, projectId, creds.keySet());
            setStatus(jobId, null, 10);

            var fetch = tenableClient.fetchAllAssets(integration.settings(), creds);
            log.info("Tenable: {} workbench assets fetched for job={} endpoint={}",
                fetch.assets().size(), jobId, fetch.endpointUsed());
            setStatus(jobId, null, 50);

            ParseResult parsed = assetParser.parseAssets(fetch.assets());
            setStatus(jobId, null, 75);

            IngestResult result = ingestFacade.ingest(projectId, orgId, SOURCE_TYPE, parsed);
            setStatus(jobId, null, 95);

            updateLastSync(integrationId);

            Map<String, Object> resultData = new LinkedHashMap<>();
            resultData.put("assetsCreated",     result.assetsCreated());
            resultData.put("warnings",           result.warnings().size());
            resultData.put("tenableAssetsFound", fetch.assets().size());
            resultData.put("endpointUsed",       fetch.endpointUsed());
            if (fetch.rawResponseSnippet() != null)
                resultData.put("tenableRawResponse", fetch.rawResponseSnippet());
            if (!result.warnings().isEmpty())
                resultData.put("warningDetails", result.warnings());
            completeJob(jobId, resultData);
            log.info("Tenable asset sync done job={} tenableFound={} created={}",
                jobId, fetch.assets().size(), result.assetsCreated());

        } catch (Exception ex) {
            log.error("Tenable asset sync failed job={}", jobId, ex);
            safeFailJob(jobId, ex.getMessage());
        }
    }

    // ── Vuln sync ─────────────────────────────────────────────────────────────

    public void syncVulns(Long jobId, Long integrationId, Long projectId, Long orgId) {
        setStatus(jobId, "running", 0);
        try {
            IntegrationView integration = integrationFacade.get(integrationId);
            Map<String, String> creds = resolveSyncCredentials(integration, projectId, orgId);

            log.info("Tenable vuln sync start job={} integration={} project={}",
                jobId, integrationId, projectId);
            setStatus(jobId, null, 5);

            String exportUuid = tenableClient.initiateVulnExport(integration.settings(), creds);
            setStatus(jobId, null, 10);

            JsonNode statusNode = tenableClient.pollVulnExport(exportUuid, integration.settings(), creds,
                () -> jobFacade.isCancelled(jobId));
            setStatus(jobId, null, 40);

            List<JsonNode> chunks = tenableClient.getVulnChunks(
                exportUuid, statusNode, integration.settings(), creds);
            setStatus(jobId, null, 65);

            ParseResult parsed = vulnParser.parseVulns(chunks);
            setStatus(jobId, null, 80);

            IngestResult result = ingestFacade.ingest(projectId, orgId, SOURCE_TYPE, parsed);
            setStatus(jobId, null, 95);

            updateLastSync(integrationId);
            completeJob(jobId, Map.of(
                "detectionsCreated", result.detectionsCreated(),
                "detectionsUpdated", result.detectionsUpdated(),
                "assetsCreated",     result.assetsCreated(),
                "warnings",          result.warnings().size()
            ));
            log.info("Tenable vuln sync done job={} created={} updated={} assets={}",
                jobId, result.detectionsCreated(), result.detectionsUpdated(),
                result.assetsCreated());

        } catch (java.util.concurrent.CancellationException ce) {
            log.info("Tenable vuln sync job={} stopped: {}", jobId, ce.getMessage());
            safeFailJob(jobId, ce.getMessage());
        } catch (Exception ex) {
            log.error("Tenable vuln sync failed job={}", jobId, ex);
            safeFailJob(jobId, ex.getMessage());
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Resolves the credentials to use for a sync call.
     *
     *  For plain "tenable" integrations, that's just the integration's own stored credentials.
     *
     *  For "tenable-mssp" integrations, the parent's accessKey/secretKey can only ever query the
     *  parent's own (typically empty) container — Tenable's VM API has no way to "impersonate"
     *  another account via a header. The real mechanism is to mint short-lived access/secret keys
     *  scoped to the grant's managed child account (TenableClient.generateChildAccountKeys) and use
     *  THOSE in place of the parent's keys for every call in this sync. A missing grant or a grant
     *  without a selected managed account is a real misconfiguration and must fail the sync loudly —
     *  otherwise it silently queries the parent account (0 assets/vulns that looks like success). */
    private Map<String, String> resolveSyncCredentials(IntegrationView integration, Long projectId, Long orgId) throws Exception {
        Map<String, String> parentCreds = integrationFacade.loadCredentials(integration.id());
        if (!"tenable-mssp".equalsIgnoreCase(integration.type())) {
            return parentCreds;
        }

        GrantView grant;
        try {
            grant = integrationFacade.resolveGrant(integration.id(), projectId, orgId);
        } catch (Exception e) {
            throw new IllegalStateException(
                "Tenable MSSP integration " + integration.id() + ": failed to resolve the "
                + "managed-account grant for project " + projectId + ": " + e.getMessage(), e);
        }
        String childUuid = grant.accountId();
        if (childUuid == null || childUuid.isBlank()) {
            throw new IllegalStateException(
                "Tenable MSSP integration " + integration.id() + " has no managed account "
                + "selected for project " + projectId + " — edit the grant and choose a managed "
                + "account before syncing.");
        }
        try {
            return tenableClient.generateChildAccountKeys(integration.settings(), parentCreds, childUuid);
        } catch (Exception e) {
            throw new IllegalStateException(
                "Tenable MSSP integration " + integration.id() + ": failed to generate child-account "
                + "keys for managed account " + childUuid + ": " + e.getMessage(), e);
        }
    }

    private void setStatus(Long jobId, String status, Integer progress) {
        try { jobFacade.update(jobId, status, progress, null, null); }
        catch (Exception e) { log.warn("job update failed: {}", e.getMessage()); }
    }

    private void completeJob(Long jobId, Map<String, Object> resultData) {
        try {
            String json = objectMapper.writeValueAsString(resultData);
            jobFacade.update(jobId, "completed", 100, json, null);
        } catch (Exception e) { log.warn("Could not complete job {}: {}", jobId, e.getMessage()); }
    }

    private void safeFailJob(Long jobId, String error) {
        try { jobFacade.update(jobId, "failed", null, null, error); }
        catch (Exception ignored) {}
    }

    private void updateLastSync(Long integrationId) {
        try {
            integrationFacade.recordSyncResult(integrationId, "success");
        } catch (Exception e) {
            log.warn("Could not update lastSyncAt for integration {}: {}", integrationId, e.getMessage());
        }
    }
}
