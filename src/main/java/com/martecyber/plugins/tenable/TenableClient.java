package com.martecyber.plugins.tenable;

import com.martecyber.ares.integrations.tools.IntegrationClient;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;

/**
 * Tenable Vulnerability Management API client.
 *
 * Auth: X-ApiKeys "accessKey=xxx; secretKey=yyy" — same key for all endpoints.
 *
 * Module detection: call lightweight endpoints to determine which VM capabilities
 * (SYNC_ASSETS, SYNC_VULNS) are accessible with the provided credentials.
 *
 * Asset sync:  GET /workbenches/assets?date_range=90
 *              Fields: ipv4[], fqdn[], hostname[] (arrays, no plural 's')
 *
 * Vuln sync:   POST /vulns/export → poll → GET chunks
 *              Each chunk item has asset{fqdn,hostname,ipv4} (singular strings)
 *              and plugin{id,name,cvss3_base_score,...} + severity + state
 *              Only state=[open,reopened] are imported as detections.
 *
 * Ref: Tenable_Vulnerability_Management_API.json
 */
public class TenableClient implements IntegrationClient {

    private static final Logger log = LoggerFactory.getLogger(TenableClient.class);
    private static final String DEFAULT_BASE_URL  = "https://cloud.tenable.com";
    private static final int    POLL_MAX_ATTEMPTS = 40;
    private static final long   POLL_DELAY_MS     = 15_000;

    protected final HttpClient http;
    protected final ObjectMapper objectMapper;

    public TenableClient(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();
    }

    @Override
    public String supports() { return "tenable"; }

    @Override
    public List<Map<String, String>> listPickerItems(String settingsJson, Map<String, String> credentials) throws Exception {
        return listMsspAccounts(settingsJson, credentials).stream()
            .map(a -> Map.of("id", a.id(), "name", a.name()))
            .toList();
    }

    // ── Auth check ────────────────────────────────────────────────────────────

    @Override
    public void testConnection(String settingsJson, Map<String, String> credentials) throws Exception {
        String base = baseUrl(settingsJson);
        String auth = authHeader(credentials);

        HttpResponse<String> resp = http.send(
            get(base + "/session", auth), HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200)
            throw new RuntimeException("Tenable auth failed: HTTP " + resp.statusCode()
                + " — " + snippet(resp.body()));

        JsonNode session = objectMapper.readTree(resp.body());
        log.info("Tenable session — username={} container_id={} container_name={} permissions={}",
            session.path("username").asText("?"),
            session.path("container_id").asText("?"),
            session.path("container_name").asText("?"),
            session.path("permissions").asInt(-1));

        // Diagnostic: list available scans
        HttpResponse<String> scansResp = http.send(
            get(base + "/scans", auth), HttpResponse.BodyHandlers.ofString());
        log.info("GET /scans → HTTP {} body[0-400]={}", scansResp.statusCode(), snippet(scansResp.body(), 400));

        // Diagnostic: assets total
        HttpResponse<String> assetsResp = http.send(
            get(base + "/assets?limit=1", auth), HttpResponse.BodyHandlers.ofString());
        log.info("GET /assets?limit=1 → HTTP {} body[0-400]={}", assetsResp.statusCode(), snippet(assetsResp.body(), 400));
    }

    // ── Module / capability detection ─────────────────────────────────────────

    /**
     * Probes lightweight endpoints to determine which VM capabilities are available.
     * Returns a list of capability IDs (e.g. ["SYNC_ASSETS", "SYNC_VULNS"]).
     */
    public List<String> detectCapabilities(String settingsJson, Map<String, String> creds) {
        String base = baseUrl(settingsJson);
        String auth = authHeader(creds);
        List<String> caps = new ArrayList<>();

        // SYNC_ASSETS: probe GET /assets?limit=1
        try {
            HttpResponse<String> r = http.send(
                get(base + "/assets?limit=1", auth),
                HttpResponse.BodyHandlers.ofString());
            log.info("SYNC_ASSETS probe GET /assets?limit=1 → HTTP {} body={}", r.statusCode(), snippet(r.body(), 200));
            if (r.statusCode() == 200) caps.add("SYNC_ASSETS");
            else log.warn("SYNC_ASSETS not available: HTTP {}", r.statusCode());
        } catch (Exception e) { log.warn("SYNC_ASSETS probe failed: {}", e.getMessage()); }

        // SYNC_VULNS: probe GET /workbenches/vulnerabilities
        try {
            HttpResponse<String> r = http.send(
                get(base + "/workbenches/vulnerabilities?date_range=1&filter_type=and", auth),
                HttpResponse.BodyHandlers.ofString());
            log.info("SYNC_VULNS probe → HTTP {} body={}", r.statusCode(), snippet(r.body(), 200));
            if (r.statusCode() == 200) caps.add("SYNC_VULNS");
            else log.warn("SYNC_VULNS not available: HTTP {}", r.statusCode());
        } catch (Exception e) { log.warn("SYNC_VULNS probe failed: {}", e.getMessage()); }

        log.info("Tenable detected capabilities: {}", caps);
        return caps;
    }

    // ── Asset sync: GET /workbenches/assets ───────────────────────────────────

    /**
     * Fetches all assets from GET /assets (paginated).
     * Response: { "assets": [...], "total": N }
     * Field names per asset: ipv4[], fqdn[], hostname[] (arrays).
     */
    public FetchResult fetchAllAssets(String settingsJson, Map<String, String> creds) throws Exception {
        String base = baseUrl(settingsJson);
        String auth = authHeader(creds);
        log.info("Tenable fetchAllAssets: base={} accessKey={}...",
            base, creds.getOrDefault("accessKey", "").substring(0, Math.min(6, creds.getOrDefault("accessKey", "").length())));

        List<JsonNode> out = new ArrayList<>();
        int limit  = 100;
        int offset = 0;
        int total  = Integer.MAX_VALUE;
        String lastBody = null;

        while (offset < total) {
            String url = base + "/assets?limit=" + limit + "&offset=" + offset;
            HttpResponse<String> resp = http.send(get(url, auth), HttpResponse.BodyHandlers.ofString());
            lastBody = resp.body();

            log.info("GET {} → HTTP {} body[0-600]={}",
                url, resp.statusCode(), snippet(resp.body(), 600));

            if (resp.statusCode() != 200)
                throw new RuntimeException("GET /assets failed: HTTP " + resp.statusCode()
                    + " " + snippet(resp.body(), 300));

            JsonNode root = objectMapper.readTree(resp.body());
            total = root.path("total").asInt(0);

            JsonNode assets = root.has("assets") ? root.path("assets") : root;
            if (!assets.isArray()) {
                log.warn("Unexpected /assets structure — top-level keys: {}", root.fieldNames());
                return new FetchResult(out, url, snippet(resp.body(), 400));
            }

            int pageSize = 0;
            for (JsonNode a : assets) { out.add(a); pageSize++; }
            log.info("GET /assets offset={} → {} assets this page, {} total, {} fetched so far",
                offset, pageSize, total, out.size());

            if (pageSize == 0) break;   // guard against infinite loop if API misbehaves
            offset += pageSize;
        }

        log.info("Tenable /assets: fetched {} of {} total assets", out.size(), total == Integer.MAX_VALUE ? "?" : total);
        String diag = out.isEmpty() ? snippet(lastBody, 400) : null;
        return new FetchResult(out, base + "/assets", diag);
    }

    public record FetchResult(List<JsonNode> assets, String endpointUsed, String rawResponseSnippet) {}

    // ── Vuln sync: POST /vulns/export ─────────────────────────────────────────

    /**
     * Initiates a vulnerability export for open/reopened findings only.
     * Returns the export UUID.
     */
    public String initiateVulnExport(String settingsJson, Map<String, String> credentials) throws Exception {
        String base = baseUrl(settingsJson);
        // Export open, reopened AND fixed so we can transition detections to "fixed"
        String body = """
            {"num_assets":500,"filters":{"state":["open","reopened","fixed"]}}
            """;
        HttpResponse<String> resp = http.send(
            post(base + "/vulns/export", authHeader(credentials), body),
            HttpResponse.BodyHandlers.ofString());
        log.debug("POST /vulns/export HTTP {} body={}", resp.statusCode(), snippet(resp.body()));
        expectStatus(resp, 200, "vuln export initiation");
        String uuid = objectMapper.readTree(resp.body()).path("export_uuid").asText(null);
        if (uuid == null || uuid.isBlank())
            throw new RuntimeException("Tenable did not return export_uuid. Body: " + snippet(resp.body()));
        log.info("Tenable vuln export initiated uuid={}", uuid);
        return uuid;
    }

    /**
     * Polls until the vuln export is FINISHED. Returns the full status JSON node.
     * Status response fields: status, chunks_available (int array), chunks_available_count,
     * total_chunks, finished_chunks.
     *
     * @param isCancelled checked between attempts; when it returns true the poll loop stops
     *                    immediately instead of continuing to hit Tenable in the background
     *                    after the caller's job has been cancelled.
     */
    public JsonNode pollVulnExport(String exportUuid, String settingsJson, Map<String, String> creds,
                                   java.util.function.BooleanSupplier isCancelled)
            throws Exception {
        String base = baseUrl(settingsJson);
        String auth = authHeader(creds);
        String path = base + "/vulns/export/" + exportUuid + "/status";

        for (int attempt = 0; attempt < POLL_MAX_ATTEMPTS; attempt++) {
            if (isCancelled.getAsBoolean()) {
                log.info("Tenable vuln export {} polling stopped — job was cancelled", exportUuid);
                throw new CancellationException("Tenable vuln export polling cancelled");
            }

            HttpResponse<String> resp = http.send(get(path, auth), HttpResponse.BodyHandlers.ofString());
            expectStatus(resp, 200, "vuln export status poll");
            JsonNode node = objectMapper.readTree(resp.body());
            String status = node.path("status").asText();
            log.debug("Tenable vuln export status={} chunks_available_count={} attempt={}/{}",
                status, node.path("chunks_available_count").asInt(-1), attempt + 1, POLL_MAX_ATTEMPTS);

            if ("FINISHED".equalsIgnoreCase(status)) {
                log.info("Tenable vuln export FINISHED. Full status: {}", resp.body());
                return node;
            }
            if ("ERROR".equalsIgnoreCase(status) || "CANCELLED".equalsIgnoreCase(status))
                throw new RuntimeException("Tenable vuln export " + status
                    + ": " + node.path("message").asText("no details"));
            if (attempt < POLL_MAX_ATTEMPTS - 1) Thread.sleep(POLL_DELAY_MS);
        }
        throw new RuntimeException("Tenable vuln export did not finish in " + POLL_MAX_ATTEMPTS + " attempts");
    }

    /**
     * Downloads all available vuln chunks. Chunk IDs come from statusNode.chunks_available[] (int array).
     * Each chunk is a JSON array of vuln records.
     */
    public List<JsonNode> getVulnChunks(String exportUuid, JsonNode statusNode,
                                         String settingsJson, Map<String, String> creds) throws Exception {
        String base = baseUrl(settingsJson);
        String auth = authHeader(creds);
        List<Integer> chunkIds = resolveChunkIds(statusNode);
        log.info("Tenable vuln export: downloading {} chunks", chunkIds.size());

        List<JsonNode> chunks = new ArrayList<>();
        for (int chunkId : chunkIds) {
            HttpResponse<String> resp = http.send(
                get(base + "/vulns/export/" + exportUuid + "/chunks/" + chunkId, auth),
                HttpResponse.BodyHandlers.ofString());
            expectStatus(resp, 200, "vuln chunk " + chunkId);
            JsonNode node = objectMapper.readTree(resp.body());
            log.debug("Vuln chunk {} size={}", chunkId,
                node.isArray() ? node.size() : "object-wrapped");
            chunks.add(node);
        }
        return chunks;
    }

    // ── MSSP account list ─────────────────────────────────────────────────────

    public record MsspAccount(String id, String name) {}

    /**
     * Lists all managed accounts visible to the MSSP admin credentials.
     * Calls GET /mssp/accounts and returns a flat list of {id, name} records
     * (id is the child container UUID needed by {@link #generateChildAccountKeys}).
     */
    public List<MsspAccount> listMsspAccounts(String settingsJson, Map<String, String> creds) throws Exception {
        String base = baseUrl(settingsJson);
        String auth = authHeader(creds);
        HttpResponse<String> resp = http.send(get(base + "/mssp/accounts", auth), HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200)
            throw new RuntimeException("GET /mssp/accounts failed: HTTP " + resp.statusCode()
                + " — " + snippet(resp.body()));
        JsonNode root = objectMapper.readTree(resp.body());
        JsonNode items = root.isArray() ? root : root.path("accounts");
        if (!items.isArray())
            throw new RuntimeException("Unexpected /mssp/accounts response shape: " + snippet(resp.body()));
        List<MsspAccount> result = new ArrayList<>();
        for (JsonNode a : items) {
            String id   = a.path("uuid").asText(a.path("container_uuid").asText(a.path("id").asText(null)));
            String name = a.path("name").asText(a.path("container_name").asText(id));
            if (id != null && !id.isBlank()) result.add(new MsspAccount(id, name));
        }
        return result;
    }

    /**
     * Mints temporary access/secret keys scoped to one MSSP-managed child account.
     * Per Tenable's MSSP key-generation flow: POST /mssp/accounts/mssp-child-keys with the
     * MSSP admin's own X-ApiKeys credentials (Administrator role required), returning a
     * short-lived {@code access_key}/{@code secret_key} pair that authenticates directly
     * against standard VM endpoints (/assets, /vulns/export, ...) as that child account.
     * There is no "impersonation" header on those endpoints — the child keys ARE the auth.
     */
    public Map<String, String> generateChildAccountKeys(String settingsJson, Map<String, String> parentCreds,
                                                          String childContainerUuid) throws Exception {
        String base = baseUrl(settingsJson);
        String auth = authHeader(parentCreds);
        String body = objectMapper.writeValueAsString(Map.of(
            "child_container_uuid", childContainerUuid,
            "keys_validity_duration_seconds", 3600
        ));
        HttpResponse<String> resp = http.send(
            post(base + "/mssp/accounts/mssp-child-keys", auth, body),
            HttpResponse.BodyHandlers.ofString());
        expectStatus(resp, 200, "generate MSSP child-account keys for " + childContainerUuid);

        JsonNode node = objectMapper.readTree(resp.body());
        String accessKey = node.path("access_key").asText(null);
        String secretKey = node.path("secret_key").asText(null);
        if (accessKey == null || accessKey.isBlank() || secretKey == null || secretKey.isBlank())
            throw new RuntimeException("Tenable did not return access_key/secret_key for child account "
                + childContainerUuid + ". Body: " + snippet(resp.body()));
        log.info("Tenable MSSP: generated temporary child-account keys for account={}", childContainerUuid);
        return Map.of("accessKey", accessKey, "secretKey", secretKey);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Resolves chunk IDs from the export status node.
     * The Tenable VM API uses "chunks_available" = int array of available chunk IDs.
     * Falls back to generating 1..chunks_available_count if the array is absent.
     */
    private List<Integer> resolveChunkIds(JsonNode statusNode) {
        JsonNode available = statusNode.path("chunks_available");
        if (available.isArray() && available.size() > 0) {
            List<Integer> ids = new ArrayList<>();
            for (JsonNode n : available) ids.add(n.asInt());
            return ids;
        }
        int count = statusNode.path("chunks_available_count").asInt(0);
        List<Integer> ids = new ArrayList<>();
        for (int i = 1; i <= count; i++) ids.add(i);
        return ids;
    }

    protected HttpRequest get(String url, String auth) {
        return HttpRequest.newBuilder()
            .uri(URI.create(url))
            .header("X-ApiKeys", auth)
            .header("Accept", "application/json")
            .timeout(Duration.ofSeconds(60))
            .GET().build();
    }

    protected HttpRequest post(String url, String auth, String body) {
        return HttpRequest.newBuilder()
            .uri(URI.create(url))
            .header("X-ApiKeys", auth)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .timeout(Duration.ofSeconds(30))
            .POST(HttpRequest.BodyPublishers.ofString(body)).build();
    }

    protected void expectStatus(HttpResponse<String> resp, int expected, String ctx) {
        if (resp.statusCode() != expected)
            throw new RuntimeException("Tenable " + ctx + " failed: HTTP " + resp.statusCode()
                + " body=" + snippet(resp.body()));
    }

    protected String authHeader(Map<String, String> creds) {
        return "accessKey=" + creds.getOrDefault("accessKey", "")
            + "; secretKey=" + creds.getOrDefault("secretKey", "");
    }

    protected String baseUrl(String settingsJson) {
        if (settingsJson == null || settingsJson.isBlank()) return DEFAULT_BASE_URL;
        try {
            JsonNode n = objectMapper.readTree(settingsJson);
            String url = n.path("baseUrl").asText(null);
            return (url != null && !url.isBlank()) ? url.replaceAll("/$", "") : DEFAULT_BASE_URL;
        } catch (Exception e) { return DEFAULT_BASE_URL; }
    }

    private static String snippet(String s) { return snippet(s, 300); }

    private static String snippet(String s, int max) {
        if (s == null) return "null";
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }
}
