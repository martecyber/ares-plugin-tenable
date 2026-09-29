package com.martecyber.plugins.tenable;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.martecyber.ares.assets.AssetLinkType;
import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.AssetMetadataKeys;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;
import com.martecyber.ares.imports.ParsedDetection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Maps Tenable vuln export chunks → ParseResult (detections + assets derived from vuln records).
 *
 * Source: GET /vulns/export/{uuid}/chunks/{id} — each chunk is a JSON array.
 *
 * Each vuln record structure:
 *   asset.fqdn      → string (singular, not array) — host identifier
 *   asset.hostname  → string
 *   asset.ipv4      → string
 *   port.port/protocol/service → open-port info; port=0 means no network port (skipped)
 *   plugin.id       → int → sourceTemplateId
 *   plugin.name     → string → detection title
 *   severity        → "critical"|"high"|"medium"|"low"|"info"
 *   state           → "open"|"reopened"|"fixed" (we already filter to open/reopened at export time)
 *   plugin.cvss3_base_score / plugin.cvss_base_score → raw CVSS data stored in rawData
 */
public class TenableVulnParser {

    private static final Logger log = LoggerFactory.getLogger(TenableVulnParser.class);
    private final ObjectMapper objectMapper;

    public TenableVulnParser(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * Parses vuln export chunks into detections.
     * Also extracts assets embedded in each vuln record for cross-linking.
     */
    public ParseResult parseVulns(List<JsonNode> chunks) {
        ParseResult result = new ParseResult();
        int raw = 0;
        for (JsonNode chunk : chunks) {
            JsonNode items = unwrap(chunk);
            if (items == null || !items.isArray()) {
                log.warn("Skipping non-array vuln chunk: type={}", chunk.getNodeType());
                continue;
            }
            raw += items.size();
            for (JsonNode vuln : items) parseVuln(vuln, result);
        }
        log.info("TenableVulnParser: {} raw → {} detections, {} assets",
            raw, result.getDetections().size(), result.getAssets().size());
        return result;
    }

    private void parseVuln(JsonNode vuln, ParseResult result) {
        JsonNode plugin = vuln.path("plugin");
        String pluginId   = String.valueOf(plugin.path("id").asLong(0));
        String pluginName = plugin.path("name").asText("Unknown vulnerability");
        String severity   = vuln.path("severity").asText("info");
        String state      = vuln.path("state").asText("open").toLowerCase();

        // Asset embedded in each vuln record (singular string fields)
        JsonNode assetNode = vuln.path("asset");
        String assetIdentifier = resolveAssetIdentifier(assetNode);

        // Also add the asset to ParseResult so resolveOrCreate creates it if needed
        // Skip asset creation for fixed vulns — if the asset doesn't exist yet, no need to create it
        if (!"fixed".equals(state)) addAssetFromVuln(vuln, result);

        String rawData = buildRawData(vuln);
        String description = plugin.path("synopsis").asText(null);

        ParsedDetection detection = new ParsedDetection(
            pluginName, severity, description, assetIdentifier, pluginId, rawData, state
        );
        applyCvss(plugin, detection);
        result.addDetection(detection);
    }

    /**
     * Tenable reports at most one CVSS score per plugin (not per CVE, even when a plugin lists
     * several CVEs) — prefer CVSS 3.x when present, fall back to 2.0. Version string must match
     * finding_score_type.title exactly so ImportService can resolve the FK by title.
     */
    private void applyCvss(JsonNode plugin, ParsedDetection detection) {
        JsonNode cvss3 = plugin.path("cvss3_base_score");
        if (!cvss3.isMissingNode() && !cvss3.isNull()) {
            detection.setCvssScore(java.math.BigDecimal.valueOf(cvss3.asDouble()));
            detection.setCvssVersion("CVSS 3.1");
            detection.setCvssVector(plugin.path("cvss3_vector").asText(null));
            return;
        }
        JsonNode cvss2 = plugin.path("cvss_base_score");
        if (!cvss2.isMissingNode() && !cvss2.isNull()) {
            detection.setCvssScore(java.math.BigDecimal.valueOf(cvss2.asDouble()));
            detection.setCvssVersion("CVSS 2.0");
            detection.setCvssVector(plugin.path("cvss_vector").asText(null));
        }
    }

    /**
     * Derive the asset identifier from the vuln record's embedded asset. Always "host-"+ipv4 —
     * an internal join key, not the host's Name (see AssetImportHelper) — so detections
     * resolve to whatever host AssetImportHelper decides owns this IP, never to a stale
     * duplicate keyed by a hostname/fqdn string. Records without an ipv4 have no stable
     * identity to key off and are skipped (matches addAssetFromVuln).
     */
    private String resolveAssetIdentifier(JsonNode asset) {
        String ipv4 = asset.path("ipv4").asText(null);
        if (ipv4 != null && !ipv4.isBlank()) return "host-" + ipv4.trim();
        return null;
    }

    /**
     * Adds host → interface → ip (→ service) chain from the vuln record. Host identity is
     * always "host-{ip}" (see resolveAssetIdentifier); hostname is carried as a hint merged
     * into the resolved host's `hostnames` list instead of driving its identifier. Vuln
     * records contain only one IP, so there is always exactly one interface.
     */
    private void addAssetFromVuln(JsonNode vuln, ParseResult result) {
        JsonNode asset  = vuln.path("asset");
        String hostname = asset.path("hostname").asText(null);
        String fqdn     = asset.path("fqdn").asText(null);
        String ipv4     = asset.path("ipv4").asText(null);
        String uuid     = asset.path("uuid").asText(null);

        if (ipv4 == null || ipv4.isBlank()) return;
        String ip = ipv4.trim();
        String hostId = "host-" + ip;

        Map<String, Object> hostMeta = new LinkedHashMap<>();
        if (hostname != null && !hostname.isBlank()) {
            hostMeta.put(AssetMetadataKeys.HOSTNAME_HINTS_KEY, List.of(hostname.toLowerCase().trim()));
        }
        // Same stable-identity fix as TenableAssetParser: resolve by Tenable's own asset uuid
        // first, so a host doesn't get duplicated when its active IP drifts between syncs.
        if (uuid != null && !uuid.isBlank()) {
            hostMeta.put(AssetMetadataKeys.EXTERNAL_ID_TOOL_KEY, "tenable");
            hostMeta.put(AssetMetadataKeys.EXTERNAL_ID_VALUE_KEY, uuid.trim());
        }
        result.addAsset(new ParsedAsset(hostId, AssetType.HOST, hostMeta));

        String ifaceId = "iface-" + ip;
        result.addAsset(new ParsedAsset(ifaceId, AssetType.INTERFACE,
            Map.of("ip", ip, "host", hostId)));
        result.addAsset(new ParsedAsset(ip, AssetType.IP));
        result.addLink(hostId, ifaceId, AssetLinkType.HOST_INTERFACE);
        result.addLink(ifaceId, ip,     AssetLinkType.INTERFACE_IP);

        // Service asset from the vuln's port info, if any. Tenable uses port=0 for
        // checks with no associated network port (e.g. local/registry checks), so
        // only emit a SERVICE asset when a real port is reported.
        JsonNode portNode = vuln.path("port");
        int port = portNode.path("port").asInt(0);
        if (port > 0) {
            String protocol = portNode.path("protocol").asText("tcp").toLowerCase();
            String serviceName = portNode.path("service").asText(null);
            String serviceId = ip + ":" + port + "/" + protocol;

            Map<String, Object> svcMeta = new LinkedHashMap<>();
            svcMeta.put("port", port);
            svcMeta.put("protocol", protocol);
            if (serviceName != null && !serviceName.isBlank()) svcMeta.put("service", serviceName);

            result.addAsset(new ParsedAsset(serviceId, AssetType.SERVICE, svcMeta));
            result.addLink(ifaceId, serviceId, AssetLinkType.INTERFACE_SERVICE);
        }

        // FQDN asset (only when distinct from hostname) — no domain_a link: Tenable's vuln
        // records carry no DNS record type/chain metadata, only DNS-record-aware tools (dnsx)
        // create domain_a/domain_aaaa relationships.
        if (fqdn != null && !fqdn.isBlank() && !fqdn.equalsIgnoreCase(hostname)) {
            String domainId = fqdn.toLowerCase().trim();
            result.addAsset(new ParsedAsset(domainId, AssetType.DOMAIN));
        }
    }

    /** Stores the complete vuln record Tenable returned, not a curated subset — so any field
     *  this parser's own logic doesn't act on (full description, risk factor, exploitability,
     *  see_also, port/output, patch dates, ...) still reaches raw_data for an operator to check,
     *  same convention every other integration's VulnParser (Action1/CrowdStrike/FortiRecon/
     *  Qualys) already follows. One derived field is added on top: {@code cwe_refs}, because
     *  plugin.xrefs entries are {"type":"CWE","id":"79"} objects whose serialized shape doesn't
     *  match DetectionReferenceExtractor's CWE-\d+ regex — reformatted as plain "CWE-79" strings
     *  so that extractor still finds them. plugin.cve needs no such treatment: its entries are
     *  already literal "CVE-2023-1234" strings, so the regex finds them straight in the full dump. */
    private String buildRawData(JsonNode vuln) {
        try {
            ObjectNode raw = vuln.deepCopy();
            JsonNode xrefs = vuln.path("plugin").path("xrefs");
            if (xrefs.isArray()) {
                var cweRefs = objectMapper.createArrayNode();
                for (JsonNode xref : xrefs) {
                    if ("CWE".equalsIgnoreCase(xref.path("type").asText(""))) {
                        String id = xref.path("id").asText(null);
                        if (id != null && !id.isBlank()) cweRefs.add("CWE-" + id);
                    }
                }
                if (cweRefs.size() > 0) raw.set("cwe_refs", cweRefs);
            }
            return objectMapper.writeValueAsString(raw);
        } catch (Exception e) { return null; }
    }

    private JsonNode unwrap(JsonNode chunk) {
        if (chunk.isArray()) return chunk;
        // Some export responses wrap the array
        if (chunk.isObject() && chunk.has("vulnerabilities")) return chunk.get("vulnerabilities");
        return null;
    }
}
