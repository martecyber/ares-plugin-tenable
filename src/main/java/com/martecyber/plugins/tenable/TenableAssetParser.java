package com.martecyber.plugins.tenable;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.martecyber.ares.assets.AssetLinkType;
import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.AssetMetadataKeys;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Maps Tenable asset records (GET /assets) → ParseResult.
 *
 * Produces the full host → interface → ip chain (same model as nmap):
 *   host      "host-{ip}" — an internal join key only; see below
 *   interface identified by MAC address (or "iface-{ip}" when MAC unknown)
 *   ip        the IPv4 address
 *
 * Links emitted:
 *   host → interface  HOST_INTERFACE  (exclusive: interface belongs to 1 host)
 *   interface → ip    INTERFACE_IP    (exclusive: ip belongs to 1 interface)
 *   domain → ip       DOMAIN_A        (when FQDN is a DNS A-record for a single IP)
 *
 * Host identity: the HOST ParsedAsset's identifier is always "host-{primary active ip}" —
 * an internal join key resolved to the real (possibly pre-existing) host identity by
 * AssetImportHelper, never derived from hostname text directly (this is what keeps host
 * identity stable across a hostname change for the same IP). Any hostname/netbios_name
 * candidates are carried as hints (AssetMetadataKeys.HOSTNAME_HINTS_KEY) merged into the
 * resolved host's `hostnames` list instead.
 * Interface identifier: MAC address > "iface-{ip}" (per IP, one interface each)
 *
 * Only the currently active IP is used for host_interface / interface_ip links.
 * Active IP detection:
 *   - network-scanned assets: last_scan_target (most recent scan)
 *   - agent-scanned assets:   all IPs in the array (agent reports live state)
 *   - unknown:                all IPs (no better signal)
 */
public class TenableAssetParser {

    private static final Logger log = LoggerFactory.getLogger(TenableAssetParser.class);

    public ParseResult parseAssets(List<JsonNode> assets) {
        ParseResult result = new ParseResult();
        for (JsonNode asset : assets) parseAsset(asset, result);
        log.info("TenableAssetParser: {} raw → {} assets {} links",
            assets.size(), result.getAssets().size(), result.getLinks().size());
        return result;
    }

    private void parseAsset(JsonNode asset, ParseResult result) {
        JsonNode ipv4Array     = getArray(asset, "ipv4", "ipv4s");
        JsonNode fqdnArray     = getArray(asset, "fqdn", "fqdns");
        JsonNode hostnameArray = getArray(asset, "hostname", "hostnames");
        JsonNode macArray      = getArray(asset, "mac_address", "mac_addresses");

        // ── Determine active IPs ──────────────────────────────────────────────
        // Tenable accumulates historical IPs in the ipv4 array. We only create
        // host↔interface↔ip chains for IPs believed to be currently active.
        //
        // Signal                           Action
        // -------------------------------- -----------------------------------
        // last_scan_target present         Only that IP is the active one
        // has_agent=true, no scan target   All IPs (agent reports live state)
        // Neither                          All IPs (no better signal)

        boolean hasAgent = asset.path("has_agent").asBoolean(false);
        String lastScanTarget = asset.path("last_scan_target").asText(null);
        if (lastScanTarget != null && lastScanTarget.isBlank()) lastScanTarget = null;

        List<String> allIps = new ArrayList<>();
        if (ipv4Array.isArray()) {
            for (JsonNode ip : ipv4Array) {
                String s = ip.asText("").trim();
                if (!s.isEmpty()) allIps.add(s);
            }
        }

        List<String> activeIps;
        if (lastScanTarget != null) {
            activeIps = List.of(lastScanTarget);
        } else {
            activeIps = allIps;
        }

        if (activeIps.isEmpty()) {
            log.debug("Skipping Tenable asset with no usable IP: tenable_id={}",
                asset.path("id").asText("?"));
            return;
        }

        // Host identity is always "host-{primary active ip}" — an internal join key, not the
        // final Name. Hostname/netbios_name candidates are hints merged into the resolved
        // host's `hostnames` list by AssetImportHelper, never used to derive the identifier.
        String hostId = "host-" + activeIps.get(0);

        List<String> hostnameHints = new ArrayList<>();
        if (hostnameArray.isArray()) {
            for (JsonNode h : hostnameArray) {
                String v = h.asText("").toLowerCase().trim();
                if (!v.isEmpty()) hostnameHints.add(v);
            }
        }
        String netbios = asset.path("netbios_name").asText(null);
        if (netbios != null && !netbios.isBlank()) hostnameHints.add(netbios.toLowerCase().trim());

        // Primary MAC (used for all interfaces of this asset when only 1 IP is active)
        String primaryMac = null;
        if (macArray.isArray() && macArray.size() > 0)
            primaryMac = macArray.get(0).asText(null);

        // ── Host asset ────────────────────────────────────────────────────────
        Map<String, Object> hostMeta = buildHostMetadata(asset);
        if (!hostnameHints.isEmpty()) hostMeta.put(AssetMetadataKeys.HOSTNAME_HINTS_KEY, hostnameHints);
        // Tenable's own asset.id survives an active-IP change across syncs (DHCP reassignment,
        // agent vs. network scan reporting a different NIC) — resolve by it first instead of
        // only by IP/interface, which previously created a duplicate HOST whenever the active
        // IP drifted. See AssetImportHelper.EXTERNAL_ID_* / resolveOrCreateHost.
        String tenableAssetId = asset.path("id").asText(null);
        if (tenableAssetId != null && !tenableAssetId.isBlank()) {
            hostMeta.put(AssetMetadataKeys.EXTERNAL_ID_TOOL_KEY, "tenable");
            hostMeta.put(AssetMetadataKeys.EXTERNAL_ID_VALUE_KEY, tenableAssetId.trim());
        }
        result.addAsset(new ParsedAsset(hostId, AssetType.HOST, hostMeta));

        // ── Interface → IP chain for each active IP ───────────────────────────
        for (String ip : activeIps) {
            // Interface identifier: MAC when only one active IP, else iface-{ip}
            String ifaceId = (primaryMac != null && activeIps.size() == 1)
                ? primaryMac.toLowerCase()
                : "iface-" + ip;

            result.addAsset(new ParsedAsset(ifaceId, AssetType.INTERFACE,
                Map.of("ip", ip, "host", hostId)));
            result.addAsset(new ParsedAsset(ip, AssetType.IP));

            result.addLink(hostId, ifaceId, AssetLinkType.HOST_INTERFACE);
            result.addLink(ifaceId, ip,     AssetLinkType.INTERFACE_IP);
        }

        // ── Domain assets from FQDNs ──────────────────────────────────────────
        // Asset only, no domain_a link: Tenable's asset inventory reports FQDN↔IP
        // associations with no DNS record type/chain metadata (could be a CNAME alias
        // resolved through an intermediate domain) — only DNS-record-aware tools (dnsx)
        // create domain_a/domain_aaaa relationships.
        if (fqdnArray.isArray()) {
            for (JsonNode fqdn : fqdnArray) {
                String domainId = fqdn.asText("").toLowerCase().trim();
                if (domainId.isEmpty()) continue;
                result.addAsset(new ParsedAsset(domainId, AssetType.DOMAIN));
            }
        }
    }

    // ── Metadata builder ──────────────────────────────────────────────────────

    private Map<String, Object> buildHostMetadata(JsonNode asset) {
        Map<String, Object> meta = new LinkedHashMap<>();

        putStr(meta, "tenable_id",   asset.path("id").asText(null));
        putStr(meta, "netbios_name", asset.path("netbios_name").asText(null));

        JsonNode macArr = getArray(asset, "mac_address", "mac_addresses");
        if (macArr.isArray() && macArr.size() > 0)
            putStr(meta, "mac_address", macArr.get(0).asText(null));

        meta.put("has_agent", asset.path("has_agent").asBoolean(false));
        putStr(meta, "agent_uuid",         asset.path("agent_uuid").asText(null));
        putStr(meta, "last_seen_tenable",  asset.path("last_seen").asText(null));
        putStr(meta, "first_seen_tenable", asset.path("first_seen").asText(null));

        if (!asset.path("acr_score").isMissingNode() && !asset.path("acr_score").isNull())
            meta.put("acr_score", asset.path("acr_score").asInt());

        JsonNode sources = asset.path("sources");
        if (sources.isArray() && sources.size() > 0) {
            List<String> names = new ArrayList<>();
            for (JsonNode s : sources) {
                String n = s.path("name").asText(null);
                if (n != null) names.add(n);
            }
            if (!names.isEmpty()) meta.put("sources", names);
        }

        return meta;
    }

    private void putStr(Map<String, Object> map, String key, String value) {
        if (value != null && !value.isBlank()) map.put(key, value);
    }

    private JsonNode getArray(JsonNode node, String singular, String plural) {
        JsonNode v = node.path(singular);
        if (v.isArray()) return v;
        v = node.path(plural);
        if (v.isArray()) return v;
        return JsonNodeFactory.instance.arrayNode();
    }
}
