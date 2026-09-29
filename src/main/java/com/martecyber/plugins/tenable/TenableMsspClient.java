package com.martecyber.plugins.tenable;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.http.HttpResponse;
import java.util.Map;

/**
 * Tenable MSSP integration — identical to Tenable Account but:
 *  - testConnection also verifies MSSP admin access (GET /mssp/accounts).
 *  - All data-fetching calls carry X-Impersonate-Account: <msspAccountId>
 *    (injected into the credentials map from the grant's accountId before sync).
 *  - Separate integration type ("tenable-mssp") so it appears as a distinct
 *    entry in the integration type picker with account selection at grant time.
 */
public class TenableMsspClient extends TenableClient {

    public TenableMsspClient(ObjectMapper objectMapper) {
        super(objectMapper);
    }

    @Override
    public String supports() { return "tenable-mssp"; }

    /** Also verifies that the credentials have MSSP admin access. */
    @Override
    public void testConnection(String settingsJson, Map<String, String> credentials) throws Exception {
        // Standard credential check
        super.testConnection(settingsJson, credentials);
        // MSSP-specific: verify /mssp/accounts is accessible
        String base = baseUrl(settingsJson);
        String auth = authHeader(credentials);
        HttpResponse<String> resp = http.send(
            get(base + "/mssp/accounts", auth),
            HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200)
            throw new RuntimeException(
                "Tenable MSSP access check failed: HTTP " + resp.statusCode()
                + " — credentials may lack MSSP admin privileges.");
    }
}
