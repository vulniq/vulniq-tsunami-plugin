/*
 * Copyright 2020 VulnIQ
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.vulniq.tsunami;

import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.protobuf.util.Timestamps;
import com.google.tsunami.common.net.http.HttpClient;
import com.google.tsunami.common.net.http.HttpHeaders;
import com.google.tsunami.common.net.http.HttpResponse;
import com.google.tsunami.common.time.UtcClock;
import com.google.tsunami.plugin.PluginType;
import com.google.tsunami.plugin.VulnDetector;
import com.google.tsunami.plugin.annotations.PluginInfo;
import com.google.tsunami.proto.AdditionalDetail;
import com.google.tsunami.proto.DetectionReport;
import com.google.tsunami.proto.DetectionReportList;
import com.google.tsunami.proto.DetectionStatus;
import com.google.tsunami.proto.NetworkService;
import com.google.tsunami.proto.Severity;
import com.google.tsunami.proto.TargetInfo;
import com.google.tsunami.proto.TextData;
import com.google.tsunami.proto.Vulnerability;
import com.google.tsunami.proto.VulnerabilityId;

import javax.inject.Inject;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static com.google.tsunami.common.net.http.HttpRequest.get;

@PluginInfo(
        type = PluginType.VULN_DETECTION,
        name = "VulnIQVulnDetectorPlugin",
        // Current version of your plugin.
        version = "1.0-SNAPSHOT",
        // Detailed description about what this plugin does.
        description = "VulnIQ vulnerability detector plugin reports vulnerabilities based on discovered version numbers.",
        // Author of this plugin.
        author = "VulnIQ (info@vulniq.com)",
        // How should Tsunami scanner bootstrap your plugin.
        bootstrapModule = VulnIQVulnDetectorBootstrapModule.class)

public class VulnIQVulnDetector implements VulnDetector
{
    private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();
    private VulnIQVulnDetectorConfig config;
    private final HttpClient httpClient;
    private final Clock utcClock;
    Map<String, VulnIQVendorProduct> vendorProductMappings = new HashMap<>();

    @Inject
    VulnIQVulnDetector(@UtcClock Clock utcClock, HttpClient httpClient, VulnIQVulnDetectorConfig config)
    {
        this.utcClock = utcClock;
        this.httpClient = httpClient;
        this.config = config;


        //TODO add Nmap service name to VulnIQ product mapping
        // just for the sake of example we have these hardcoded mappings
        vendorProductMappings.put("Apache httpd", new VulnIQVendorProduct("Apache", "http server"));
        vendorProductMappings.put("Elasticsearch REST API", new VulnIQVendorProduct("Elastic", "Elasticsearch"));
    }

    @Override
    public DetectionReportList detect(TargetInfo targetInfo, ImmutableList<NetworkService> matchedServices)
    {
        logger.atInfo().log("VulnIQVulnDetector begin.");
        DetectionReportList.Builder reportListBuilder = DetectionReportList.newBuilder();
        for (NetworkService networkService : matchedServices)
        {
            logger.atInfo().log("VulnIQVulnDetector networkService=" + networkService);

            //TODO there may be a better filtering mechanism
            //we skip if we don't have a version for this software
            if (networkService.getVersionSet().getVersionsCount() > 0)
            {
                logger.atInfo().log("VulnIQVulnDetector processing " +
                        networkService.getNetworkEndpoint().getIpAddress().getAddress() +
                        ":" +
                        networkService.getNetworkEndpoint().getPort().getPortNumber() +
                        " " +
                        networkService.getSoftware().getName() +
                        networkService.getVersionSet().getVersions(0).getFullVersionString()
                );

                JsonObject apiResponse = getVulnerabilities(networkService);
                if (apiResponse != null)
                {
                    if (apiResponse.has("results"))
                    {
                        JsonArray results = apiResponse.get("results").getAsJsonArray();
                        for (JsonElement result : results)
                        {
                            JsonObject vulnObject = result.getAsJsonObject();
                            DetectionReport report = buildDetectionReport(targetInfo, networkService, vulnObject);
                            reportListBuilder.addDetectionReports(report);
                        }
                    }
                    else
                    {
                        logger.atWarning().log("VulnIQ API returned an error response for " +
                                networkService.getNetworkEndpoint().getIpAddress().getAddress() +
                                ":" +
                                networkService.getNetworkEndpoint().getPort().getPortNumber() +
                                " " +
                                networkService.getSoftware().getName() +
                                networkService.getVersionSet().getVersions(0).getFullVersionString() +
                                " VulnIQ API response:" +
                                apiResponse
                        );
                    }
                }
            }
            else
            {
                logger.atInfo().log("VulnIQVulnDetector skipping " +
                        networkService.getNetworkEndpoint().getIpAddress().getAddress() +
                        ":" +
                        networkService.getNetworkEndpoint().getPort().getPortNumber() +
                        " because a version number is not available for it");
            }
        }

        // An example implementation for a VulnDetector.
        return reportListBuilder.build();
    }

    private Map<String, String> getVPVParams(NetworkService networkService)
    {
        try
        {
            Map<String, String> rv = new HashMap<>();
            rv.put("vendorName", vendorProductMappings.get(networkService.getSoftware().getName()).vendor);
            rv.put("productName", vendorProductMappings.get(networkService.getSoftware().getName()).product);
            rv.put("versionName", networkService.getVersionSet().getVersions(0).getFullVersionString());
            return rv;
        }
        catch (Exception ex)
        {
            logger.atSevere().withCause(ex).log("Failed to create query params");
            return null;
        }
    }

    public String getEngineBaseUrl()
    {
        return config.engineBaseUrl;
    }

    public String getVulnsByVPVUrl()
    {
        return config.vulnsByVPVUrl;
    }

    public String getAccessToken()
    {
        return config.accessToken;
    }

    public JsonObject getVulnerabilities(NetworkService networkService)
    {

        Map<String, String> vpvParams = getVPVParams(networkService);
        if (vpvParams == null)
        {
            logger.atInfo().log("Skipping networkService as we don't have a vendor & product mapping for it" + networkService);
            return null;
        }

        StringBuilder url = new StringBuilder(getEngineBaseUrl() + getVulnsByVPVUrl() + "?");
        for (String paramName : vpvParams.keySet())
        {
            url.append("&");
            url.append(paramName);
            url.append("=");
            url.append(urlEncode(vpvParams.get(paramName)));
        }
        HttpResponse response = null;
        try
        {
            HttpHeaders httpHeaders = HttpHeaders.builder()
                    .addHeader("Authorization", "Bearer " + getAccessToken())
                    .build();
            response = httpClient.send(get(url.toString()).setHeaders(httpHeaders).build());
        }
        catch (Exception e)
        {
            logger.atSevere().withCause(e).log("Error fetching " + url);
            return null;
        }
        if (response.status().isSuccess())
        {
            JsonObject parsedResponse = new JsonParser().parse(response.bodyString().get()).getAsJsonObject();
            return parsedResponse;
        }
        else
        {
            logger.atWarning().log("Unexpected response code '" + response.status() + "' from " + url);
            return null;
        }
    }

    private String urlEncode(String param)
    {
        try
        {
            return URLEncoder.encode(param, "UTF-8");
        }
        catch (UnsupportedEncodingException e)
        {
            logger.atSevere().log("This should not happen", e);
        }
        return param;
    }

    // This builds the DetectionReport message for a specifc vulnerable network service.
    private DetectionReport buildDetectionReport(
            TargetInfo targetInfo, NetworkService vulnerableNetworkService, JsonObject vulnFromVulnIQAPI)
    {
        DetectionReport.Builder reportBuilder = DetectionReport.newBuilder();
        reportBuilder.setTargetInfo(targetInfo);
        reportBuilder.setNetworkService(vulnerableNetworkService);
        reportBuilder.setDetectionTimestamp(Timestamps.fromMillis(Instant.now(utcClock).toEpochMilli()));
        reportBuilder.setDetectionStatus(DetectionStatus.VULNERABILITY_PRESENT);
        Vulnerability.Builder vulnBuilder = Vulnerability.newBuilder();
        vulnBuilder.setMainId(
                VulnerabilityId.newBuilder().setValue(vulnFromVulnIQAPI.get("guid").getAsString())
        );
        vulnBuilder.setSeverity(Severity.CRITICAL);
        vulnBuilder.setTitle(vulnFromVulnIQAPI.get("name").getAsString());
        vulnBuilder.setDescription(vulnFromVulnIQAPI.get("description").getAsString());
        vulnBuilder.setSeverity(getTsunamiSeverity(vulnFromVulnIQAPI));
        vulnBuilder.setRecommendation(getVulnIQLink(vulnFromVulnIQAPI.get("guid").getAsString()));
        //TODO add cvss score and other information
        reportBuilder.setVulnerability(vulnBuilder.build());
        return reportBuilder.build();
    }

    private String getVulnIQLink(String vulnIQGuid)
    {
        return String.format(config.vulnIQLinkFormatString, vulnIQGuid);
    }

    /**
     * VulnIQ to Tsunami severity mapping
     *
     * @param vulnFromVulnIQAPI
     * @return
     */
    private Severity getTsunamiSeverity(JsonObject vulnFromVulnIQAPI)
    {
        String dataScore = vulnFromVulnIQAPI.get("dataScore").getAsString();
        switch (dataScore)
        {
            case "Critical":
                return Severity.CRITICAL;
            case "High":
                return Severity.HIGH;
            case "Medium":
                return Severity.MEDIUM;
            case "Low":
                return Severity.LOW;
            case "None":
                return Severity.MINIMAL;
            case "Unknown":
            default:
                return Severity.SEVERITY_UNSPECIFIED;
        }
    }

    private class VulnIQVendorProduct
    {
        public VulnIQVendorProduct(String vendorName, String productName)
        {
            vendor = vendorName;
            product = productName;
        }

        public String vendor;
        public String product;
    }
}
