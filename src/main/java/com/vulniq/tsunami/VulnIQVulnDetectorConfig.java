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

import com.google.tsunami.common.config.annotations.ConfigProperties;

/**
 * This is how it should look like in tsunami.yaml
 *
 * plugins:
 *   vulniq_vuln_detector:
 *     engineBaseUrl: https://free.vulniq.com
 *     ovalXMLUrl: /api/oval/xml
 *     ...
 */
@ConfigProperties("plugins.vulniq_vuln_detector")
final class VulnIQVulnDetectorConfig
{
    String engineBaseUrl = "https://free.vulniq.com";

    //access token to be used to call VulnIQ services
    String accessToken;

    //VulnIQ API endpoints, do not change unless you know what you are doing
    String vulnsByVPVUrl = "/api/vulnerability/list-by-vpv";

    String vulnIQLinkFormatString = "https://free.vulniq.com/data/%s/info";
}
