/*
 * Copyright (c) 2018, hiwepy (https://github.com/easy-4-java).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.biz.authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.springframework.security.boot.biz.filter.HttpParamsFilter;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

/**
 * Netease Url Authentication Success Handler
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
public class NeteaseUrlAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    public NeteaseUrlAuthenticationSuccessHandler() {
        super();
    }

    public NeteaseUrlAuthenticationSuccessHandler(String defaultTargetUrl) {
        super(defaultTargetUrl);
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
        if (isAlwaysUseDefaultTargetUrl()) {
            return this.getDefaultTargetUrl();
        }

        // Check for the parameter and use that if available
        String targetUrl = null;

        if (this.getTargetUrlParameter() != null) {
            targetUrl = request.getParameter(this.getTargetUrlParameter());

            if (StringUtils.hasText(targetUrl)) {
                logger.debug("Found targetUrlParameter in request: " + targetUrl);

                return targetUrl;
            }
        }

        if (!StringUtils.hasText(targetUrl)) {
            HttpSession session = request.getSession();
            targetUrl = (String) session.getAttribute(HttpParamsFilter.REQUESTED_URL);
        }

        if (!StringUtils.hasText(targetUrl)) {
            targetUrl = this.getDefaultTargetUrl();
            logger.debug("Using default Url: " + targetUrl);
        }

        return targetUrl;
    }
}