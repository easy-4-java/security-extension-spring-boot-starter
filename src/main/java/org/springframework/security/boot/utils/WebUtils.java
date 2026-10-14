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
package org.springframework.security.boot.utils;

import javax.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.savedrequest.SavedRequest;

/**
 * Spring WebUtils 扩展
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
public class WebUtils extends org.springframework.web.util.WebUtils {

	private static final String XML_HTTP_REQUEST = "XMLHttpRequest";
    private static final String X_REQUESTED_WITH = "X-Requested-With";
    private static final String CONTENT_TYPE_JSON = "application/json";

	public static boolean isAjaxResponse(HttpServletRequest request) {
		return isAjaxRequest(request) || isContentTypeJson(request) || isPostRequest(request);
	}

    public static boolean isObjectRequest(HttpServletRequest request) {
        return isPostRequest(request) && isContentTypeJson(request);
    }

    public static boolean isObjectRequest(SavedRequest request) {
        return isPostRequest(request) && isContentTypeJson(request);
    }
    
    public static boolean isAjaxRequest(HttpServletRequest request) {
        return XML_HTTP_REQUEST.equals(request.getHeader(X_REQUESTED_WITH));
    }
    
    public static boolean isAjaxRequest(SavedRequest request) {
        return request.getHeaderValues(X_REQUESTED_WITH).contains(XML_HTTP_REQUEST);
    }

    public static boolean isContentTypeJson(HttpServletRequest request) {
        return request.getHeader(HttpHeaders.CONTENT_TYPE).contains(CONTENT_TYPE_JSON);
    }
    
    public static boolean isContentTypeJson(SavedRequest request) {
        return request.getHeaderValues(HttpHeaders.CONTENT_TYPE).contains(CONTENT_TYPE_JSON);
    }
    
    public static boolean isPostRequest(HttpServletRequest request) {
        return HttpMethod.POST.name().equals(request.getMethod());
    }
    
    public static boolean isPostRequest(SavedRequest request) {
        return HttpMethod.POST.name().equals(request.getMethod());
    }
    
}
