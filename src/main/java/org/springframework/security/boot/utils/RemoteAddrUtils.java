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
import org.apache.commons.lang3.StringUtils;

/**
 * http://blog.csdn.net/caoshuming_500/article/details/20952329
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
public class RemoteAddrUtils {

	private static String[] HEADERS = new String[]{"Cdn-Src-Ip", "X-Real-IP", "X-Forwarded-For", "Proxy-Client-IP", "WL-Proxy-Client-IP", "HTTP_CLIENT_IP", "HTTP_X_FORWARDED_FOR"};
	private static String LOCALIP = "127.0.0.1";
	private static String LOCALHOST = "localhost";  
	private static String UNKNOWN = "unknown";
	
	/**
	 * 
	 * 获取请求客户端IP地址，支持代理服务器
	 * @author <a href="https://github.com/loong10k">Loong Wan</a>
	 * @param request the HttpServletRequest
	 * @return the Remote Addr
	 */
	public static String getRemoteAddr(HttpServletRequest request) {
		
		// 1、获取客户端IP地址，支持代理服务器
		String remoteAddr = null;
		for (String header : HEADERS) {
			remoteAddr = request.getHeader(header);
			if(!StringUtils.isEmpty(remoteAddr) && !StringUtils.equals(remoteAddr, UNKNOWN)){
				break;
			}
		}
		// 2、没有取得特定标记的值
		if(StringUtils.isEmpty(remoteAddr) ){
			remoteAddr = request.getRemoteAddr();
		}
		
		// 3、判断是否localhost访问
		if(StringUtils.equals(remoteAddr, LOCALHOST)){
			remoteAddr = LOCALIP;
		}
		 
		return remoteAddr;
	}
}
