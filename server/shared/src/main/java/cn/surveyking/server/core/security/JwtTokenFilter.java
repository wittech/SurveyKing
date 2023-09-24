package cn.surveyking.server.core.security;

import cn.hutool.core.date.DateUtil;
import cn.hutool.core.exceptions.ValidateException;
import cn.hutool.core.util.ObjUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSON;
import cn.hutool.json.JSONArray;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import cn.hutool.jwt.JWT;
import cn.hutool.jwt.JWTUtil;
import cn.hutool.jwt.JWTValidator;
import cn.surveyking.server.core.config.WebSecurityConfig;
import cn.surveyking.server.core.constant.AppConsts;
import cn.surveyking.server.core.uitls.ContextHelper;
import cn.surveyking.server.domain.dto.UserInfo;
import cn.surveyking.server.service.UserService;
import lombok.RequiredArgsConstructor;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import static java.util.Optional.ofNullable;
import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.StringUtils.isNotBlank;

/**
 * @author javahuang
 * @date 2021/8/23
 */
@Component
@RequiredArgsConstructor
public class JwtTokenFilter extends OncePerRequestFilter {

	private final JwtTokenUtil jwtTokenUtil;

	private final UserService userService;

	private final RestAuthenticationEntryPoint resolveException;

	protected static final String TOKEN_TYPE_BEARER = "Bearer ";

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
		if (StrUtil.isEmpty(authorizationHeader)) {
			chain.doFilter(request, response);
			return;
		}
		String deviceId = request.getHeader("x-device-id");
		if (StrUtil.isEmpty(deviceId)) {
			deviceId = "Web";
		}
		String accessToken = authorizationHeader.substring(TOKEN_TYPE_BEARER.length());
		if (StrUtil.isEmpty(deviceId) || StrUtil.isEmpty(accessToken)) {
			chain.doFilter(request, response);
			return;
		}
		JWT jwt = JWTUtil.parseToken(accessToken);
		StringRedisTemplate redisTemplate = ContextHelper.getBean(StringRedisTemplate.class);
		Object sub = jwt.getPayload().getClaim("sub");
		String tokenKey = String.format("tokens:%s:%s", sub, deviceId);
		int leeway = 0;
		boolean isInValid = false;
		try {
			JWTValidator.of(jwt).validateDate(DateUtil.date(), leeway);
		} catch (ValidateException e) {
			isInValid = true;
		}
		if (isInValid) {
			// 如果token校验无效，则自动删除掉；
			redisTemplate.opsForHash().delete(tokenKey, accessToken);
			chain.doFilter(request, response);
			return;
		}
		Boolean hasKey = redisTemplate.opsForHash().hasKey(tokenKey, accessToken);
		if (!hasKey) {
			chain.doFilter(request, response);
			return;
		}
		// 从user的缓存中获取user对象的值，如果没有也报错；
		String userCacheKey = String.format("user:%s", sub);
		Object userData = redisTemplate.opsForValue().get(userCacheKey);
		if (ObjUtil.isEmpty(userData)) {
			chain.doFilter(request, response);
			return;
		}
		// Get authorization cookie and validate
		// Cookie tokenFromCookie = WebUtils.getCookie(request, AppConsts.TOKEN_NAME);
		// WebSecurityConfig securityConfig =
		// ContextHelper.getBean(WebSecurityConfig.class);
		// String tokenFromParameter =
		// securityConfig.getUrlTokenAuthentication().isEnabled()
		// ? request.getParameter(AppConsts.TOKEN_NAME)
		// : null;
		// if (tokenFromCookie == null && isBlank(tokenFromParameter)) {
		// chain.doFilter(request, response);
		// return;
		// }

		// // Get jwt token and validate
		// final String token = isNotBlank(tokenFromParameter) ? tokenFromParameter :
		// tokenFromCookie.getValue().trim();
		// if (!jwtTokenUtil.validate(token)) {
		// chain.doFilter(request, response);
		// return;
		// }

		try {
			// Get user identity and set it on the spring security context
			// UserDetails userDetails =
			// userService.loadUserById(jwtTokenUtil.getUser(token).getUserId());

			// UsernamePasswordAuthenticationToken authentication = new
			// UsernamePasswordAuthenticationToken(userDetails,
			// null, ofNullable(userDetails).map(UserDetails::getAuthorities).orElse(new
			// ArrayList<>()));
			// authentication.setDetails(new
			// WebAuthenticationDetailsSource().buildDetails(request));

			// SecurityContextHolder.getContext().setAuthentication(authentication);

			// // Execute login
			// if (tokenFromCookie == null && tokenFromParameter != null) {
			// Cookie cookie = new Cookie(AppConsts.TOKEN_NAME, tokenFromParameter);
			// cookie.setPath("/");
			// cookie.setHttpOnly(true);
			// response.addCookie(cookie);
			// }

			// chain.doFilter(request, response);
			JSONObject userJson = JSONUtil.parseObj(userData);
			String userName = userJson.getStr("username");
			String name = userJson.getStr("name");

			UserInfo userDetails = new UserInfo(userName, sub.toString(), name);
			JSONArray roles = userJson.getJSONArray("roles");
			if (roles != null && roles.size() > 0) {
				Set<String> authorities = new HashSet<>();
				authorities.add("ROLE_admin");
				// roles.forEach(role -> {
				// authorities.add("ROLE_" + role.getCode());
				// Arrays.stream(role.getAuthority().split(",")).forEach(authority -> {
				// authorities.add(authority);
				// });
				// });
				// 设置用户的管理权限
				userDetails.setAuthorities(
						authorities.stream().map(authority -> (GrantedAuthority) () -> authority)
								.collect(Collectors.toSet()));
			}

			UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails,
					null, ofNullable(userDetails).map(UserDetails::getAuthorities).orElse(new ArrayList<>()));
			authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

			SecurityContextHolder.getContext().setAuthentication(authentication);
			chain.doFilter(request, response);

		} catch (AuthenticationException e) {
			// spring security filter 里面的异常，GlobalExceptionHandler 不能捕获
			resolveException.commence(request, response, e);
		}

	}

}
