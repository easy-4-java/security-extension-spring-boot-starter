package org.springframework.security.boot.biz.session;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationListener;
import org.springframework.data.redis.core.BoundHashOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.session.SessionDestroyedEvent;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/** 会话注册表：无参构造用于单节点；传入 RedisTemplate 时在 Redis 中保存会话索引。 */
@Slf4j
public class MySessionRegistryImpl implements SessionRegistry, ApplicationListener<SessionDestroyedEvent> {

    private static final String SESSION_IDS = "sessionIds";
    private static final String PRINCIPALS = "principals";

    private final RedisTemplate<String, Object> redisTemplate;
    private final Map<String, SessionInformation> localSessions = new ConcurrentHashMap<>();
    private final Map<String, Set<String>> localPrincipals = new ConcurrentHashMap<>();

    public MySessionRegistryImpl() {
        this.redisTemplate = null;
    }

    public MySessionRegistryImpl(RedisTemplate<String, Object> redisTemplate) {
        Assert.notNull(redisTemplate, "RedisTemplate must not be null");
        this.redisTemplate = redisTemplate;
    }

    @Override
    public List<Object> getAllPrincipals() {
        Set<Object> result = new HashSet<>();
        for (String key : getPrincipalsKeySet()) {
            Set<String> sessionIds = getPrincipals(key);
            if (Objects.nonNull(sessionIds)) {
                for (String sessionId : sessionIds) {
                    SessionInformation info = getSessionInfo(sessionId);
                    if (Objects.nonNull(info)) {
                        result.add(info.getPrincipal());
                    }
                }
            }
        }
        return new ArrayList<>(result);
    }

    @Override
    public List<SessionInformation> getAllSessions(Object principal, boolean includeExpiredSessions) {
        Assert.notNull(principal, "Principal must not be null");
        Set<String> sessionIds = getPrincipals(principalKey(principal));
        if (Objects.isNull(sessionIds)) {
            return Collections.emptyList();
        }
        List<SessionInformation> result = new ArrayList<>();
        for (String sessionId : sessionIds) {
            SessionInformation info = getSessionInfo(sessionId);
            if (Objects.nonNull(info) && (includeExpiredSessions || !info.isExpired())) {
                result.add(info);
            }
        }
        return result;
    }

    @Override
    public SessionInformation getSessionInformation(String sessionId) {
        Assert.hasText(sessionId, "SessionId required as per interface contract");
        return getSessionInfo(sessionId);
    }

    @Override
    public void onApplicationEvent(SessionDestroyedEvent event) {
        removeSessionInformation(event.getId());
    }

    @Override
    public synchronized void refreshLastRequest(String sessionId) {
        SessionInformation info = getSessionInformation(sessionId);
        if (Objects.nonNull(info)) {
            info.refreshLastRequest();
            addSessionInfo(sessionId, info);
        }
    }

    @Override
    public synchronized void registerNewSession(String sessionId, Object principal) {
        Assert.hasText(sessionId, "SessionId required as per interface contract");
        Assert.notNull(principal, "Principal required as per interface contract");
        removeSessionInformation(sessionId);
        addSessionInfo(sessionId, new SessionInformation(principal, sessionId, new Date()));
        String key = principalKey(principal);
        Set<String> sessionIds = getPrincipals(key);
        Set<String> updated = Objects.isNull(sessionIds) ? new HashSet<>() : new HashSet<>(sessionIds);
        updated.add(sessionId);
        putPrincipals(key, updated);
        log.debug("Registered session {} for principal {}", sessionId, key);
    }

    @Override
    public synchronized void removeSessionInformation(String sessionId) {
        Assert.hasText(sessionId, "SessionId required as per interface contract");
        SessionInformation info = getSessionInfo(sessionId);
        if (Objects.isNull(info)) {
            return;
        }
        removeSessionInfo(sessionId);
        String key = principalKey(info.getPrincipal());
        Set<String> sessionIds = getPrincipals(key);
        if (Objects.nonNull(sessionIds)) {
            Set<String> updated = new HashSet<>(sessionIds);
            updated.remove(sessionId);
            if (updated.isEmpty()) {
                removePrincipal(key);
            } else {
                putPrincipals(key, updated);
            }
        }
    }

    public void addSessionInfo(String sessionId, SessionInformation info) {
        if (Objects.isNull(redisTemplate)) {
            localSessions.put(sessionId, info);
        } else {
            sessions().put(sessionId, info);
        }
    }

    public SessionInformation getSessionInfo(String sessionId) {
        return Objects.isNull(redisTemplate) ? localSessions.get(sessionId) :
                (SessionInformation) sessions().get(sessionId);
    }

    public void removeSessionInfo(String sessionId) {
        if (Objects.isNull(redisTemplate)) {
            localSessions.remove(sessionId);
        } else {
            sessions().delete(sessionId);
        }
    }

    public Set<String> putIfAbsentPrincipals(String key, Set<String> value) {
        if (Objects.isNull(redisTemplate)) {
            return localPrincipals.putIfAbsent(key, new HashSet<>(value));
        }
        Boolean inserted = principals().putIfAbsent(key, new HashSet<>(value));
        return Boolean.TRUE.equals(inserted) ? null : getPrincipals(key);
    }

    public void putPrincipals(String key, Set<String> value) {
        if (Objects.isNull(redisTemplate)) {
            localPrincipals.put(key, new HashSet<>(value));
        } else {
            principals().put(key, new HashSet<>(value));
        }
    }

    @SuppressWarnings("unchecked")
    public Set<String> getPrincipals(String key) {
        return Objects.isNull(redisTemplate) ? localPrincipals.get(key) :
                (Set<String>) principals().get(key);
    }

    public Set<String> getPrincipalsKeySet() {
        if (Objects.isNull(redisTemplate)) {
            return new HashSet<>(localPrincipals.keySet());
        }
        Set<String> keys = principals().keys();
        return Objects.isNull(keys) ? Collections.emptySet() : keys;
    }

    public void removePrincipal(String key) {
        if (Objects.isNull(redisTemplate)) {
            localPrincipals.remove(key);
        } else {
            principals().delete(key);
        }
    }

    private String principalKey(Object principal) {
        return principal instanceof UserDetails user ? user.getUsername() : principal.toString();
    }

    private BoundHashOperations<String, String, Object> sessions() {
        return redisTemplate.boundHashOps(SESSION_IDS);
    }

    private BoundHashOperations<String, String, Object> principals() {
        return redisTemplate.boundHashOps(PRINCIPALS);
    }
}
