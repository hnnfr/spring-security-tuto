package fr.algofi.hnn.springsecuritytuto.event;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authorization.event.AuthorizationEvent;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class AuthorizationEvents {
    @EventListener
    public void onFailure(AuthorizationEvent event) {
        log.error("Authorization failed for user: {} due to: {}",
                event.getAuthentication().get().getName(), event.getAuthorizationDecision().toString());
    }
}
