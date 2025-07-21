package org.sample.enhanced.oidc.ext.auth.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.user.core.service.RealmService;

public final class ServiceInstanceHolder {
    private static final ServiceInstanceHolder instance = new ServiceInstanceHolder();
    private static final Log log = LogFactory.getLog(ServiceInstanceHolder.class);

    private RealmService realmService;

    private ServiceInstanceHolder() {
    }

    public static ServiceInstanceHolder getInstance() {
        return instance;
    }

    public RealmService getRealmService() {
        return realmService;
    }

    public void setRealmService(final RealmService realmService) {
        this.realmService = realmService;
    }
}
