/*
 * Copyright 2012-2025 CodeLibs Project and the Others.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language
 * governing permissions and limitations under the License.
 */
package org.codelibs.fess.sso.entraid;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Date;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.codelibs.core.lang.StringUtil;
import org.codelibs.fess.entity.FessUser.PermissionState;
import org.codelibs.fess.session.SessionDataSerializer;
import org.codelibs.fess.sso.entraid.EntraIdAuthenticator.StateData;
import org.codelibs.fess.sso.entraid.EntraIdCredential.EntraIdUser;
import org.codelibs.fess.util.ComponentUtil;
import org.codelibs.fess.util.LogUtil;

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.Serializer;
import com.esotericsoftware.kryo.io.Input;
import com.esotericsoftware.kryo.io.Output;
import com.microsoft.aad.msal4j.IAccount;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.microsoft.aad.msal4j.ITenantProfile;

import jakarta.annotation.PostConstruct;

/**
 * Registers the classes this plugin keeps in an HTTP session with the OpenSearch-backed session store
 * of Fess ({@code FESS_SESSION_STORE=opensearch}), so that the nodes behind a load balancer share them.
 * Nothing here is used, and nothing is written anywhere, when the session store is not selected.
 *
 * <p>Two things are shared: the {@link EntraIdUser} inside the user bean of a logged-in session, and the
 * {@code entraidStates} map of the authorization attempts, so that a login begun on one node can end on
 * another. Both have an explicit serializer that names exactly what is written. No token, no client secret
 * and nothing else that grants access to Microsoft Entra ID or Microsoft Graph is among it, because the
 * stored sessions can be read by whoever can read the search engine.</p>
 *
 * <p>What a node that restores an {@link EntraIdUser} does not have is the access token and, more to the
 * point, the refresh token: MSAL4J keeps the latter only in the token cache of the node that handled the
 * login, and no public API of it hands it out. A restored user therefore keeps the memberships resolved at
 * login and cannot call Microsoft Graph. It can still renew its token on the node that holds the cache,
 * because the account it carries is the key of that cache.</p>
 */
public class EntraIdSessionSerializers {

    private static final Logger logger = LogManager.getLogger(EntraIdSessionSerializers.class);

    /** The name of the component of Fess that serializes the attributes of a session for the session store. */
    protected static final String SESSION_DATA_SERIALIZER = "sessionDataSerializer";

    /** The layout of the bytes of a user. A reader of another layout refuses the user instead of misreading it. */
    protected static final int USER_FORMAT = 1;

    /** The layout of the bytes of the state of an authorization attempt. */
    protected static final int STATE_FORMAT = 1;

    /** The longest string, in UTF-8 bytes, that is written or read. */
    protected static final int MAX_STRING_BYTES = 4096;

    /** The most group names, or role names, of one user that are written or read. */
    protected static final int MAX_ENTRIES = 10000;

    /**
     * How far ahead of the clock of this node the start of an authorization attempt may be. A state that
     * started in the future would not expire when it should.
     */
    protected static final long CLOCK_SKEW_TOLERANCE = 60 * 60 * 1000L;

    /**
     * Default constructor.
     */
    public EntraIdSessionSerializers() {
        // nothing to do
    }

    /**
     * Registers the serializers. A registration that is refused does not stop the start of the container: the
     * registrations of the session store may be fixed already, the store may be absent, or the classes may be
     * registered already. Fess then boots and keeps the Entra ID login and its authorization state in the
     * session of the node that handled them, as the SAML and OpenID Connect plugins do. A warning is logged once.
     */
    @PostConstruct
    public void register() {
        try {
            if (!ComponentUtil.hasComponent(SESSION_DATA_SERIALIZER)) {
                throw new IllegalStateException("The component " + SESSION_DATA_SERIALIZER + " is not available.");
            }
            final SessionDataSerializer serializer = ComponentUtil.getComponent(SESSION_DATA_SERIALIZER);
            serializer.register(EntraIdUser.class, new EntraIdUserSerializer());
            serializer.register(StateData.class, new StateDataSerializer());
        } catch (final RuntimeException e) {
            LogUtil.warnOnce(logger, "register", "Entra ID sessions are not shared between nodes by the session store: {}", e.toString());
        }
    }

    // ===================================================================================
    //                                                                              Helper
    //                                                                              ======
    /**
     * Writes a string that may be null, bounded by {@link #MAX_STRING_BYTES}.
     *
     * @param output the output
     * @param value the string
     */
    protected static void writeString(final Output output, final String value) {
        if (value == null) {
            output.writeVarInt(0, true);
            return;
        }
        final byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_STRING_BYTES) {
            throw new IllegalStateException("A string of " + bytes.length + " bytes is too long to be shared.");
        }
        output.writeVarInt(bytes.length + 1, true);
        output.writeBytes(bytes);
    }

    /**
     * Reads a string written by {@link #writeString(Output, String)}. The length is checked against the
     * bound and the bytes left before anything is allocated.
     *
     * @param input the input
     * @param required whether null is refused
     * @return the string, or null
     */
    protected static String readString(final Input input, final boolean required) {
        final int size = input.readVarInt(true);
        if (size == 0) {
            if (required) {
                throw new IllegalStateException("A required string is missing.");
            }
            return null;
        }
        final int length = size - 1;
        if (size < 0 || length > MAX_STRING_BYTES || length > remaining(input)) {
            throw new IllegalStateException("The length of a string is invalid: " + size);
        }
        return new String(input.readBytes(length), StandardCharsets.UTF_8);
    }

    /**
     * Writes a string array that may be null.
     *
     * @param output the output
     * @param values the values, none of which is null
     */
    protected static void writeStrings(final Output output, final String[] values) {
        if (values == null) {
            output.writeVarInt(0, true);
            return;
        }
        if (values.length > MAX_ENTRIES) {
            throw new IllegalStateException(values.length + " names are too many to be shared.");
        }
        output.writeVarInt(values.length + 1, true);
        for (final String value : values) {
            if (value == null) {
                throw new IllegalStateException("A name is null.");
            }
            writeString(output, value);
        }
    }

    /**
     * Reads a string array written by {@link #writeStrings(Output, String[])}. Every element takes a byte
     * at least, so a count above the bytes left cannot be true, and nothing is allocated for it.
     *
     * @param input the input
     * @return the values, or null
     */
    protected static String[] readStrings(final Input input) {
        final int size = input.readVarInt(true);
        if (size == 0) {
            return null;
        }
        final int length = size - 1;
        if (size < 0 || length > MAX_ENTRIES || length > remaining(input)) {
            throw new IllegalStateException("The number of names is invalid: " + size);
        }
        final String[] values = new String[length];
        for (int i = 0; i < length; i++) {
            values[i] = readString(input, true);
        }
        return values;
    }

    private static int remaining(final Input input) {
        return input.limit() - input.position();
    }

    // ===================================================================================
    //                                                                          Serializers
    //                                                                          ===========
    /**
     * Writes the part of an {@link EntraIdUser} that authorization and the continued operation of the
     * session read. Written: the account (user name, home account id and environment, which are the key of
     * the token cache of MSAL4J and no credential), when the access token expires, the object id, the groups
     * and roles that were resolved, whether the resolution has completed, and how it ended. Not written: the
     * access token, the ID token and the refresh token (which the user does not hold), the permissions (they
     * are derived from the rest), the state of a token renewal in progress and the time until which a failed
     * renewal is not retried (they belong to the node).
     *
     * <p>A user whose memberships are still being resolved is not written: it throws, and the session store
     * then keeps the whole user bean on this node and writes it with a later request, when the resolution
     * has landed. Sharing it earlier would let the copy of another node replace the object that the
     * resolution is about to fill in, and the resolution would be lost.</p>
     */
    protected static class EntraIdUserSerializer extends Serializer<EntraIdUser> {

        /**
         * Default constructor.
         */
        protected EntraIdUserSerializer() {
            // nothing to do
        }

        @Override
        public void write(final Kryo kryo, final Output output, final EntraIdUser user) {
            // The state first: the resolution writes the memberships and only then the state.
            final PermissionState state = user.getPermissionState();
            if (state == PermissionState.RESOLVED || state == PermissionState.FAILED) {
                final String[] groups;
                final String[] roles;
                synchronized (user) {
                    groups = user.getGroupNames();
                    roles = user.getRoleNames();
                }
                final IAuthenticationResult result = user.getAuthenticationResult();
                final IAccount account = result.account();
                if (StringUtil.isBlank(account.username())) {
                    throw new IllegalStateException("The Entra ID user has no name.");
                }
                output.writeVarInt(USER_FORMAT, true);
                writeString(output, account.username());
                writeString(output, account.homeAccountId());
                writeString(output, account.environment());
                output.writeLong(result.expiresOnDate().getTime());
                writeString(output, user.getObjectId());
                output.writeByte(state == PermissionState.RESOLVED ? 0 : 1);
                output.writeBoolean(user.isResolutionCompleted());
                writeStrings(output, groups);
                writeStrings(output, roles);
            } else {
                throw new IllegalStateException("The Entra ID memberships of the user are not resolved yet: " + state);
            }
        }

        @Override
        public EntraIdUser read(final Kryo kryo, final Input input, final Class<? extends EntraIdUser> type) {
            if (input.readVarInt(true) != USER_FORMAT) {
                throw new IllegalStateException("The format of the Entra ID user is unknown.");
            }
            final String username = readString(input, true);
            if (StringUtil.isBlank(username)) {
                throw new IllegalStateException("The Entra ID user has no name.");
            }
            final String homeAccountId = readString(input, false);
            final String environment = readString(input, false);
            final long expiresOn = input.readLong();
            if (expiresOn < 0) {
                throw new IllegalStateException("The expiry of the Entra ID user is invalid.");
            }
            final String objectId = readString(input, false);
            // PENDING is never written, and is not read: nothing on this node would resolve it
            final PermissionState state = switch (input.readByte()) {
            case 0 -> PermissionState.RESOLVED;
            case 1 -> PermissionState.FAILED;
            default -> throw new IllegalStateException("The permission state of the Entra ID user is invalid.");
            };
            final boolean resolutionCompleted = input.readBoolean();
            final String[] groups = readStrings(input);
            final String[] roles = readStrings(input);

            final EntraIdUser user = new EntraIdUser(
                    new RestoredAuthenticationResult(new RestoredAccount(username, homeAccountId, environment), new Date(expiresOn)),
                    objectId);
            user.setGroups(groups);
            user.setRoles(roles);
            user.setPermissionState(state);
            if (resolutionCompleted) {
                user.markResolutionCompleted();
            }
            return user;
        }
    }

    /**
     * Writes the state of an authorization attempt: the nonce, and the time the attempt started (which
     * {@code StateData} calls its expiration, and which the time to live is counted from). The key of the
     * map, the {@code state} parameter, is written by the serializer of the map. Both values are in the
     * authorization URL that the browser has seen, so the store holds nothing the user agent did not.
     *
     * <p>The attempt is single-use and time-limited as before: it is removed from the map when the callback
     * consumes it, the removal is part of the session that is written at the end of that request, and a
     * state that is older than the time to live is dropped when the map is next read.</p>
     */
    protected static class StateDataSerializer extends Serializer<StateData> {

        /**
         * Default constructor.
         */
        protected StateDataSerializer() {
            // nothing to do
        }

        @Override
        public void write(final Kryo kryo, final Output output, final StateData stateData) {
            output.writeVarInt(STATE_FORMAT, true);
            writeString(output, stateData.getNonce());
            output.writeLong(stateData.getExpiration());
        }

        @Override
        public StateData read(final Kryo kryo, final Input input, final Class<? extends StateData> type) {
            if (input.readVarInt(true) != STATE_FORMAT) {
                throw new IllegalStateException("The format of the Entra ID state is unknown.");
            }
            final String nonce = readString(input, true);
            if (StringUtil.isEmpty(nonce)) {
                throw new IllegalStateException("The nonce of the Entra ID state is empty.");
            }
            final long startedAt = input.readLong();
            if (startedAt <= 0 || startedAt > System.currentTimeMillis() + CLOCK_SKEW_TOLERANCE) {
                throw new IllegalStateException("The start of the Entra ID state is invalid.");
            }
            return new StateData(nonce, startedAt);
        }
    }

    /**
     * The account of a restored user: the key of the token cache of MSAL4J, and the name.
     */
    protected static class RestoredAccount implements IAccount {

        private static final long serialVersionUID = 1L;

        /** The user name of the account. */
        private final String username;

        /** The home account id, or null. */
        private final String homeAccountId;

        /** The environment, or null. */
        private final String environment;

        /**
         * Creates the account.
         *
         * @param username the user name
         * @param homeAccountId the home account id, or null
         * @param environment the environment, or null
         */
        protected RestoredAccount(final String username, final String homeAccountId, final String environment) {
            this.username = username;
            this.homeAccountId = homeAccountId;
            this.environment = environment;
        }

        @Override
        public String homeAccountId() {
            return homeAccountId;
        }

        @Override
        public String environment() {
            return environment;
        }

        @Override
        public String username() {
            return username;
        }

        @Override
        public Map<String, ITenantProfile> getTenantProfiles() {
            return Collections.emptyMap();
        }
    }

    /**
     * The authentication result of a restored user. It holds no token: only the account and when the access
     * token that the user had expires, which {@link EntraIdUser#refresh()} reads.
     */
    protected static class RestoredAuthenticationResult implements IAuthenticationResult {

        private static final long serialVersionUID = 1L;

        /** The account of the restored user. */
        private final IAccount account;

        /** When the access token that the user had expires, in epoch milliseconds. */
        private final long expiresOn;

        /**
         * Creates the result.
         *
         * @param account the account
         * @param expiresOn when the access token that the user had expires
         */
        protected RestoredAuthenticationResult(final IAccount account, final Date expiresOn) {
            this.account = account;
            this.expiresOn = expiresOn.getTime();
        }

        @Override
        public String accessToken() {
            return null;
        }

        @Override
        public String idToken() {
            return null;
        }

        @Override
        public IAccount account() {
            return account;
        }

        @Override
        public ITenantProfile tenantProfile() {
            return null;
        }

        @Override
        public String environment() {
            return account.environment();
        }

        @Override
        public String scopes() {
            return null;
        }

        @Override
        public Date expiresOnDate() {
            return new Date(expiresOn);
        }
    }
}
