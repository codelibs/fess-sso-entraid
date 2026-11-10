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

import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.logging.log4j.LogManager;
import org.codelibs.fess.entity.FessUser.PermissionState;
import org.codelibs.fess.exception.SsoStateException;
import org.codelibs.fess.helper.SystemHelper;
import org.codelibs.fess.mylasta.action.FessUserBean;
import org.codelibs.fess.session.SessionDataSerializer;
import org.codelibs.fess.sso.entraid.EntraIdAuthenticator.StateData;
import org.codelibs.fess.sso.entraid.EntraIdCredential.EntraIdUser;
import org.codelibs.fess.unit.UnitFessTestCase;
import org.codelibs.fess.util.ComponentUtil;
import org.codelibs.fess.util.LogUtil;
import org.junit.jupiter.api.Test;

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.io.Input;
import com.esotericsoftware.kryo.io.Output;
import com.microsoft.aad.msal4j.IAccount;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.microsoft.aad.msal4j.ITenantProfile;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;

import jakarta.servlet.http.HttpSession;

public class EntraIdSessionSerializersTest extends UnitFessTestCase {

    private static final String USER_NAME = "taro@contoso.onmicrosoft.com";

    private static final String HOME_ACCOUNT_ID = "3f7a1c9e-0b52-4d18-9a6c-2e5b8d41f0aa.9d1e2c3b-4a5f-4b6c-8d7e-0f1a2b3c4d5e";

    private static final String ENVIRONMENT = "login.microsoftonline.com";

    private static final String OBJECT_ID = "3f7a1c9e-0b52-4d18-9a6c-2e5b8d41f0aa";

    private static final String ACCESS_TOKEN =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.ACCESS-TOKEN-PAYLOAD-0123456789.ACCESS-TOKEN-SIGNATURE";

    private static final String ID_TOKEN =
            new PlainJWT(new JWTClaimsSet.Builder().claim("oid", OBJECT_ID).claim("nonce", "ID-TOKEN-NONCE-0123456789").build())
                    .serialize();

    private static final String ATTRIBUTE = "userBean";

    /** The time of the system helper, in epoch milliseconds. */
    private final AtomicLong clock = new AtomicLong(System.currentTimeMillis());

    /** How many times a membership resolution was scheduled. */
    private final AtomicInteger scheduled = new AtomicInteger();

    /** Exposes what the tests need to build the bytes of a session by hand. */
    private static class Probe extends SessionDataSerializer {
        long fingerprint() {
            getFormatVersion();
            return fingerprint;
        }

        Kryo kryo() {
            return kryoThreadLocal.get();
        }
    }

    private Probe newSerializer() {
        final Probe probe = new Probe();
        ComponentUtil.register(probe, "sessionDataSerializer");
        new EntraIdSessionSerializers().register();
        return probe;
    }

    private void registerHelpers() {
        ComponentUtil.register(new SystemHelper() {
            @Override
            public long getCurrentTimeAsLong() {
                return clock.get();
            }
        }, "systemHelper");
        ComponentUtil.register(new EntraIdAuthenticator() {
            @Override
            public void scheduleUpdateMemberOf(final EntraIdUser user) {
                scheduled.incrementAndGet();
            }
        }, EntraIdAuthenticator.class.getCanonicalName());
    }

    private static IAuthenticationResult authResult(final Date expiresOn) {
        final IAccount account = new IAccount() {
            private static final long serialVersionUID = 1L;

            @Override
            public String homeAccountId() {
                return HOME_ACCOUNT_ID;
            }

            @Override
            public String environment() {
                return ENVIRONMENT;
            }

            @Override
            public String username() {
                return USER_NAME;
            }

            @Override
            public Map<String, ITenantProfile> getTenantProfiles() {
                return Collections.emptyMap();
            }
        };
        return new IAuthenticationResult() {
            private static final long serialVersionUID = 1L;

            @Override
            public String accessToken() {
                return ACCESS_TOKEN;
            }

            @Override
            public String idToken() {
                return ID_TOKEN;
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
                return ENVIRONMENT;
            }

            @Override
            public String scopes() {
                return "https://graph.microsoft.com/.default";
            }

            @Override
            public Date expiresOnDate() {
                return expiresOn;
            }
        };
    }

    private EntraIdUser newResolvedUser(final PermissionState state) {
        final EntraIdUser user = new EntraIdUser(authResult(new Date(clock.get() + 3_600_000L)));
        user.setGroups(new String[] { "group-a", "group-b" });
        user.setRoles(new String[] { "role-a" });
        user.setPermissionState(state);
        user.markResolutionCompleted();
        return user;
    }

    private static Map<String, Object> attributes(final String name, final Object value) {
        final Map<String, Object> attributes = new LinkedHashMap<>();
        attributes.put(name, value);
        return attributes;
    }

    private static boolean contains(final byte[] bytes, final String text) {
        return indexOf(bytes, text.getBytes(StandardCharsets.UTF_8)) >= 0;
    }

    /**
     * A search that tolerates the string encoding of Kryo, which sets the high bit of the last byte of an
     * ASCII string: the text without its last character is what must not be found.
     */
    private static boolean containsPrefixOf(final byte[] bytes, final String text) {
        return contains(bytes, text.substring(0, text.length() - 1));
    }

    private static int indexOf(final byte[] bytes, final byte[] needle) {
        outer: for (int i = 0; i <= bytes.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (bytes[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    // ===================================================================================
    //                                                                                User
    // ===================================================================================
    @Test
    public void test_user_roundTripKeepsWhatAuthorizationReads() {
        registerHelpers();
        final Probe serializer = newSerializer();
        final EntraIdUser original = newResolvedUser(PermissionState.RESOLVED);

        final byte[] bytes = serializer.toBytes(attributes(ATTRIBUTE, new FessUserBean(original)));
        final Map<String, Object> restoredAttributes = serializer.fromBytes(bytes);

        assertNotNull(restoredAttributes);
        final FessUserBean bean = (FessUserBean) restoredAttributes.get(ATTRIBUTE);
        assertNotNull(bean);
        assertTrue(bean.getFessUser() instanceof EntraIdUser);
        final EntraIdUser restored = (EntraIdUser) bean.getFessUser();
        assertEquals(USER_NAME, restored.getName());
        assertEquals(Arrays.asList("group-a", "group-b"), Arrays.asList(restored.getGroupNames()));
        assertEquals(Arrays.asList("role-a"), Arrays.asList(restored.getRoleNames()));
        assertEquals(PermissionState.RESOLVED, restored.getPermissionState());
        assertTrue(restored.isResolutionCompleted());
        // The permissions are derived, and the object id comes from the stored value as the ID token is not kept.
        ComponentUtil.register(new SystemHelper(), "systemHelper");
        assertEquals(new TreeSet<>(Arrays.asList(original.getPermissions())), new TreeSet<>(Arrays.asList(restored.getPermissions())));
        assertTrue(Arrays.asList(restored.getPermissions()).contains("1" + OBJECT_ID));
        // What the account is for: the key of the token cache of the node that holds the refresh token.
        final IAuthenticationResult result = restored.getAuthenticationResult();
        assertEquals(HOME_ACCOUNT_ID, result.account().homeAccountId());
        assertEquals(ENVIRONMENT, result.account().environment());
        assertEquals(original.getAuthenticationResult().expiresOnDate().getTime(), result.expiresOnDate().getTime());
    }

    @Test
    public void test_user_restoredUserDoesNotStartAResolution() {
        registerHelpers();
        final Probe serializer = newSerializer();
        final EntraIdUser original = newResolvedUser(PermissionState.RESOLVED);
        assertEquals(1, scheduled.get());

        final byte[] bytes = serializer.toBytes(attributes(ATTRIBUTE, new FessUserBean(original)));
        final FessUserBean bean = (FessUserBean) serializer.fromBytes(bytes).get(ATTRIBUTE);

        // The public constructor seeds the defaults and schedules a Graph call that a user without a token cannot make.
        assertEquals(1, scheduled.get());
        assertNotNull(bean);
    }

    @Test
    public void test_user_failedStaysFailedAndIsNeverPromoted() {
        registerHelpers();
        final Probe serializer = newSerializer();
        final EntraIdUser original = newResolvedUser(PermissionState.FAILED);

        final byte[] bytes = serializer.toBytes(attributes(ATTRIBUTE, new FessUserBean(original)));
        final EntraIdUser restored = (EntraIdUser) ((FessUserBean) serializer.fromBytes(bytes).get(ATTRIBUTE)).getFessUser();

        assertEquals(PermissionState.FAILED, restored.getPermissionState());
    }

    @Test
    public void test_user_pendingUserIsNotSharedAndStaysOnTheNode() {
        registerHelpers();
        final Probe serializer = newSerializer();
        final EntraIdUser pending = new EntraIdUser(authResult(new Date(clock.get() + 3_600_000L)));
        assertEquals(PermissionState.PENDING, pending.getPermissionState());

        final Set<String> skipped = new TreeSet<>();
        final byte[] bytes = serializer.toBytes(attributes(ATTRIBUTE, new FessUserBean(pending)), skipped);

        // Reported as skipped, so the session store neither removes it from this node nor lets another node replace it.
        assertEquals(Set.of(ATTRIBUTE), skipped);
        assertFalse(serializer.fromBytes(bytes).containsKey(ATTRIBUTE));
    }

    @Test
    public void test_user_isSharedOnceTheResolutionHasLanded() {
        registerHelpers();
        final Probe serializer = newSerializer();
        final EntraIdUser user = new EntraIdUser(authResult(new Date(clock.get() + 3_600_000L)));
        final Set<String> skipped = new TreeSet<>();
        serializer.toBytes(attributes(ATTRIBUTE, new FessUserBean(user)), skipped);
        assertEquals(Set.of(ATTRIBUTE), skipped);

        // what updateMemberOf does, in its order
        user.setGroups(new String[] { "resolved-group" });
        user.setRoles(new String[0]);
        user.resetPermissions();
        user.setPermissionState(PermissionState.RESOLVED);
        user.markResolutionCompleted();

        skipped.clear();
        final byte[] bytes = serializer.toBytes(attributes(ATTRIBUTE, new FessUserBean(user)), skipped);
        assertTrue(skipped.isEmpty());
        final EntraIdUser restored = (EntraIdUser) ((FessUserBean) serializer.fromBytes(bytes).get(ATTRIBUTE)).getFessUser();
        assertEquals(Arrays.asList("resolved-group"), Arrays.asList(restored.getGroupNames()));
    }

    @Test
    public void test_user_noSecretIsInTheBytes() {
        registerHelpers();
        final Probe serializer = newSerializer();
        final EntraIdUser original = newResolvedUser(PermissionState.RESOLVED);
        // the permissions are computed and cached on the user, as they are after a request
        ComponentUtil.register(new SystemHelper(), "systemHelper");
        original.getPermissions();

        final byte[] bytes = serializer.toBytes(attributes(ATTRIBUTE, new FessUserBean(original)));

        // the positive controls: the search finds what is stored
        assertTrue(contains(bytes, USER_NAME));
        assertTrue(contains(bytes, HOME_ACCOUNT_ID));
        assertTrue(contains(bytes, OBJECT_ID));
        assertTrue(contains(bytes, "group-a"));
        // the secrets, whole and without the last character
        for (final String secret : new String[] { ACCESS_TOKEN, ID_TOKEN, "ACCESS-TOKEN-PAYLOAD", "ACCESS-TOKEN-SIGNATURE",
                "ID-TOKEN-NONCE-0123456789" }) {
            assertFalse(secret, containsPrefixOf(bytes, secret));
        }
        // the header and the claims of the ID token, which are readable once decoded
        assertFalse(contains(bytes, ID_TOKEN.substring(0, 20)));
    }

    @Test
    public void test_user_tooManyGroupsAreNotSharedInsteadOfTruncated() {
        registerHelpers();
        final Probe serializer = newSerializer();
        final EntraIdUser user = newResolvedUser(PermissionState.RESOLVED);
        final String[] groups = new String[EntraIdSessionSerializers.MAX_ENTRIES + 1];
        Arrays.fill(groups, "g");
        user.setGroups(groups);

        final Set<String> skipped = new TreeSet<>();
        final byte[] bytes = serializer.toBytes(attributes(ATTRIBUTE, new FessUserBean(user)), skipped);

        assertEquals(Set.of(ATTRIBUTE), skipped);
        assertFalse(serializer.fromBytes(bytes).containsKey(ATTRIBUTE));
    }

    @Test
    public void test_user_restoredUserWithExpiredTokenCannotRenewWithoutTheCacheAndKeepsItsMemberships() {
        registerHelpers();
        final Probe serializer = newSerializer();
        final EntraIdUser original = new EntraIdUser(authResult(new Date(clock.get() - 1000L)));
        original.setGroups(new String[] { "group-a" });
        original.setRoles(new String[0]);
        original.setPermissionState(PermissionState.RESOLVED);
        original.markResolutionCompleted();
        final EntraIdUser restored =
                (EntraIdUser) ((FessUserBean) serializer.fromBytes(serializer.toBytes(attributes(ATTRIBUTE, new FessUserBean(original))))
                        .get(ATTRIBUTE)).getFessUser();

        // no token cache entry on this node: the silent acquisition fails, which is not an exception for the caller
        assertFalse(restored.refresh());
        assertEquals(Arrays.asList("group-a"), Arrays.asList(restored.getGroupNames()));
        assertEquals(PermissionState.RESOLVED, restored.getPermissionState());
    }

    // ===================================================================================
    //                                                                           Hardening
    // ===================================================================================
    private Output validUserOutput() {
        final Output output = new Output(256, -1);
        output.writeVarInt(EntraIdSessionSerializers.USER_FORMAT, true);
        EntraIdSessionSerializers.writeString(output, USER_NAME);
        EntraIdSessionSerializers.writeString(output, HOME_ACCOUNT_ID);
        EntraIdSessionSerializers.writeString(output, ENVIRONMENT);
        output.writeLong(clock.get());
        EntraIdSessionSerializers.writeString(output, OBJECT_ID);
        output.writeByte(0);
        output.writeBoolean(true);
        EntraIdSessionSerializers.writeStrings(output, new String[] { "g" });
        EntraIdSessionSerializers.writeStrings(output, new String[] { "r" });
        return output;
    }

    private EntraIdUser readUser(final byte[] bytes) {
        return new EntraIdSessionSerializers.EntraIdUserSerializer().read(new Kryo(), new Input(bytes), EntraIdUser.class);
    }

    @Test
    public void test_user_handWrittenValidBytesAreRead() {
        registerHelpers();
        assertEquals(USER_NAME, readUser(validUserOutput().toBytes()).getName());
    }

    @Test
    public void test_user_everyTruncationIsRefused() {
        registerHelpers();
        final byte[] bytes = validUserOutput().toBytes();
        for (int length = 0; length < bytes.length; length++) {
            final byte[] truncated = Arrays.copyOf(bytes, length);
            try {
                readUser(truncated);
                fail("read " + length + " of " + bytes.length + " bytes");
            } catch (final RuntimeException expected) {
                // refused: a Kryo exception or an IllegalStateException
            }
        }
    }

    @Test
    public void test_user_oversizedLengthsAreRefusedBeforeAnythingIsAllocated() {
        registerHelpers();
        // a count of groups that the bytes cannot hold, in the shapes an attacker or a corrupt page would take
        for (final int count : new int[] { Integer.MAX_VALUE, 1 << 30, EntraIdSessionSerializers.MAX_ENTRIES + 2, 100 }) {
            final Output output = new Output(64, -1);
            output.writeVarInt(EntraIdSessionSerializers.USER_FORMAT, true);
            EntraIdSessionSerializers.writeString(output, USER_NAME);
            output.writeVarInt(0, true);
            output.writeVarInt(0, true);
            output.writeLong(clock.get());
            output.writeVarInt(0, true);
            output.writeByte(0);
            output.writeBoolean(true);
            output.writeVarInt(count, true);
            try {
                readUser(output.toBytes());
                fail("count " + count);
            } catch (final IllegalStateException expected) {
                assertTrue(expected.getMessage(), expected.getMessage().contains("invalid"));
            }
        }
        // a string longer than the bytes left, and longer than the bound
        for (final int length : new int[] { Integer.MAX_VALUE, 1 << 30, EntraIdSessionSerializers.MAX_STRING_BYTES + 2, 100 }) {
            final Output output = new Output(64, -1);
            output.writeVarInt(EntraIdSessionSerializers.USER_FORMAT, true);
            output.writeVarInt(length, true);
            output.writeBytes("short".getBytes(StandardCharsets.UTF_8));
            try {
                readUser(output.toBytes());
                fail("length " + length);
            } catch (final IllegalStateException expected) {
                assertTrue(expected.getMessage(), expected.getMessage().contains("invalid"));
            }
        }
    }

    @Test
    public void test_user_invalidFieldsAreRefused() {
        registerHelpers();
        // an unknown layout, a state that is not shareable, an empty name and a negative expiry
        final byte[] valid = validUserOutput().toBytes();

        final byte[] otherFormat = valid.clone();
        otherFormat[0] = 2;
        assertRefused(otherFormat);

        final Output pending = new Output(256, -1);
        pending.writeVarInt(EntraIdSessionSerializers.USER_FORMAT, true);
        EntraIdSessionSerializers.writeString(pending, USER_NAME);
        pending.writeVarInt(0, true);
        pending.writeVarInt(0, true);
        pending.writeLong(clock.get());
        pending.writeVarInt(0, true);
        pending.writeByte(2); // not a value of this format: PENDING is never written
        pending.writeBoolean(false);
        pending.writeVarInt(0, true);
        pending.writeVarInt(0, true);
        assertRefused(pending.toBytes());

        final Output noName = new Output(256, -1);
        noName.writeVarInt(EntraIdSessionSerializers.USER_FORMAT, true);
        EntraIdSessionSerializers.writeString(noName, "");
        assertRefused(noName.toBytes());

        final Output negativeExpiry = new Output(256, -1);
        negativeExpiry.writeVarInt(EntraIdSessionSerializers.USER_FORMAT, true);
        EntraIdSessionSerializers.writeString(negativeExpiry, USER_NAME);
        negativeExpiry.writeVarInt(0, true);
        negativeExpiry.writeVarInt(0, true);
        negativeExpiry.writeLong(-1L);
        assertRefused(negativeExpiry.toBytes());
    }

    private void assertRefused(final byte[] bytes) {
        try {
            readUser(bytes);
            fail("read");
        } catch (final IllegalStateException expected) {
            // refused
        }
    }

    @Test
    public void test_session_truncatedAndGarbageBytesNeverThrowAndNeverYieldAUser() {
        registerHelpers();
        final Probe serializer = newSerializer();
        final Map<String, Object> attributes = new LinkedHashMap<>();
        attributes.put(ATTRIBUTE, new FessUserBean(newResolvedUser(PermissionState.RESOLVED)));
        attributes.put(EntraIdAuthenticator.STATES, new ConcurrentHashMap<>(Map.of("state", new StateData("nonce", clock.get()))));
        final byte[] bytes = serializer.toBytes(attributes);
        assertEquals(2, serializer.fromBytes(bytes).size());

        for (int length = 0; length < bytes.length; length++) {
            final Map<String, Object> read = serializer.fromBytes(Arrays.copyOf(bytes, length));
            if (read != null) {
                // an entry is dropped whole, never half read
                assertTrue(read.size() < 2);
            }
        }
        final Random random = new Random(42L);
        for (int i = 0; i < 2000; i++) {
            final byte[] garbage = new byte[random.nextInt(200)];
            random.nextBytes(garbage);
            serializer.fromBytes(garbage);
            // garbage behind a valid header, to reach the entries
            final byte[] flipped = bytes.clone();
            flipped[random.nextInt(flipped.length)] ^= (byte) (1 + random.nextInt(255));
            serializer.fromBytes(flipped);
        }
    }

    @Test
    public void test_session_unregisteredClassIdIsDroppedAndTheOthersAreKept() {
        registerHelpers();
        final Probe serializer = newSerializer();
        final byte[] valid = serializer.toBytes(
                attributes(EntraIdAuthenticator.STATES, new ConcurrentHashMap<>(Map.of("state", new StateData("nonce", clock.get())))));
        // a session with the valid entry and one whose value starts with a class id that nothing has
        final Output output = new Output(256, -1);
        output.writeVarInt(1, true);
        output.writeLong(serializer.fingerprint());
        output.writeVarInt(2, true);
        output.writeString("evil");
        final byte[] unknown = { 0x7e, 0x01, 0x02, 0x03 };
        output.writeVarInt(unknown.length, true);
        output.writeBytes(unknown);
        output.writeString(EntraIdAuthenticator.STATES);
        // the value bytes of the valid entry are the tail of its session bytes: reuse them by writing the map again
        final Output scratch = new Output(256, -1);
        serializer.kryo().writeClassAndObject(scratch, new ConcurrentHashMap<>(Map.of("state", new StateData("nonce", clock.get()))));
        output.writeVarInt(scratch.toBytes().length, true);
        output.writeBytes(scratch.toBytes());

        final Map<String, Object> read = serializer.fromBytes(output.toBytes());

        assertNotNull(read);
        assertFalse(read.containsKey("evil"));
        assertTrue(read.get(EntraIdAuthenticator.STATES) instanceof ConcurrentHashMap);
        assertNotNull(valid);
    }

    @Test
    public void test_session_aNodeWithoutThePluginReadsNothingOfASessionWrittenWithIt() {
        registerHelpers();
        final Probe withPlugin = newSerializer();
        final byte[] bytes = withPlugin.toBytes(attributes(ATTRIBUTE, new FessUserBean(newResolvedUser(PermissionState.RESOLVED))));

        // the fingerprint of the registered classes differs, so the whole session is treated as absent
        assertNull(new Probe().fromBytes(bytes));
    }

    // ===================================================================================
    //                                                                               State
    // ===================================================================================
    @Test
    public void test_state_roundTripKeepsTheNonceTheStartAndTheMapType() {
        registerHelpers();
        final Probe serializer = newSerializer();
        final long started = clock.get() - 5000L;
        final Map<String, StateData> states = new ConcurrentHashMap<>();
        states.put("state-1", new StateData("nonce-1", started));
        states.put("state-2", new StateData("nonce-2", started + 1));

        final byte[] bytes = serializer.toBytes(attributes(EntraIdAuthenticator.STATES, states));
        final Object read = serializer.fromBytes(bytes).get(EntraIdAuthenticator.STATES);

        // getStateMap accepts a ConcurrentHashMap only and would replace anything else
        assertTrue(read instanceof ConcurrentHashMap);
        @SuppressWarnings("unchecked")
        final Map<String, StateData> restored = (Map<String, StateData>) read;
        assertEquals(2, restored.size());
        assertEquals("nonce-1", restored.get("state-1").getNonce());
        assertEquals(started, restored.get("state-1").getExpiration());
        assertEquals(started + 1, restored.get("state-2").getExpiration());
    }

    @Test
    public void test_state_invalidValuesAreRefused() {
        registerHelpers();
        final EntraIdSessionSerializers.StateDataSerializer serializer = new EntraIdSessionSerializers.StateDataSerializer();
        final long[] starts = { 0L, -5L, System.currentTimeMillis() + 2 * EntraIdSessionSerializers.CLOCK_SKEW_TOLERANCE };
        for (final long start : starts) {
            final Output output = new Output(64, -1);
            output.writeVarInt(EntraIdSessionSerializers.STATE_FORMAT, true);
            EntraIdSessionSerializers.writeString(output, "nonce");
            output.writeLong(start);
            try {
                serializer.read(new Kryo(), new Input(output.toBytes()), StateData.class);
                fail("start " + start);
            } catch (final IllegalStateException expected) {
                // refused
            }
        }
        for (final String nonce : new String[] { null, "" }) {
            final Output output = new Output(64, -1);
            output.writeVarInt(EntraIdSessionSerializers.STATE_FORMAT, true);
            EntraIdSessionSerializers.writeString(output, nonce);
            output.writeLong(System.currentTimeMillis());
            try {
                serializer.read(new Kryo(), new Input(output.toBytes()), StateData.class);
                fail("nonce " + nonce);
            } catch (final IllegalStateException expected) {
                // refused
            }
        }
    }

    /** A node's session: the attributes of the servlet session, as a stub, because every node has its own object. */
    private static HttpSession newSession(final Map<String, Object> attributes) {
        return (HttpSession) Proxy.newProxyInstance(HttpSession.class.getClassLoader(), new Class<?>[] { HttpSession.class },
                (proxy, method, args) -> switch (method.getName()) {
                case "getAttribute" -> attributes.get(args[0]);
                case "setAttribute" -> attributes.put((String) args[0], args[1]);
                case "removeAttribute" -> attributes.remove(args[0]);
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == args[0];
                default -> throw new UnsupportedOperationException(method.getName());
                });
    }

    private static HttpSession sessionOf(final Probe serializer, final byte[] bytes) {
        final Map<String, Object> read = serializer.fromBytes(bytes);
        return newSession(read != null ? read : new HashMap<>());
    }

    @Test
    public void test_state_aLoginStartedOnOneNodeEndsOnAnotherAndCannotBeReplayedAfterwards() {
        registerHelpers();
        final Probe serializer = newSerializer();
        final EntraIdAuthenticator authenticator = new EntraIdAuthenticator();

        // node A starts the login and writes the session at the end of the request
        final Map<String, Object> attributesOfA = new HashMap<>();
        final HttpSession nodeA = newSession(attributesOfA);
        authenticator.storeStateInSession(nodeA, "state-1", "nonce-1");
        final byte[] written = serializer.toBytes(attributesOfA);

        // node B receives the callback and consumes the state
        final Map<String, Object> attributesOfB = serializer.fromBytes(written);
        final HttpSession nodeB = newSession(attributesOfB);
        clock.addAndGet(5000L);
        final StateData consumed = authenticator.validateState(nodeB, "state-1");
        assertEquals("nonce-1", consumed.getNonce());
        // the removal is an in-place change of the map: the session writes it because it serializes every attribute again
        final byte[] afterConsumption = serializer.toBytes(attributesOfB);

        // a replay that reaches any node after that write is refused
        try {
            authenticator.validateState(sessionOf(serializer, afterConsumption), "state-1");
            fail("replayed");
        } catch (final SsoStateException expected) {
            // single-use
        }
        // and a node that has not read that write yet can still consume it, which is the race that the one-time
        // authorization code at Microsoft closes: the second redemption of the same code fails there
        assertEquals("nonce-1", authenticator.validateState(sessionOf(serializer, written), "state-1").getNonce());
    }

    @Test
    public void test_state_expiresOnTheNodeThatReadsItAfterTheTimeToLive() {
        registerHelpers();
        final Probe serializer = newSerializer();
        final EntraIdAuthenticator authenticator = new EntraIdAuthenticator();
        final Map<String, Object> attributes = new HashMap<>();
        authenticator.storeStateInSession(newSession(attributes), "state-1", "nonce-1");
        final byte[] written = serializer.toBytes(attributes);

        // the default time to live is 3600 seconds, counted from the start written with the state
        clock.addAndGet(3599L * 1000L);
        assertEquals("nonce-1", authenticator.validateState(sessionOf(serializer, written), "state-1").getNonce());
        clock.addAndGet(2L * 1000L);
        try {
            authenticator.validateState(sessionOf(serializer, written), "state-1");
            fail("expired");
        } catch (final SsoStateException expected) {
            // time-limited
        }
    }

    // ===================================================================================
    //                                                                        Registration
    // ===================================================================================
    @Test
    public void test_register_addsBothClassesToTheFormatOfTheSessionStore() {
        final String before = new Probe().getFormatVersion();
        final Probe serializer = newSerializer();
        assertFalse(before.equals(serializer.getFormatVersion()));

        // a second registration is refused by the store, but that must not stop the start of Fess
        LogUtil.resetWarnOnce();
        new EntraIdSessionSerializers().register();
        assertWarned();
    }

    @Test
    public void test_register_afterTheStoreIsLockedDoesNotThrowAndWarnsOnce() {
        LogUtil.resetWarnOnce();
        final Probe probe = new Probe();
        probe.getFormatVersion(); // fixes the registrations
        ComponentUtil.register(probe, "sessionDataSerializer");
        new EntraIdSessionSerializers().register();
        assertWarned();
    }

    @Test
    public void test_register_withoutTheSerializerComponentDoesNotThrowAndWarnsOnce() throws Exception {
        LogUtil.resetWarnOnce();
        final Field field = ComponentUtil.class.getDeclaredField("componentMap");
        field.setAccessible(true);
        @SuppressWarnings("unchecked")
        final Map<String, Object> componentMap = (Map<String, Object>) field.get(null);
        componentMap.remove("sessionDataSerializer");
        assertFalse(ComponentUtil.hasComponent("sessionDataSerializer"));
        new EntraIdSessionSerializers().register();
        assertWarned();
    }

    /** The warning was logged already by the registration, so asking to log it again is refused. */
    private void assertWarned() {
        assertFalse(LogUtil.warnOnce(LogManager.getLogger(EntraIdSessionSerializers.class), "register", "again"));
    }
}
