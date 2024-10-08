// Copyright 2024 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package org.casbin.rolemanager;

import org.casbin.jcasbin.main.Enforcer;
import org.casbin.jcasbin.persist.file_adapter.FileAdapter;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.*;

public class SessionRoleManagerTest {

    private SessionRoleManager rm;

    @Before
    public void setUp() {
        // Initialize the role manager with a hierarchy level (3 here for example)
        rm = new SessionRoleManager(3);
    }

    // Helper functions to simulate time functions from the Go version
    private String getCurrentTime() {
        return String.valueOf(System.currentTimeMillis());
    }

    private String getInOneHour() {
        return String.valueOf(System.currentTimeMillis() + 3600 * 1000);
    }

    private String getOneHourAgo() {
        return String.valueOf(System.currentTimeMillis() - 3600 * 1000);
    }

    private String getAfterOneHour() {
        return String.valueOf(System.currentTimeMillis() + 3600 * 1000 + 1);
    }

    // Test the role inheritance with time-limited sessions
    @Test
    public void testSessionRole() {
        rm.addLink("alpha", "bravo", getCurrentTime(), getInOneHour());
        rm.addLink("alpha", "charlie", getCurrentTime(), getInOneHour());
        rm.addLink("bravo", "delta", getCurrentTime(), getInOneHour());
        rm.addLink("bravo", "echo", getCurrentTime(), getInOneHour());
        rm.addLink("charlie", "echo", getCurrentTime(), getInOneHour());
        rm.addLink("charlie", "foxtrott", getCurrentTime(), getInOneHour());

        assertTrue(rm.hasLink("alpha", "bravo", getCurrentTime()));
        assertTrue(rm.hasLink("alpha", "charlie", getCurrentTime()));
        assertTrue(rm.hasLink("bravo", "delta", getCurrentTime()));
        assertTrue(rm.hasLink("bravo", "echo", getCurrentTime()));
        assertTrue(rm.hasLink("charlie", "echo", getCurrentTime()));
        assertTrue(rm.hasLink("charlie", "foxtrott", getCurrentTime()));

        assertFalse(rm.hasLink("alpha", "bravo", getOneHourAgo()));
        assertFalse(rm.hasLink("alpha", "charlie", getOneHourAgo()));
        assertFalse(rm.hasLink("bravo", "delta", getOneHourAgo()));
        assertFalse(rm.hasLink("bravo", "echo", getOneHourAgo()));
        assertFalse(rm.hasLink("charlie", "echo", getOneHourAgo()));
        assertFalse(rm.hasLink("charlie", "foxtrott", getOneHourAgo()));

        assertFalse(rm.hasLink("alpha", "bravo", getAfterOneHour()));
        assertFalse(rm.hasLink("alpha", "charlie", getAfterOneHour()));
        assertFalse(rm.hasLink("bravo", "delta", getAfterOneHour()));
        assertFalse(rm.hasLink("bravo", "echo", getAfterOneHour()));
        assertFalse(rm.hasLink("charlie", "echo", getAfterOneHour()));
        assertFalse(rm.hasLink("charlie", "foxtrott", getAfterOneHour()));
    }

    // Test the Clear function to ensure all roles are cleared
    @Test
    public void testClear() {
        rm.addLink("alpha", "bravo", getCurrentTime(), getInOneHour());
        rm.addLink("alpha", "charlie", getCurrentTime(), getInOneHour());
        rm.clear();

        assertFalse(rm.hasLink("alpha", "bravo", getCurrentTime()));
        assertFalse(rm.hasLink("alpha", "charlie", getCurrentTime()));
    }

    @Test
    public void testAddLink() {
        rm.addLink("alpha", "bravo", getCurrentTime(), getInOneHour());
        assertTrue(rm.hasLink("alpha", "bravo", getCurrentTime()));
    }

    // Test hasLink functionality for session roles
    @Test
    public void testHasLink() {
        assertFalse(rm.hasLink("alpha", "bravo", getCurrentTime()));
        assertTrue(rm.hasLink("alpha", "alpha", getCurrentTime()));

        rm.addLink("alpha", "bravo", getCurrentTime(), getInOneHour());
        assertTrue(rm.hasLink("alpha", "bravo", getCurrentTime()));
    }

    // Test deleting specific links
    @Test
    public void testDeleteLink() {
        rm.addLink("alpha", "bravo", getOneHourAgo(), getInOneHour());
        rm.deleteLink("alpha", "bravo");

        assertFalse(rm.hasLink("alpha", "bravo", getCurrentTime()));
    }

    // Test hierarchy level limits
    @Test
    public void testHierarchieLevel() {
        rm = new SessionRoleManager(2);
        rm.addLink("alpha", "bravo", getOneHourAgo(), getInOneHour());
        rm.addLink("bravo", "charlie", getOneHourAgo(), getInOneHour());

        assertFalse(rm.hasLink("alpha", "charlie", getCurrentTime()));
        rm = new SessionRoleManager(3);
        rm.clear();
        rm.addLink("alpha", "bravo", getOneHourAgo(), getInOneHour());
        rm.addLink("bravo", "charlie", getOneHourAgo(), getInOneHour());

        assertTrue(rm.hasLink("alpha", "charlie", getCurrentTime()));
    }

    // Test expired session handling
    @Test
    public void testOutdatedSessions() {
        rm.addLink("alpha", "bravo", getOneHourAgo(), getCurrentTime());
        rm.addLink("bravo", "charlie", getOneHourAgo(), getInOneHour());

        assertFalse(rm.hasLink("alpha", "bravo", getInOneHour()));
        assertTrue(rm.hasLink("alpha", "charlie", getOneHourAgo()));
    }

    // Test role inheritance
    @Test
    public void testGetRoles() {
        String oneHourAgo = getOneHourAgo();
        String currentTime = getCurrentTime();
        String inOneHour = getInOneHour();

        rm.addLink("alpha", "bravo", oneHourAgo, inOneHour);
        rm.addLink("alpha", "charlie", oneHourAgo, currentTime);

        assertEquals(Arrays.asList("bravo", "charlie"), rm.getRoles("alpha", oneHourAgo));
        assertEquals(Arrays.asList("bravo"), rm.getRoles("alpha", currentTime + 1));
    }

    // Test user-role mappings
    @Test
    public void testGetUsers() {
        rm.addLink("bravo", "alpha", getOneHourAgo(), getInOneHour());
        rm.addLink("charlie", "alpha", getOneHourAgo(), getInOneHour());
        rm.addLink("delta", "alpha", getOneHourAgo(), getInOneHour());

        assertEquals(Arrays.asList("bravo", "charlie", "delta"), rm.getUsers("alpha", getCurrentTime()));
    }

    // Test the Enforcer with session-based roles and policies
    @Test
    public void testEnforcer() throws Exception {
        // Create a new Enforcer using the model path. The default role manager is used initially.
        Enforcer e = new Enforcer("examples/rbac_model_with_sessions.conf");

        // Manually set an adapter for the policy.
        FileAdapter a = new FileAdapter("examples/rbac_policy_with_sessions.csv");
        e.setAdapter(a);

        // Use our custom role manager.
        SessionRoleManager rm = new SessionRoleManager(10);
        e.setRoleManager(rm);

        // If our role manager relies on Casbin policy (e.g., reading "g" policy rules),
        // we need to set the role manager before loading the policy.
        e.loadPolicy();

        // Current role inheritance tree (Time ranges shown in parentheses):
        //          delta          echo          foxtrott
        //             \            / \           /
        //      (0-20)  \   (5-15) /   \ (10-20) / (10-12)
        //               \        /     \       /
        //                 bravo         charlie
        //                   \             /
        //             (0-10) \           / (5-15)
        //                     \         /
        //                        alpha

        // Test permissions for different time points
        assertTrue(e.enforce("alpha", "data1", "read", "00"));
        assertTrue(e.enforce("alpha", "data1", "read", "05"));
        assertTrue(e.enforce("alpha", "data1", "read", "10"));
        assertFalse(e.enforce("alpha", "data1", "read", "15"));
        assertFalse(e.enforce("alpha", "data1", "read", "20"));

        assertFalse(e.enforce("alpha", "data2", "read", "00"));
        assertTrue(e.enforce("alpha", "data2", "read", "05"));
        assertTrue(e.enforce("alpha", "data2", "read", "10"));
        assertTrue(e.enforce("alpha", "data2", "read", "15"));
        assertFalse(e.enforce("alpha", "data2", "read", "20"));

        assertFalse(e.enforce("alpha", "data3", "read", "00"));
        assertFalse(e.enforce("alpha", "data3", "read", "05"));
        assertTrue(e.enforce("alpha", "data3", "read", "10"));
        assertFalse(e.enforce("alpha", "data3", "read", "15"));
        assertFalse(e.enforce("alpha", "data3", "read", "20"));
    }
}
