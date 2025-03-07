/*
 * Licensed to Elasticsearch B.V. under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch B.V. licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */


package org.logstash;


import org.awaitility.Awaitility;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Test;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;


public class StringInterpolationTest extends RubyTestBase {

    @Test
    public void testCompletelyStaticTemplate() throws IOException {
        Event event = getTestEvent();
        String path = "/full/path/awesome";
        assertEquals(path, StringInterpolation.evaluate(event, path));
    }

    @Test
    public void testOneLevelField() throws IOException {
        Event event = getTestEvent();
        String path = "/full/%{bar}/awesome";
        assertEquals("/full/foo/awesome", StringInterpolation.evaluate(event, path));
    }

    @Test
    public void testMultipleLevelField() throws IOException {
        Event event = getTestEvent();
        String path = "/full/%{bar}/%{awesome}";
        assertEquals("/full/foo/logstash", StringInterpolation.evaluate(event, path));
    }

    @Test
    public void testMissingKey() throws IOException {
        Event event = getTestEvent();
        String path = "/full/%{do-not-exist}";
        assertEquals("/full/%{do-not-exist}", StringInterpolation.evaluate(event, path));
    }

    @Test
    public void testDateFormatter() throws IOException {
        Event event = getTestEvent();
        String path = "/full/%{+YYYY}";
        assertEquals("/full/2015", StringInterpolation.evaluate(event, path));
    }

    @Test
    public void testMixDateAndFields() throws IOException {
        Event event = getTestEvent();
        String path = "/full/%{+YYYY}/weeee/%{bar}";
        assertEquals("/full/2015/weeee/foo", StringInterpolation.evaluate(event, path));
    }

    @Test
    public void testMixDateAndFieldsJavaSyntax() throws IOException {
        Event event = getTestEvent();
        String path = "/full/%{{YYYY-DDD}}/weeee/%{bar}";
        assertEquals("/full/2015-274/weeee/foo", StringInterpolation.evaluate(event, path));
    }

    @Test
    public void testUnclosedTag() throws IOException {
        Event event = getTestEvent();
        String path = "/full/%{+YYY/web";
        assertEquals("/full/%{+YYY/web", StringInterpolation.evaluate(event, path));
    }

    @Test
    public void testStringIsOneDateTag() throws IOException {
        Event event = getTestEvent();
        String path = "%{+YYYY}";
        assertEquals("2015", StringInterpolation.evaluate(event, path));
    }

    @Test
    public void testStringIsJavaDateTag() throws IOException {
        Event event = getTestEvent();
        String path = "%{{YYYY-'W'ww}}";
        assertEquals("2015-W40", StringInterpolation.evaluate(event, path));
    }

    @Test
    public void testFieldRef() throws IOException {
        Event event = getTestEvent();
        String path = "%{[j][k1]}";
        assertEquals("v", StringInterpolation.evaluate(event, path));
    }

    @Test
    public void testEpochSeconds() throws IOException {
        Event event = getTestEvent();
        String path = "%{+%ss}";
        // `+%ss` bypasses the EPOCH syntax and instead matches the JODA syntax.
        // which produces the literal `%` followed by a two-s seconds value `00`
        assertEquals("%00", StringInterpolation.evaluate(event, path));
    }

    @Test
    public void testEpoch() throws IOException {
        Event event = getTestEvent();
        String path = "%{+%s}";
        assertEquals("1443657600", StringInterpolation.evaluate(event, path));
    }

    @Test
    public void testValueIsArray() throws IOException {
        ArrayList<String> l = new ArrayList<>();
        l.add("Hello");
        l.add("world");

        Event event = getTestEvent();
        event.setField("message", l);

        String path = "%{message}";
        assertEquals("Hello,world", StringInterpolation.evaluate(event, path));
    }

    @Test
    public void testValueIsHash() throws IOException {
        Event event = getTestEvent();

        String path = "%{j}";
        assertEquals("{\"k1\":\"v\"}", StringInterpolation.evaluate(event, path));
    }

    @Test
    public void testPatternTimeNowGenerateFreshTimestamp() throws IOException, InterruptedException {
        Event event = getTestEvent();
        Timestamp before = new Timestamp();
        Awaitility.await("Make sure we sleep enough get another current timestamp")
                .atMost(Duration.ofSeconds(1))
                .until(() -> Instant.now().isAfter(before.toInstant()));
        Timestamp result = new Timestamp(StringInterpolation.evaluate(event, "%{{TIME_NOW}}"));
        assertTrue(before.compareTo(result) < 0);
    }

    @Test
    public void testBadPatternTimeNowShouldThrowException() throws IOException {
        Event event = getTestEvent();
        assertThrows(IllegalArgumentException.class, () -> StringInterpolation.evaluate(event, "%{{BAD_TIME_NOW}}"));
    }

    public Event getTestEvent() {
        Map<String, Object> data = new HashMap<>();
        Map<String, String> inner = new HashMap<>();

        inner.put("k1", "v");

        data.put("bar", "foo");
        data.put("awesome", "logstash");
        data.put("j", inner);
        data.put("@timestamp", new DateTime(2015, 10, 1, 0, 0, 0, DateTimeZone.UTC));


        Event event = new Event(data);

        return event;
    }
}
