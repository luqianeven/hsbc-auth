package com.hsbc.security.service;

import com.hsbc.security.util.MessageDict;
import com.hsbc.security.util.StringUtil;
import org.junit.Test;

import static junit.framework.TestCase.assertEquals;

public class StringUtilTest {
    @Test
    public void testIsEmpty() {
        boolean isEmpty = StringUtil.isEmpty("");
        assertEquals(true, isEmpty);
        isEmpty = StringUtil.isEmpty(null);
        assertEquals(true, isEmpty);
    }

    @Test
    public void testIsBlank() {
        boolean isBlank = StringUtil.isBlank("");
        assertEquals(true, isBlank);
        isBlank = StringUtil.isBlank("    ");
        assertEquals(true, isBlank);
        isBlank = StringUtil.isEmpty(null);
        assertEquals(true, isBlank);
    }

    @Test
    public void testHash() {
        String hashStr = StringUtil.hash("test");
        assertEquals("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", hashStr);
    }
}
