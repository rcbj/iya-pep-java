// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.local;

import com.iyasec.pep.engine.Designator;
import com.iyasec.pep.engine.Names;
import org.junit.jupiter.api.Test;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LocalTest {
    private static final String PIP_NS = "urn:sts:xacml:pip:1.0";
    private static final String XACML_NS = "urn:oasis:names:tc:xacml:3.0:core:schema:wd-17";

    @Test
    void thePipQueryEscapesAndNamesEachDesignator() throws Exception {
        Designator designator = new Designator(Names.ACCESS_SUBJECT, "dept", Names.STRING, null);
        String query = Local.pipQuery("a<b", true, List.of(designator));
        assertTrue(query.contains("a&lt;b"), query);
        assertTrue(query.contains("subject-kind"), query);
        assertTrue(query.contains("AttributeId=\"dept\""), query);
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.newDocumentBuilder().parse(new ByteArrayInputStream(query.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void aPipAnswerIsReadByDesignatorAndGarbageIsNothing() {
        String text = "<PIPResponse xmlns=\"" + PIP_NS + "\"><Attributes xmlns=\"" + XACML_NS
                + "\" Category=\"" + Names.ACCESS_SUBJECT + "\"><Attribute AttributeId=\"dept\" IncludeInResult=\"false\">"
                + "<AttributeValue DataType=\"" + Names.STRING + "\">eng</AttributeValue>"
                + "<AttributeValue DataType=\"" + Names.STRING + "\">ops</AttributeValue>"
                + "</Attribute></Attributes></PIPResponse>";
        Designator designator = new Designator(Names.ACCESS_SUBJECT, "dept", Names.STRING, null);
        Local.PipAnswers answers = Local.readPipAnswer(text);
        assertEquals(2, answers.resolve(designator).size());
        assertNull(Local.readPipAnswer("<nope").resolve(designator));
    }
}
