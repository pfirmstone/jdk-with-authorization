/*
 * Copyright (c) 2016, 2018, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package catalog;

import static jaxp.library.JAXPTestUtilities.clearSystemProperty;
import static jaxp.library.JAXPTestUtilities.getSystemProperty;
import static jaxp.library.JAXPTestUtilities.setSystemProperty;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import javax.xml.stream.XMLResolver;
import javax.xml.stream.XMLStreamException;
import javax.xml.transform.Source;
import javax.xml.transform.TransformerException;
import javax.xml.transform.URIResolver;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.sax.SAXSource;
import javax.xml.transform.stax.StAXSource;
import javax.xml.transform.stream.StreamSource;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.w3c.dom.ls.LSResourceResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

/*
 * @test
 * @bug 8158084 8162438 8162442 8163535 8166220 8344800
 * @library /javax/xml/jaxp/libs /javax/xml/jaxp/unittest
 * @run testng/othervm -DrunSecMngr=true -Djava.security.manager=allow catalog.CatalogSupport3
 * @run testng/othervm catalog.CatalogSupport3
 * @summary extends CatalogSupport tests, verifies that the use of the Catalog may
 * be disabled through the API property.
 */

/**
 * For all of the JAXP processors that support the Catalog, the use of the Catalog
 * is turned on by default. It can then be turned off through the API and the
 * System property.
 *
 * @author huizhe.wang@oracle.com
 */
@Listeners({jaxp.library.FilePolicy.class, jaxp.library.NetAccessPolicy.class})
public class CatalogSupport3 extends CatalogSupportBase {
    static final String TTIMEOUTREAD = "sun.net.client.defaultReadTimeout";
    static final String TIMEOUTCONNECT = "sun.net.client.defaultConnectTimeout";
    static String timeoutRead = getSystemProperty(TTIMEOUTREAD);
    static String timeoutConnect = getSystemProperty(TIMEOUTCONNECT);
    /*
     * Initializing fields
     */
    @BeforeClass
    public void setUpClass() throws Exception {
        setUp();
        timeoutRead = getSystemProperty(TTIMEOUTREAD);
        timeoutConnect = getSystemProperty(TIMEOUTCONNECT);
        setSystemProperty(TTIMEOUTREAD, "1000");
        setSystemProperty(TIMEOUTCONNECT, "1000");
        setSystemProperty(SP_ACCESS_EXTERNAL_DTD, "file");
    }

    @AfterClass
    public void tearDownClass() throws Exception {
        setSystemProperty(TIMEOUTCONNECT, "-1");
        setSystemProperty(TTIMEOUTREAD, "-1");
        clearSystemProperty(SP_ACCESS_EXTERNAL_DTD);
    }

    /*
       Verifies the Catalog support on SAXParser.
    */
    @Test(dataProvider = "data_SAXC", expectedExceptions = SAXParseException.class)
    public void testSAXC(boolean setUseCatalog, boolean useCatalog, String catalog,
            String xml, MyHandler handler, String expected) throws Exception {
        testSAX(setUseCatalog, useCatalog, catalog, xml, handler, expected);
    }

    /*
       Verifies the Catalog support on XMLReader.
    */
    @Test(dataProvider = "data_SAXC", expectedExceptions = SAXParseException.class)
    public void testXMLReaderC(boolean setUseCatalog, boolean useCatalog, String catalog,
            String xml, MyHandler handler, String expected) throws Exception {
        testXMLReader(setUseCatalog, useCatalog, catalog, xml, handler, expected);
    }

    /*
       Verifies the Catalog support on XInclude.
    */
    @Test(dataProvider = "data_XIC", expectedExceptions = SAXParseException.class)
    public void testXIncludeC(boolean setUseCatalog, boolean useCatalog, String catalog,
            String xml, MyHandler handler, String expected) throws Exception {
        testXInclude(setUseCatalog, useCatalog, catalog, xml, handler, expected);
    }

    /*
       Verifies the Catalog support on DOM parser.
    */
    @Test(dataProvider = "data_DOMC", expectedExceptions = SAXParseException.class)
    public void testDOMC(boolean setUseCatalog, boolean useCatalog, String catalog,
            String xml, MyHandler handler, String expected) throws Exception {
        testDOM(setUseCatalog, useCatalog, catalog, xml, handler, expected);
    }

    /*
       Verifies the Catalog support on XMLStreamReader.
    */
    @Test(dataProvider = "data_StAXC", expectedExceptions = XMLStreamException.class)
    public void testStAXC(boolean setUseCatalog, boolean useCatalog, String catalog,
            String xml, XMLResolver resolver, String expected) throws Exception {
        testStAXNegative(setUseCatalog, useCatalog, catalog, xml, resolver, expected);
    }

    /*
       Verifies the Catalog support on resolving DTD, xsd import and include in
    Schema files.
    */
    @Test(dataProvider = "data_SchemaC", expectedExceptions = SAXParseException.class)
    public void testValidationC(boolean setUseCatalog, boolean useCatalog, String catalog,
            String xsd, LSResourceResolver resolver)
            throws Exception {
        testValidation(setUseCatalog, useCatalog, catalog, xsd, resolver) ;
    }

    /*
       @bug 8158084 8162438 these tests also verifies the fix for 8162438
       Verifies the Catalog support on the Schema Validator.
    */
    @Test(dataProvider = "data_ValidatorC", expectedExceptions = {SAXException.class, IOException.class})
    public void testValidatorC(boolean setUseCatalog1, boolean setUseCatalog2, boolean useCatalog,
            Source source, LSResourceResolver resolver1, LSResourceResolver resolver2,
            String catalog1, String catalog2)
            throws Exception {
        testValidator(setUseCatalog1, setUseCatalog2, useCatalog, source,
                resolver1, resolver2, catalog1, catalog2);
    }

    /*
       Verifies the Catalog support on resolving DTD, xsl import and include in
    XSL files.
    */
    @Test(dataProvider = "data_XSLC", expectedExceptions = TransformerException.class)
    public void testXSLImportC(boolean setUseCatalog, boolean useCatalog, String catalog, SAXSource xsl, StreamSource xml,
        URIResolver resolver, String expected) throws Exception {

        testXSLImport(setUseCatalog, useCatalog, catalog, xsl, xml, resolver, expected);
    }

    /*
       @bug 8158084 8162442
       Verifies the Catalog support on resolving DTD, xsl import and include in
    XSL files.
    */
    @Test(dataProvider = "data_XSLC", expectedExceptions = TransformerException.class)
    public void testXSLImportWTemplatesC(boolean setUseCatalog, boolean useCatalog, String catalog,
            SAXSource xsl, StreamSource xml,
        URIResolver resolver, String expected) throws Exception {
        testXSLImportWTemplates(setUseCatalog, useCatalog, catalog, xsl, xml, resolver, expected);
    }

    /*
       DataProvider: for testing the SAX parser
       Data: set use_catalog, use_catalog, catalog file, xml file, handler, expected result string
     */
    @DataProvider(name = "data_SAXC")
    public Object[][] getDataSAXC() {
        return new Object[][]{
            {true, false, xml_catalog, xml_system, new MyHandler(elementInSystem), expectedWCatalog}

        };
    }

    /*
       DataProvider: for testing XInclude
       Data: set use_catalog, use_catalog, catalog file, xml file, handler, expected result string
     */
    @DataProvider(name = "data_XIC")
    public Object[][] getDataXIC() {
        return new Object[][]{
            {true, false, xml_catalog, xml_xInclude, new MyHandler(elementInXISimple), contentInUIutf8Catalog},
        };
    }

    /*
       DataProvider: for testing DOM parser
       Data: set use_catalog, use_catalog, catalog file, xml file, handler, expected result string
     */
    @DataProvider(name = "data_DOMC")
    public Object[][] getDataDOMC() {
        return new Object[][]{
            {true, false, xml_catalog, xml_system, new MyHandler(elementInSystem), expectedWCatalog}
        };
    }

    /*
       DataProvider: for testing the StAX parser
       Data: set use_catalog, use_catalog, catalog file, xml file, handler, expected result string
     */
    @DataProvider(name = "data_StAXC")
    public Object[][] getDataStAX() {
        return new Object[][]{
            {true, false, xml_catalog, xml_system, null, "null"},
        };
    }

    /*
       DataProvider: for testing Schema validation
       Data: set use_catalog, use_catalog, catalog file, xsd file, a LSResourceResolver
     */
    @DataProvider(name = "data_SchemaC")
    public Object[][] getDataSchemaC() {

        return new Object[][]{
            // for resolving DTD in xsd
            {true, false, xml_catalog, xsd_val_test_dtd, null},
            // for resolving xsd import
            {true, false, xml_catalog, xsd_xmlSchema_import, null},
            // for resolving xsd include
            {true, false, xml_catalog, xsd_include_company, null}
        };
    }


    /*
       DataProvider: for testing Schema Validator
       Data: source, resolver1, resolver2, catalog1, a catalog2
     */
    @DataProvider(name = "data_ValidatorC")
    public Object[][] getDataValidator() {
        DOMSource ds = getDOMSource(xml_val_test, xml_val_test_id, false, true, xml_catalog);

        SAXSource ss = new SAXSource(new InputSource(xml_val_test));
        ss.setSystemId(xml_val_test_id);

        StAXSource stax = getStaxSource(xml_val_test, xml_val_test_id, false, true, xml_catalog);
        StAXSource stax1 = getStaxSource(xml_val_test, xml_val_test_id, false, true, xml_catalog);

        StreamSource source = new StreamSource(new File(xml_val_test));

        return new Object[][]{
            // use catalog disabled through factory
            {true, false, false, ds, null, null, xml_catalog, null},
            {true, false, false, ds, null, null, null, xml_catalog},
            {true, false, false, ss, null, null, xml_catalog, null},
            {true, false, false, ss, null, null, null, xml_catalog},
            {true, false, false, stax, null, null, xml_catalog, null},
            {true, false, false, stax1, null, null, null, xml_catalog},
            {true, false, false, source, null, null, xml_catalog, null},
            {true, false, false, source, null, null, null, xml_catalog},
            // use catalog disabled through validatory
            {false, true, false, ds, null, null, xml_catalog, null},
            {false, true, false, ds, null, null, null, xml_catalog},
            {false, true, false, ss, null, null, xml_catalog, null},
            {false, true, false, ss, null, null, null, xml_catalog},
            {false, true, false, stax, null, null, xml_catalog, null},
            {false, true, false, stax1, null, null, null, xml_catalog},
            {false, true, false, source, null, null, xml_catalog, null},
            {false, true, false, source, null, null, null, xml_catalog},
        };
    }

    /*
       DataProvider: for testing XSL import and include
       Data: set use_catalog, use_catalog, catalog file, xsl file, xml file, a URIResolver, expected
     */
    @DataProvider(name = "data_XSLC")
    public Object[][] getDataXSLC() {
        SAXSource xslSourceDTD = new SAXSource(new InputSource(new StringReader(xsl_includeDTD)));
        StreamSource xmlSourceDTD = new StreamSource(new StringReader(xml_xslDTD));

        SAXSource xslDocSource = new SAXSource(new InputSource(new File(xsl_doc).toURI().toASCIIString()));
        StreamSource xmlDocSource = new StreamSource(new File(xml_doc));
        return new Object[][]{
            // for resolving DTD, import and include in xsl
            {true, false, xml_catalog, xslSourceDTD, xmlSourceDTD, null, ""},
            // for resolving reference by the document function
            {true, false, xml_catalog, xslDocSource, xmlDocSource, null, "Resolved by a catalog"},
        };
    }
}
