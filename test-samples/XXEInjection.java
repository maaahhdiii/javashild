package com.example.vulnerable;

import javax.xml.parsers.*;
import org.xml.sax.*;
import org.w3c.dom.*;
import java.io.*;

/**
 * VULNERABLE CODE - XML External Entity (XXE) Injection
 * DO NOT USE IN PRODUCTION!
 */
public class XXEInjection {
    
    // CRITICAL: Vulnerable XML parser
    public Document parseXML(String xmlContent) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new InputSource(new StringReader(xmlContent)));
        // Can include: <!ENTITY xxe SYSTEM "file:///etc/passwd">
    }
    
    // CRITICAL: SAX parser without protection
    public void parseSAX(InputStream xmlStream) throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        SAXParser parser = factory.newSAXParser();
        parser.parse(xmlStream, new DefaultHandler());
        // Vulnerable to XXE attacks
    }
    
    // HIGH: XPath injection
    public void xpathQuery(String userInput) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new File("data.xml"));
        
        javax.xml.xpath.XPathFactory xpathFactory = javax.xml.xpath.XPathFactory.newInstance();
        javax.xml.xpath.XPath xpath = xpathFactory.newXPath();
        String expression = "//user[@name='" + userInput + "']";
        xpath.evaluate(expression, doc);
        // XPath injection vulnerability
    }
    
    // CRITICAL: Unmarshalling without validation
    public Object unmarshalXML(String xml) throws Exception {
        javax.xml.bind.JAXBContext context = javax.xml.bind.JAXBContext.newInstance(Object.class);
        javax.xml.bind.Unmarshaller unmarshaller = context.createUnmarshaller();
        return unmarshaller.unmarshal(new StringReader(xml));
    }
    
    // HIGH: XSLT transformation vulnerability
    public void transformXSLT(String xsltPath, String xmlData) throws Exception {
        javax.xml.transform.TransformerFactory factory = 
            javax.xml.transform.TransformerFactory.newInstance();
        javax.xml.transform.Transformer transformer = 
            factory.newTransformer(new javax.xml.transform.stream.StreamSource(xsltPath));
        // Can execute arbitrary code through XSLT
    }
}
