import java.io.FileInputStream;
import java.security.PublicKey;
import java.util.logging.Logger;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

/**
 * Class that offers a method to validate a signed xml with a given public key.
 * 
 *   Copyright (C) 2015  Dennis Natanzon
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

public class Validation {
    
    Logger logger = Logger.getLogger("Validation");
    
    public void validate(PublicKey pubKey, String file) throws Exception {
// Validation Signature   
			
        logger.info("Parse the xml...");
			// parseDOMDocument
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            Document doc = dbf.newDocumentBuilder().parse
                    (new FileInputStream(file));

            // Get our Signature Element from the XML.
            boolean valid;
            logger.info("Search for the signature part in the xml...");
            NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
            if (nl.getLength() == 0) {
                logger.warning("Couldn't find signature part... Can't validate file!");
                valid = false;
            } else {

                XMLSignatureFactory fac = XMLSignatureFactory.getInstance();

                // Create a DOMValidateContext and specify a KeySelector
                // and document context.
                DOMValidateContext valContext = new DOMValidateContext(pubKey, nl.item(0));

                // Unmarshal the XMLSignature.
                XMLSignature signatureval = fac.unmarshalXMLSignature(valContext);

                // Validate the XMLSignature.
                valid = signatureval.validate(valContext);
            }
            logger.info("Signature is valid? " + valid);
    }
}
