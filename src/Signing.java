import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;


/**
 * Example to sign an XML and validate it using java internal libraries.
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
public class Signing {

    static Logger logger = java.util.logging.Logger.getLogger("Response");

    public static void main(String[] args) throws Exception {
            logger.info("Creating a XML Signature Factory...");
            // Create a DOM XMLSignatureFactory that will be used to
            // generate the enveloped signature.
            XMLSignatureFactory fac = XMLSignatureFactory.getInstance();
            
            // Create a Reference to the enveloped document (in this case,
            // you are signing the whole document, so a URI of "" signifies
            // that, and also specify the SHA1 digest algorithm and
            // the ENVELOPED Transform.
            logger.info("Creating a reference to the enveloped document...");
            Reference ref = fac.newReference("", fac.newDigestMethod(DigestMethod.SHA256, null),
                    Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)), null, null);

            // Create the SignedInfo.
            logger.info("Creating a Signed Info...");
            SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
                    fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null), Collections.singletonList(ref));

            // Instantiate the document to be signed.
            logger.info("Instantiate the document to be signed... in this case it's purchaseOrder.xml");
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            Document doc = dbf.newDocumentBuilder().parse
                    (new FileInputStream("purchaseOrder.xml"));


            logger.info("Load the keystore stored in this project to get our keys and certificate...");
         // Load the KeyStore and get the signing key and certificate.
         KeyStore ks = KeyStore.getInstance("JKS");
         ks.load(new FileInputStream(".keystore"), "changeit".toCharArray());
         KeyStore.PrivateKeyEntry keyEntry =
             (KeyStore.PrivateKeyEntry) ks.getEntry
                 ("mykey", new KeyStore.PasswordProtection("changeit".toCharArray()));
         X509Certificate cert = (X509Certificate) keyEntry.getCertificate();
         // Create the KeyInfo containing the X509Data.
         KeyInfoFactory kif = fac.getKeyInfoFactory();
         List x509Content = new ArrayList();
         x509Content.add(cert.getSubjectX500Principal().getName());
         x509Content.add(cert);
         X509Data xd = kif.newX509Data(x509Content);
         KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));
            
            // Create a DOMSignContext and specify the RSA PrivateKey and
            // location of the resulting XMLSignature's parent element.
         logger.info("Creating a DomSignContext with our privateKey...");
            DOMSignContext dsc = new DOMSignContext(keyEntry.getPrivateKey(), doc.getDocumentElement());

            // Create the XMLSignature, but don't sign it yet.
            logger.info("Creating the XMLsignature but don't sign it...");
            XMLSignature signature = fac.newXMLSignature(si, ki);

            // Marshal, generate, and sign the enveloped signature.
            logger.info("Marshal, generate and sign the enveloped signature...");
            signature.sign(dsc);

         // Output the resulting document.
         OutputStream os = new FileOutputStream("signedPurchaseOrder.xml");
         TransformerFactory tf = TransformerFactory.newInstance();
         Transformer trans = tf.newTransformer();
         trans.transform(new DOMSource(doc), new StreamResult(os));
         logger.info("Output to signedPurchaseOrder.xml ...");
         // Validate our created signedPurchaseOrder.xml with our provided public key.
         logger.info("Validate our signedPurchaseOrder.xml ...");
         new Validation().validate(cert.getPublicKey(), "signedPurchaseOrder.xml");
            
    }
}
