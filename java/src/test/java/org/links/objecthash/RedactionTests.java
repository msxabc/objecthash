package org.links.objecthash;

import org.junit.Test;
import java.util.logging.Logger;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;


public class RedactionTests {
    private static final Logger LOG = Logger.getLogger(RedactionTests.class.getName());


    private final static String NOT_REDACTED =
            "{\n" +
                    "\t\"stringData\": {\n" +
                    "\t\t\"_redact_data\": \"abc\",\n" +
                    "\t\t\"hash\": \"2a42a9c91b74c0032f6b8000a2c9c5bcca5bb298f004e8eff533811004dea511\",\n" +
                    "\t\t\"redacted\": false\n" +
                    "\t},\n" +
                    "\t\"intData\": {\n" +
                    "\t\t\"_redact_data\": 1,\n" +
                    "\t\t\"hash\": \"4cd9b7672d7fbee8fb51fb1e049f690342035f543a8efe734b7b5ffb0c154a45\",\n" +
                    "\t\t\"redacted\": false\n" +
                    "\t},\n" +
                    "\t\"doubleData\": {\n" +
                    "\t\t\"_redact_data\": 1.1,\n" +
                    "\t\t\"hash\": \"0b793d743402d091cda6b5153d4b722c30e3e6325fb0e34c5f6926800eafff9a\",\n" +
                    "\t\t\"redacted\": false\n" +
                    "\t},\n" +
                    "\t\"boolData\": {\n" +
                    "\t\t\"_redact_data\": true,\n" +
                    "\t\t\"hash\": \"7dc96f776c8423e57a2785489a3f9c43fb6e756876d6ad9a9cac4aa4e72ec193\",\n" +
                    "\t\t\"redacted\": false\n" +
                    "\t}\n" +
                    "}";

    private final static String REDACTED =
            "{\n" +
                    "\t\"stringData\": {\n" +
                    "\t\t\"_redact_data\": \"deepfake\",\n" +
                    "\t\t\"hash\": \"2a42a9c91b74c0032f6b8000a2c9c5bcca5bb298f004e8eff533811004dea511\",\n" +
                    "\t\t\"redacted\": true\n" +
                    "\t},\n" +
                    "\t\"intData\": {\n" +
                    "\t\t\"_redact_data\": 0,\n" +
                    "\t\t\"hash\": \"4cd9b7672d7fbee8fb51fb1e049f690342035f543a8efe734b7b5ffb0c154a45\",\n" +
                    "\t\t\"redacted\": true\n" +
                    "\t},\n" +
                    "\t\"doubleData\": {\n" +
                    "\t\t\"_redact_data\": 0.00001,\n" +
                    "\t\t\"hash\": \"0b793d743402d091cda6b5153d4b722c30e3e6325fb0e34c5f6926800eafff9a\",\n" +
                    "\t\t\"redacted\": true\n" +
                    "\t},\n" +
                    "\t\"boolData\": {\n" +
                    "\t\t\"_redact_data\": false,\n" +
                    "\t\t\"hash\": \"7dc96f776c8423e57a2785489a3f9c43fb6e756876d6ad9a9cac4aa4e72ec193\",\n" +
                    "\t\t\"redacted\": true\n" +
                    "\t}\n" +
                    "}";

    private final static String PARTIAL_REDACTED =
            "{\n" +
                    "\t\"stringData\": {\n" +
                    "\t\t\"_redact_data\": \"abc\",\n" +
                    "\t\t\"hash\": \"2a42a9c91b74c0032f6b8000a2c9c5bcca5bb298f004e8eff533811004dea511\",\n" +
                    "\t\t\"redacted\": false\n" +
                    "\t},\n" +
                    "\t\"intData\": {\n" +
                    "\t\t\"_redact_data\": -1000,\n" +
                    "\t\t\"hash\": \"4cd9b7672d7fbee8fb51fb1e049f690342035f543a8efe734b7b5ffb0c154a45\",\n" +
                    "\t\t\"redacted\": true\n" +
                    "\t},\n" +
                    "\t\"doubleData\": {\n" +
                    "\t\t\"_redact_data\": 1.1,\n" +
                    "\t\t\"hash\": \"0b793d743402d091cda6b5153d4b722c30e3e6325fb0e34c5f6926800eafff9a\",\n" +
                    "\t\t\"redacted\": false\n" +
                    "\t},\n" +
                    "\t\"boolData\": {\n" +
                    "\t\t\"_redact_data\": false,\n" +
                    "\t\t\"hash\": \"7dc96f776c8423e57a2785489a3f9c43fb6e756876d6ad9a9cac4aa4e72ec193\",\n" +
                    "\t\t\"redacted\": true\n" +
                    "\t}\n" +
                    "}";

    private final static String TAMPERED_ORIGINAL =
            "{\n" +
                    "\t\"stringData\": {\n" +
                    "\t\t\"_redact_data\": \"abcd\",\n" +
                    "\t\t\"hash\": \"2a42a9c91b74c0032f6b8000a2c9c5bcca5bb298f004e8eff533811004dea511\",\n" +
                    "\t\t\"redacted\": false\n" +
                    "\t},\n" +
                    "\t\"intData\": {\n" +
                    "\t\t\"_redact_data\": 11,\n" +
                    "\t\t\"hash\": \"4cd9b7672d7fbee8fb51fb1e049f690342035f543a8efe734b7b5ffb0c154a45\",\n" +
                    "\t\t\"redacted\": false\n" +
                    "\t},\n" +
                    "\t\"doubleData\": {\n" +
                    "\t\t\"_redact_data\": 11.1,\n" +
                    "\t\t\"hash\": \"0b793d743402d091cda6b5153d4b722c30e3e6325fb0e34c5f6926800eafff9a\",\n" +
                    "\t\t\"redacted\": false\n" +
                    "\t},\n" +
                    "\t\"boolData\": {\n" +
                    "\t\t\"_redact_data\": true,\n" +
                    "\t\t\"hash\": \"7dc96f776c8423e57a2785489a3f9c43fb6e756876d6ad9a9cac4aa4e72ec193\",\n" +
                    "\t\t\"redacted\": false\n" +
                    "\t}\n" +
                    "}";

    private final static String TAMPERED_REDACTED =
            "{\n" +
                    "\t\"stringData\": {\n" +
                    "\t\t\"_redact_data\": \"abc\",\n" +
                    "\t\t\"hash\": \"2a42a9c91b74c0032f6b8000a2c9c5bcca5bb298f004e8eff533811004dea511\",\n" +
                    "\t\t\"redacted\": false\n" +
                    "\t},\n" +
                    "\t\"intData\": {\n" +
                    "\t\t\"_redact_data\": -1000,\n" +
                    "\t\t\"hash\": \"2a42a9c91b74c0032f6b8000a2c9c5bcca5bb298f004e8eff533811004dea511\",\n" +
                    "\t\t\"redacted\": true\n" +
                    "\t},\n" +
                    "\t\"doubleData\": {\n" +
                    "\t\t\"_redact_data\": 1.1,\n" +
                    "\t\t\"hash\": \"0b793d743402d091cda6b5153d4b722c30e3e6325fb0e34c5f6926800eafff9a\",\n" +
                    "\t\t\"redacted\": false\n" +
                    "\t},\n" +
                    "\t\"boolData\": {\n" +
                    "\t\t\"_redact_data\": false,\n" +
                    "\t\t\"hash\": \"2a42a9c91b74c0032f6b8000a2c9c5bcca5bb298f004e8eff533811004dea511\",\n" +
                    "\t\t\"redacted\": true\n" +
                    "\t}\n" +
                    "}";

    @Test
    public void JSonRedact() throws Exception {
        String root = new String(ObjectHash.jsonHash(NOT_REDACTED).hash());
        String redactRoot = new String(ObjectHash.jsonHash(REDACTED).hash());
        String partialRoot = new String(ObjectHash.jsonHash(PARTIAL_REDACTED).hash());

        String tamperedOriginal = new String(ObjectHash.jsonHash(TAMPERED_ORIGINAL).hash());
        String tamperedRedacted = new String(ObjectHash.jsonHash(TAMPERED_REDACTED).hash());

        assertEquals(root, redactRoot);
        assertEquals(root, partialRoot);

        assertNotEquals(root, tamperedOriginal);
        assertNotEquals(root, tamperedRedacted);
    }
}
