package org.links.objecthash;

import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class RedactedData {

    static final String REDACT_DATA_KEY = "REDACTDATA";
    static final String REDACT_HASH_KEY = "HASHHEX";
    static final String REDACTED_KEY = "REDACTED";

    private String hash;
    private Object redacted_data;
    private boolean redacted;

    private RedactedData(String hash, Object redacted_data, boolean redacted) {
        this.hash = hash;
        this.redacted = redacted;
        this.redacted_data = redacted_data;
    }

    public static RedactedData isRedactedType(JSONObject obj) {
        Map<String, String> keys = new HashMap<>();

        obj.keySet().stream().map(s -> keys.put(s.toUpperCase(), s)).collect(Collectors.toList());

        if  ((keys.size() == 3) &&
                (keys.keySet().contains(REDACT_DATA_KEY)) &&
                (keys.keySet().contains(REDACT_HASH_KEY)) &&
                (keys.keySet().contains(REDACTED_KEY))) {
            return new RedactedData((String) obj.get(keys.get(REDACT_HASH_KEY)),
                    obj.get(keys.get(REDACT_DATA_KEY)),
                    (boolean) obj.get(keys.get(REDACTED_KEY)));
        } else {
            return null;
        }
    }

    public String getHash(){
        return this.hash;
    }

    public Object getRedactedData() {
        return this.redacted_data;
    }

    public boolean isRedacted() {
        return this.redacted;
    }

}
