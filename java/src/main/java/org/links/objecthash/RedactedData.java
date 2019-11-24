package org.links.objecthash;

import org.json.JSONObject;

public class RedactedData {

    static final String REDACT_DATA_KEY = "_redact_data";
    static final String REDACT_HASH_KEY = "hash";
    static final String REDACTED_KEY = "redacted";

    private String hash;
    private Object redacted_data;
    private boolean redacted;

    private RedactedData(String hash, Object redacted_data, boolean redacted) {
        this.hash = hash;
        this.redacted = redacted;
        this.redacted_data = redacted_data;
    }

    public static RedactedData isRedactedType(JSONObject obj) {
        if  ((obj.keySet().size() == 3) &&
                (obj.keySet().contains(REDACT_DATA_KEY)) &&
                (obj.keySet().contains(REDACT_HASH_KEY)) &&
                (obj.keySet().contains(REDACTED_KEY))) {
            return new RedactedData((String) obj.get(REDACT_HASH_KEY), obj.get(REDACT_DATA_KEY), (boolean) obj.get(REDACTED_KEY));
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
