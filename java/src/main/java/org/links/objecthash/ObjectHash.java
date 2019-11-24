package org.links.objecthash;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.logging.Logger;

import static org.links.objecthash.RedactedData.REDACT_DATA_KEY;

/**
 * TODO(phad): docs.
 */
public class ObjectHash implements Comparable<ObjectHash> {
  private static final int SHA256_BLOCK_SIZE = 32;
  private static final String SHA256 = "SHA-256";
  private static final Logger LOG = Logger.getLogger(ObjectHash.class.getName());

  private byte[] hash;
  private MessageDigest digester;

  private enum JsonType {
    BOOLEAN,
    ARRAY,
    OBJECT,
    INT,
    FLOAT,
    STRING,
    NULL,
    UNKNOWN
  }

  public ObjectHash() throws NoSuchAlgorithmException {
    this.hash = new byte[SHA256_BLOCK_SIZE];
    this.digester = MessageDigest.getInstance(SHA256);
  }

  private void hashAny(Object obj) throws NoSuchAlgorithmException,
                                          JSONException {
    digester.reset();
    JsonType outerType = getType(obj);
    switch (outerType) {
      case ARRAY: {
        hashList((JSONArray) obj);
        break;
      }
      case OBJECT: {
        hashObject((JSONObject) obj);
        break;
      }
      case INT: {
        hashInteger(obj);
        break;
      }
      case STRING: {
        hashString((String) obj);
        break;
      }
      case NULL: {
        hashNull();
        break;
      }
      case BOOLEAN: {
        hashBoolean((Boolean) obj);
        break;
      }
      case FLOAT: {
        hashDouble((Double) obj);
        break;
      }
      default: {
        throw new IllegalArgumentException("Illegal type in JSON: "
                                           + obj.getClass());
      }
    }

  }

  private byte[] hashTaggedBytes(char tag, byte[] bytes)
      throws NoSuchAlgorithmException {
    digester.reset();
    digester.update((byte) tag);
    digester.update(bytes);
    hash = digester.digest();

    return hash;
  }

  public byte[] hashString(String str) throws NoSuchAlgorithmException {
    return hashTaggedBytes('u', str.getBytes());
  }

  public byte[] hashInteger(Object value) throws NoSuchAlgorithmException {
    String str = value.toString();
    return hashTaggedBytes('i', str.getBytes());
  }

  public byte[] hashDouble(Double value) throws NoSuchAlgorithmException {
    String normalized = normalizeFloat(value);
    return hashTaggedBytes('f', normalized.getBytes());
  }

  public byte[] hashNull() throws NoSuchAlgorithmException {
    return hashTaggedBytes('n', "".getBytes());
  }

  public byte[] hashBoolean(boolean bool) throws NoSuchAlgorithmException {
    return hashTaggedBytes('b', (bool ? "1" : "0").getBytes());
  }

  private byte[] hashList(JSONArray list) throws NoSuchAlgorithmException,
                                               JSONException {
    digester.reset();
    digester.update((byte) ('l'));
    for (int n = 0; n < list.length(); ++n) {
      ObjectHash innerObject = new ObjectHash();
      innerObject.hashAny(list.get(n));
      digester.update(innerObject.hash());
    }
    hash = digester.digest();

    return hash;
  }

  private String debugString(Iterable<ByteBuffer> buffers) {
    StringBuilder sb = new StringBuilder();
    for (ByteBuffer buff : buffers) {
      sb.append('\n');
      sb.append(toHex(buff.array()));
    }
    return sb.toString();
  }

  private byte[] hashObject(JSONObject obj) throws NoSuchAlgorithmException,
                                                 JSONException, IllegalArgumentException {
    List<ByteBuffer> buffers = new ArrayList<ByteBuffer>();
    Comparator<ByteBuffer> ordering = new Comparator<ByteBuffer>() {
        @Override
        public int compare(ByteBuffer left, ByteBuffer right) {
          return toHex(left.array()).compareTo(toHex(right.array()));
        }
    };
    Iterator<String> keys = obj.keys();

    char input;
    RedactedData redactedData = RedactedData.isRedactedType(obj);

    if (redactedData != null) {
      ByteBuffer buff = ByteBuffer.allocate(2 * SHA256_BLOCK_SIZE);
      if (!redactedData.isRedacted()) {
        ObjectHash hVal = new ObjectHash();
        hVal.hashAny(obj.get(REDACT_DATA_KEY));
        buff.put(hVal.hash());
      } else {
        try {
          buff.put(hexStringToBytes(redactedData.getHash()));
        } catch (ClassCastException ex) {
          throw new IllegalArgumentException ("hash value for redacted type must be in hexdecimal string format");
        }
      }
      input = redactInputType(obj);
      buffers.add(buff);
    } else {
      while (keys.hasNext()) {
        ByteBuffer buff = ByteBuffer.allocate(2 * SHA256_BLOCK_SIZE);
        String key = keys.next();
        // TODO(phad): would be nice to chain all these calls builder-stylee.
        ObjectHash hKey = new ObjectHash();
        hKey.hashString(key);
        ObjectHash hVal = new ObjectHash();
        hVal.hashAny(obj.get(key));
        buff.put(hKey.hash());
        buff.put(hVal.hash());
        buffers.add(buff);
      }
      input = 'd';
    }
    Collections.sort(buffers, ordering);
    digester.reset();
    digester.update((byte) input);
    for (ByteBuffer buff : buffers) {
      digester.update(buff.array());
    }
    hash = digester.digest();

    return hash;
  }

  private static int parseHex(char digit) {
    assert ((digit >= '0' && digit <= '9') || (digit >= 'a' && digit <= 'f'));
    if (digit >= '0' && digit <= '9') {
      return digit - '0';
    } else {
      return 10 + digit - 'a';
    }
  }

  public static ObjectHash fromHex(String hex) throws NoSuchAlgorithmException {
    ObjectHash h = new ObjectHash();
    hex = hex.toLowerCase();
    if (hex.length() % 2 == 1) {
      hex = '0' + hex;
    }
    // TODO(phad): maybe just use Int.valueOf(s).intValue()
    int pos = SHA256_BLOCK_SIZE;
    for (int idx = hex.length(); idx > 0; idx -= 2) {
      h.hash[--pos] = (byte) (16 * parseHex(hex.charAt(idx - 2))
                              + parseHex(hex.charAt(idx - 1)));
    }
    return h;
  }

  private static JsonType getType(Object jsonObj) {
    if (jsonObj == JSONObject.NULL) {
      return JsonType.NULL;
    } else  if (jsonObj instanceof JSONArray) {
      return JsonType.ARRAY;
    } else if (jsonObj instanceof JSONObject) {
      return JsonType.OBJECT;
    } else if (jsonObj instanceof String) {
      return JsonType.STRING;
    } else if (jsonObj instanceof Integer || jsonObj instanceof Long) {
      return JsonType.INT;
    } else if (jsonObj instanceof Double) {
      return JsonType.FLOAT;
    } else if (jsonObj instanceof Boolean) {
      return JsonType.BOOLEAN;
    } else {
      LOG.warning("jsonObj is_a " + jsonObj.getClass());
      return JsonType.UNKNOWN;
    }
  }

  public static ObjectHash jsonHash(String json)
      throws JSONException, NoSuchAlgorithmException {
    ObjectHash h = new ObjectHash();
    h.hashAny(new JSONTokener(json).nextValue());
    return h;
  }

  @Override
  public String toString() {
    return this.toHex();
  }

  @Override
  public boolean equals(Object other) {
   if (this == other) return true;
   if (other == null) return false;
   if (this.getClass() != other.getClass()) return false;
   return this.toHex().equals(((ObjectHash) other).toHex());
  }

  @Override
  public int compareTo(ObjectHash other) {
    return toHex().compareTo(other.toHex());
  }

  public byte[] hash() {
    return hash;
  }

  private static String byteToHex(byte num) {
    char[] hexDigits = new char[2];
    hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
    hexDigits[1] = Character.forDigit((num & 0xF), 16);
    return new String(hexDigits);
  }

  private static String toHex(byte[] buffer) {
    StringBuffer hexStringBuffer = new StringBuffer();
    for (int i = 0; i < buffer.length; i++) {
      hexStringBuffer.append(byteToHex(buffer[i]));
    }
    return hexStringBuffer.toString();
  }

  public String toHex() {
    return toHex(hash);
  }

  public byte hexToByte(String hexString) {
    int firstDigit = toDigit(hexString.charAt(0));
    int secondDigit = toDigit(hexString.charAt(1));
    return (byte) ((firstDigit << 4) + secondDigit);
  }

  private int toDigit(char hexChar) {
    int digit = Character.digit(hexChar, 16);
    if(digit == -1) {
      throw new IllegalArgumentException(
              "Invalid Hexadecimal Character: "+ hexChar);
    }
    return digit;
  }

  public byte[] hexStringToBytes(String hex) {
    if (hex.length() % 2 == 1) {
      throw new IllegalArgumentException(
              "Invalid hexadecimal String supplied.");
    }

    byte[] bytes = new byte[hex.length() / 2];
    for (int i = 0; i < hex.length(); i += 2) {
      bytes[i / 2] = hexToByte(hex.substring(i, i + 2));
    }
    return bytes;
  }

  static String normalizeFloat(double f) {
    // Early out for zero.
    if (f == 0.0) {
      return "+0:";
    }
    StringBuffer sb = new StringBuffer();
    // Sign
    sb.append(f < 0.0 ? '-' : '+');
    if (f < 0.0) f = -f;
    // Exponent
    int e = 0;
    while (f > 1) {
      f /= 2;
      e += 1;
    }
    while (f < 0.5) {
      f *= 2;
      e -= 1;
    }
    sb.append(e);
    sb.append(':');
    // Mantissa
    if (f > 1 || f <= 0.5) {
      throw new IllegalStateException("wrong range for mantissa");
    }
    while (f != 0) {
      if (f >= 1) {
        sb.append('1');
        f -= 1;
      } else {
        sb.append('0');
      }
      if (f >= 1) {
        throw new IllegalStateException("oops, f is too big");
      }
      if (sb.length() > 1000) {
        throw new IllegalStateException("things have got out of hand");
      }
      f *= 2;
    }
    return sb.toString();
  }

  private static char redactInputType(JSONObject obj) {
    Object data = obj.get(REDACT_DATA_KEY);

    ObjectHash.JsonType outerType = getType(data);
    switch (outerType) {
      case INT: {
        return 'i';
      }
      case STRING: {
        return 'u';
      }
      case BOOLEAN: {
        return 'b';
      }
      case FLOAT: {
        return 'f';
      }
      default: {
        throw new IllegalArgumentException("Illegal type in redacted data: "
                + obj.getClass());
      }
    }
  }
}
