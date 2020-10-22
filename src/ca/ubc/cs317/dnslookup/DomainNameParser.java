package ca.ubc.cs317.dnslookup;

import java.util.Arrays;

public class DomainNameParser {
    
    private static int length;
    private static String domainName = "";

    public static void parse(byte[] b, int pos) {
        length = 0;
        domainName = "";
        boolean isCompressed = false;
        int curPos = pos;
        int label = b[curPos++];
        length++;

        while (label != 0) {
            if (label > 0) {
                domainName += new String(Arrays.copyOfRange(b, curPos, curPos + label));
                curPos += label;
                if (!isCompressed) length += label;
                label = b[curPos++];
                if (!isCompressed) length++;
                if (label != 0) domainName += ".";
            } else {
                curPos = ((label & 0x3F) << 8) | (b[curPos] & 0xFF);
                label = b[curPos++];
                if (!isCompressed) length++;
                isCompressed = true;
            }
        }
    }

    public static int getDataLength() {
        return length;
    }

    public static String getDomainName() {
        return domainName;
    }
}
