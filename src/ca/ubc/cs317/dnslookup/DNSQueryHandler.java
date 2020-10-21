package ca.ubc.cs317.dnslookup;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;
import java.util.Set;

public class DNSQueryHandler {

    private static final int DEFAULT_DNS_PORT = 53;
    private static DatagramSocket socket;
    private static boolean verboseTracing = false;

    private static final Random random = new Random();

    /**
     * Sets up the socket and set the timeout to 5 seconds
     *
     * @throws SocketException if the socket could not be opened, or if there was an
     *                         error with the underlying protocol
     */
    public static void openSocket() throws SocketException {
        socket = new DatagramSocket();
        socket.setSoTimeout(5000);
    }

    /**
     * Closes the socket
     */
    public static void closeSocket() {
        socket.close();
    }

    /**
     * Set verboseTracing to tracing
     */
    public static void setVerboseTracing(boolean tracing) {
        verboseTracing = tracing;
    }

    /**
     * Builds the query, sends it to the server, and returns the response.
     *
     * @param message Byte array used to store the query to DNS servers.
     * @param server  The IP address of the server to which the query is being sent.
     * @param node    Host and record type to be used for search.
     * @return A DNSServerResponse Object containing the response buffer and the transaction ID.
     * @throws IOException if an IO Exception occurs
     */
    public static DNSServerResponse buildAndSendQuery(byte[] message, InetAddress server,
                                                      DNSNode node) throws IOException {
        int pos = 0;

        int transactionId = random.nextInt() % 0xFFFF;
        message[pos++] = (byte)(transactionId >> 8);
        message[pos++] = (byte)(transactionId);
        message[pos++] = 0;
        message[pos++] = 0;
        message[pos++] = 0;
        message[pos++] = 1; // QDCOUNT
        System.out.println(message);

        for (int i = 0; i < 6; i++) {
            message[pos++] = 0;
        }
        String[] segs = node.getHostName().split("\\.");
        for (int i = 0; i < segs.length; i++) {
            String seg = segs[i];
            message[pos++] = (byte)seg.length();


            byte[] encoded = seg.getBytes();
            for (int j = 0; j < encoded.length; j++) {
                message[pos++] = encoded[j];
            }
        }

        message[pos++] = 0;
        message[pos++] = 0;
        message[pos++] = (byte)node.getType().getCode();
        message[pos++] = 0;
        message[pos++] = 1;
        System.out.println(message);

        byte[] truncatedmessage = new byte[pos];
        System.arraycopy(message,0, truncatedmessage, 0, pos);

        DatagramPacket sendPacket = new DatagramPacket(truncatedmessage, truncatedmessage.length, server, DEFAULT_DNS_PORT);
        try {
            byte[] queryId = Arrays.copyOfRange(sendPacket.getData(),0,2);
            int id = ((queryId[0] << 8) & 0xFFFF) 
            | (queryId[1] & 0xFF);

           
            socket.send(sendPacket);

            byte[] buffer = new byte[1024];
            DatagramPacket res = new DatagramPacket(buffer, buffer.length);
            socket.receive(res);
            return new DNSServerResponse(ByteBuffer.wrap(res.getData()), id);

        }catch(Exception e){
            return null;
        }
    }


    /**
     * Decodes the DNS server response and caches it.
     *
     * @param transactionID  Transaction ID of the current communication with the DNS server
     * @param responseBuffer DNS server's response
     * @param cache          To store the decoded server's response
     * @return A set of resource records corresponding to the name servers of the response.
     */
    public static Set<ResourceRecord> decodeAndCacheResponse(int transactionID, ByteBuffer responseBuffer,
                                                             DNSCache cache) {
        // TODO (PART 1): Implement this
        byte[] b = new byte[1024];
        responseBuffer.get(b, 0, 1024);
        int pos;
        // get transactionID
        int responseID = (0xff & b[0]) << 8 | (0xff & b[1]);
        // (QR) check is response. 1st bit of the third byte
       
        // *(AA) check is authoritative, 2nd bit of the fourth byte
        boolean isAuthoritative = (b[3] & 0x4) != 0;
       
        // (TC) check if truncated, if it is, fail gracefully
        // (RD) looks like that's not needed?
        // (RA) check if server is capable of recursive queries
        // (RCODE) check if 0
        boolean hasError = (0xf & b[3]) != 0;
        if (hasError) return null;
        // if (byteArray[3] != 0) // somehow throw error and exit gracefully

        // *(ANCOUNT)
        int answerCount = (0xff & b[6]) << 8 | (0xff & b[7]);
        // *(NSCOUNT)
        int nameServerCount = (0xff & b[8]) << 8 | (0xff & b[9]);
        // *(ARCOUNT)
        int additionalRecordCount = (0xff & b[10]) << 8 | (0xff & b[11]);

        // go through query portion
        pos = 12;
        int curPos = pos;
        int label = b[curPos];
        String qName = "";
        while(label != 0) {
            if (label > 0) {
                qName += new String(Arrays.copyOfRange(b, ++curPos, curPos + label));
                curPos += label;
                label = b[curPos];
                if (label != 0) qName += ".";
            } else {
                curPos = ((label & 0x3F) << 8) | (b[++curPos] & 0xFF);
                label = b[curPos];
            }
        }
        pos = curPos;
        System.out.println("QNAME " + qName);

        // (QTYPE) pos +1 +2
        // (QCLASS) pos +3 +4
        
        pos += 4;
        pos++;

        // answer section
        System.out.printf("Answers (%d)\n", answerCount);
        for (int i = 0; i < answerCount; i++) {
            String hostName = "";
            curPos = pos;
            int length = 0;
            boolean isCompressed = false;
            label = b[curPos++];
            length++;
            while(label != 0) {
                if (label > 0) {
                    hostName += new String(Arrays.copyOfRange(b, curPos, curPos + label));
                    curPos += label;
                    if (!isCompressed) length += label;
                    label = b[curPos++];
                    if (label != 0) hostName += ".";
                    if (!isCompressed) length++;
                } else {
                    curPos = ((label & 0x3F) << 8) | (b[curPos] & 0xFF);
                    label = b[curPos++];
                    if (!isCompressed) length++;
                    isCompressed = true;
                }
            }
            pos += length;
            
            int typeCode = (0xff & b[pos++]) << 8 | (0xff & b[pos++]);
            RecordType type = RecordType.getByCode(typeCode);
            int nsClass = (0xff & b[pos++]) << 8 | (0xff & b[pos++]);
            int ttl = (0xff & b[pos++] << 24 | 0xff & b[pos++] << 16 | 0xff & b[pos++]) << 8 | (0xff & b[pos++]);
            int dataLength = (0xff & b[pos++]) << 8 | (0xff & b[pos++]);
            byte[] ipBytes = Arrays.copyOfRange(b, pos, pos + dataLength);
            try {

                String ip = InetAddress.getByAddress(ipBytes).getHostAddress();
                ResourceRecord record = new ResourceRecord(hostName, type, ttl, ip);
                cache.addResult(record);
                verbosePrintResourceRecord(record, type.getCode());
            } catch (UnknownHostException E) {
                // weird
            }
            pos = pos + dataLength;
        }

        // NS records
        System.out.printf("Nameservers (%d)\n", nameServerCount);
        for (int i = 0; i < nameServerCount; i++) {
            String hostName = "";
            curPos = pos;
            int length = 0;
            boolean isCompressed = false;
            label = b[curPos++];
            length++;
            while(label != 0) {
                if (label > 0) {
                    hostName += new String(Arrays.copyOfRange(b, curPos, curPos + label));
                    curPos += label;
                    label = b[curPos++];
                    if (label != 0) hostName += ".";
                    if (!isCompressed) length += label + 1;
                } else {
                    curPos = ((label & 0x3F) << 8) | (b[curPos] & 0xFF);
                    label = b[curPos++];
                    if (!isCompressed) length++;
                    isCompressed = true;
                }
            }
            pos += length;

            RecordType type = RecordType.getByCode((0xff & b[pos++]) << 8 | (0xff & b[pos++]));
            int nsClass = (0xff & b[pos++]) << 8 | (0xff & b[pos++]);
            int ttl = (0xff & b[pos++] << 24 | 0xff & b[pos++] << 16 | 0xff & b[pos++]) << 8 | (0xff & b[pos++]);
            int dataLength = (0xff & b[pos++]) << 8 | (0xff & b[pos++]);
            String result = "";
            curPos = pos;
            label = b[curPos];
            while(label != 0) {
                if (label > 0) {
                    result += new String(Arrays.copyOfRange(b, ++curPos, curPos + label));
                    // System.out.println("Result: " + result);
                    curPos += label;
                    label = b[curPos];
                    if (label != 0) result += ".";
                } else {
                    curPos = ((label & 0x3F) << 8) | (b[++curPos] & 0xFF);
                    label = b[curPos];
                }
            }
            pos = pos + dataLength;
            
            ResourceRecord record = new ResourceRecord(hostName, type, ttl, result);
            cache.addResult(record);
            verbosePrintResourceRecord(record, type.getCode());
        }

        // Additional Records
        System.out.printf("Additional Information (%d)\n", additionalRecordCount);
        for (int i = 0; i < additionalRecordCount; i++) {
            String hostName = "";
            curPos = pos;
            int length = 0;
            boolean isCompressed = false;
            label = b[curPos++];
            length++;
            while(label != 0) {
                if (label > 0) {
                    hostName += new String(Arrays.copyOfRange(b, curPos, curPos + label));
                    curPos += label;
                    if (!isCompressed) length += label;
                    label = b[curPos++];
                    if (label != 0) hostName += ".";
                    if (!isCompressed) length++;
                } else {
                    curPos = ((label & 0x3F) << 8) | (b[curPos] & 0xFF);
                    label = b[curPos++];
                    if (!isCompressed) length++;
                    isCompressed = true;
                }
            }
            pos += length;
            
            RecordType type = RecordType.getByCode((0xff & b[pos++]) << 8 | (0xff & b[pos++]));
            int nsClass = (0xff & b[pos++]) << 8 | (0xff & b[pos++]);
            int ttl = (0xff & b[pos++] << 24 | 0xff & b[pos++] << 16 | 0xff & b[pos++]) << 8 | (0xff & b[pos++]);
            int dataLength = (0xff & b[pos++]) << 8 | (0xff & b[pos++]);
            byte[] ipBytes = Arrays.copyOfRange(b, pos, pos + dataLength);
            try {

                String ip = InetAddress.getByAddress(ipBytes).getHostAddress();
                ResourceRecord record = new ResourceRecord(hostName, type, ttl, ip);
                cache.addResult(record);
                verbosePrintResourceRecord(record, type.getCode());
            } catch (UnknownHostException E) {
                // weird
            }
            pos = pos + dataLength;
        }
        return null;
    }

    /**
     * Formats and prints record details (for when trace is on)
     *
     * @param record The record to be printed
     * @param rtype  The type of the record to be printed
     */
    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n",
                    record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }
}

