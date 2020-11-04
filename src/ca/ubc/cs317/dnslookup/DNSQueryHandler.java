package ca.ubc.cs317.dnslookup;

import java.io.IOException;
import java.net.*;
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

        byte[] truncatedmessage = new byte[pos];
        System.arraycopy(message,0, truncatedmessage, 0, pos);

        DatagramPacket sendPacket = new DatagramPacket(truncatedmessage, truncatedmessage.length, server, DEFAULT_DNS_PORT);
        try {
            byte[] queryId = Arrays.copyOfRange(sendPacket.getData(),0,2);
            int id = ((queryId[0] << 8) & 0xFFFF) 
            | (queryId[1] & 0xFF);
            
            if (verboseTracing) {
                System.out.printf("\n\nQuery ID %9d %4s %2s --> %s\n", id, node.getHostName(), node.getType(), server.getHostAddress());
            }
           
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
        // (PART 1)
        byte[] b = new byte[responseBuffer.remaining()];
        responseBuffer.get(b, 0, responseBuffer.remaining());
        int pos;
        // get transactionID
        int responseID = (0xff & b[0]) << 8 | (0xff & b[1]);
        // (QR) check is response. 1st bit of the third byte
       
        // *(AA) check is authoritative, 2nd bit of the third byte
        boolean isAuthoritative = (b[2] & 0x4) != 0;
        if (verboseTracing) {
            System.out.printf("Response ID: %5d Authoritative = %s\n", responseID, isAuthoritative ? "true" : "false");
        }
       
        // (TC) check if truncated, if it is, fail gracefully
        // (RD) looks like that's not needed?
        // (RA) check if server is capable of recursive queries
        // (RCODE) check if 0
        boolean hasError = (0xf & b[3]) != 0;
        if (hasError) return null;
        // TODO: if NOT FOUND, use a TTL of -1 and the IP 0.0.0.0

        // *(QCOUNT)
        int queryCount = (0xff & b[4]) << 8 | (0xff & b[5]);
        // *(ANCOUNT)
        int answerCount = (0xff & b[6]) << 8 | (0xff & b[7]);
        // *(NSCOUNT)
        int nameServerCount = (0xff & b[8]) << 8 | (0xff & b[9]);
        // *(ARCOUNT)
        int additionalRecordCount = (0xff & b[10]) << 8 | (0xff & b[11]);

        // go through query portion
        pos = 12;
        for (int i = 0; i < queryCount; i++) {
            DomainNameParser.parse(b, pos);
            String qName = DomainNameParser.getDomainName();
            pos += DomainNameParser.getDataLength();
        }

        // (QTYPE) pos +1 +2
        // (QCLASS) pos +3 +4
        
        pos += 4;

        // answer section
        if (verboseTracing) System.out.printf("%9s (%d)\n", "Answers", answerCount);
        for (int i = 0; i < answerCount; i++) {
            DomainNameParser.parse(b, pos);
            String hostName = DomainNameParser.getDomainName();
            pos += DomainNameParser.getDataLength();
            
            int typeCode = (0xff & b[pos++]) << 8 | (0xff & b[pos++]);
            RecordType type = RecordType.getByCode(typeCode);
            int nsClass = (0xff & b[pos++]) << 8 | (0xff & b[pos++]);
            int ttl = (0xff & b[pos++] << 24 | 0xff & b[pos++] << 16 | 0xff & b[pos++]) << 8 | (0xff & b[pos++]);
            int dataLength = (0xff & b[pos++]) << 8 | (0xff & b[pos++]);
            
            switch (type) {
                case A:
                case AAAA:
                    try {
                        byte[] ipBytes = Arrays.copyOfRange(b, pos, pos + dataLength);
                    
                        String ip = InetAddress.getByAddress(ipBytes).getHostAddress();
                        ResourceRecord record = new ResourceRecord(hostName, type, ttl, ip);
                        cache.addResult(record);
                        verbosePrintResourceRecord(record, type.getCode());
                    } catch (UnknownHostException E) {
                        // weird
                    }
                break;

                case CNAME:
                    DomainNameParser.parse(b, pos);
                    String alias = DomainNameParser.getDomainName();

                    ResourceRecord record = new ResourceRecord(hostName, type, ttl, alias);
                        cache.addResult(record);
                        verbosePrintResourceRecord(record, type.getCode());
                break;

                default:
                break;
            }
            
            pos = pos + dataLength;
        }

        // NS records
        if (verboseTracing) System.out.printf("%13s (%d)\n", "Nameservers", nameServerCount);
        for (int i = 0; i < nameServerCount; i++) {
            DomainNameParser.parse(b, pos);
            String hostName = DomainNameParser.getDomainName();
            pos += DomainNameParser.getDataLength();

            RecordType type = RecordType.getByCode((0xff & b[pos++]) << 8 | (0xff & b[pos++]));
            int nsClass = (0xff & b[pos++]) << 8 | (0xff & b[pos++]);
            int ttl = (0xff & b[pos++] << 24 | 0xff & b[pos++] << 16 | 0xff & b[pos++]) << 8 | (0xff & b[pos++]);
            int dataLength = (0xff & b[pos++]) << 8 | (0xff & b[pos++]);
            DomainNameParser.parse(b, pos);
            String result = DomainNameParser.getDomainName();
            pos = pos + dataLength;
            
            ResourceRecord record = new ResourceRecord(hostName, type, ttl, result);
            cache.addResult(record);
            verbosePrintResourceRecord(record, type.getCode());
        }

        // Additional Records
        if (verboseTracing) System.out.printf("%24s (%d)\n", "Additional Information", additionalRecordCount);
        for (int i = 0; i < additionalRecordCount; i++) {
            DomainNameParser.parse(b, pos);
            String hostName = DomainNameParser.getDomainName();
            pos += DomainNameParser.getDataLength();
            
            RecordType type = RecordType.getByCode((0xff & b[pos++]) << 8 | (0xff & b[pos++]));
            int nsClass = (0xff & b[pos++]) << 8 | (0xff & b[pos++]);
            int ttl = (0xff & b[pos++] << 24 | 0xff & b[pos++] << 16 | 0xff & b[pos++]) << 8 | (0xff & b[pos++]);
            int dataLength = (0xff & b[pos++]) << 8 | (0xff & b[pos++]);
            
            switch (type) {
                case A:
                case AAAA:
                    byte[] ipBytes = Arrays.copyOfRange(b, pos, pos + dataLength);
                    try {
                        
                        String ip = InetAddress.getByAddress(ipBytes).getHostAddress();
                        ResourceRecord record = new ResourceRecord(hostName, type, ttl, ip);
                        cache.addResult(record);
                        verbosePrintResourceRecord(record, type.getCode());
                    } catch (UnknownHostException E) {
                        // weird
                    }
                    break;
                    
                case CNAME:
                case NS:
                case SOA:
                case MX:
                    DomainNameParser.parse(b, pos);    
                    String domainName = DomainNameParser.getDomainName();
                    ResourceRecord record = new ResourceRecord(hostName, type, ttl, domainName);
                    cache.addResult(record);
                    verbosePrintResourceRecord(record, type.getCode());
                    break;

                default:
                    record = new ResourceRecord(hostName, type, ttl, "");
                    cache.addResult(record);
                    verbosePrintResourceRecord(record, type.getCode());
                    break;
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

