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
        message[pos++] = 1;
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
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }
}

