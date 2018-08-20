package org.bouncycastle.crypto.test;

import java.nio.ByteBuffer;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.crypto.digests.GOST34311Digest;
import org.bouncycastle.crypto.generators.PKCS5S1ParametersGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class GOST34311DigestTest
    extends DigestTest
{
    private static final String[] messages =
    {
        "for test only)",
    };
    
//  If S-box = D-A (see: digest/GOST3411Digest.java; function: E(byte[] in, byte[] key); string: CipherParameters  param = new GOST28147Parameters(key,"D-A");)
    private static final String[] digests =
    {
        "6cf53a7bed501cf3348e30562962121a5c68b2cc3cdf9f64ccb9b5f81464537c",
    };


    GOST34311DigestTest()
    {
        super(new GOST34311Digest(), messages, digests);
    }

    protected Digest cloneDigest(Digest digest)
    {
        return new GOST34311Digest((GOST34311Digest)digest);
    }
    
    public static void main(
        String[]    args)
    {
    	GOST34311Digest has = new GOST34311Digest();
    	has.update(messages[0].getBytes(),0, messages[0].getBytes().length);
    	byte[] out = new byte[32];
    	has.doFinal(out, 0);
    	
    	//byte[] out2 = longToBytes(swap(bytesToLong(out)));
    	
    	
    	byte[] bytes = {-1, 0, 1, 2, 3 };
        StringBuilder sb = new StringBuilder();
        for (byte b : out) {
            sb.append(String.format("%02X ", b));
        }
        System.out.println(sb.toString());
    	
    	 
        //runTest(new GOST34311DigestTest());
    }
    
    public static byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(x);
        return buffer.array();
    }

    public static long bytesToLong(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.put(bytes);
        buffer.flip();//need flip 
        return buffer.getLong();
    }
    
    public static long swap (long value)
    {
      long b1 = (value >>  0) & 0xff;
      long b2 = (value >>  8) & 0xff;
      long b3 = (value >> 16) & 0xff;
      long b4 = (value >> 24) & 0xff;
      long b5 = (value >> 32) & 0xff;
      long b6 = (value >> 40) & 0xff;
      long b7 = (value >> 48) & 0xff;
      long b8 = (value >> 56) & 0xff;

      return b1 << 56 | b2 << 48 | b3 << 40 | b4 << 32 |
             b5 << 24 | b6 << 16 | b7 <<  8 | b8 <<  0;
    }
}
