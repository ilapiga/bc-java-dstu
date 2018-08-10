package org.bouncycastle.jcajce.provider.digest;

import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.ua.UAObjectIdentifiers;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.digests.GOST34311Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
import org.bouncycastle.jcajce.provider.symmetric.util.PBESecretKeyFactory;

public class GOST34311
{
    private GOST34311()
    {

    }

    static public class Digest
        extends BCMessageDigest
        implements Cloneable
    {
        public Digest()
        {
            super(new GOST34311Digest());
        }

        public Object clone()
            throws CloneNotSupportedException
        {
            Digest d = (Digest)super.clone();
            d.digest = new GOST34311Digest((GOST34311Digest)digest);

            return d;
        }
    }

    /**
     * GOST3411 HMac
     */
    public static class HashMac
        extends BaseMac
    {
        public HashMac()
        {
            super(new HMac(new GOST34311Digest()));
        }
    }


    public static class KeyGenerator
        extends BaseKeyGenerator
    {
        public KeyGenerator()
        {
            super("HMACGOST34311", 256, new CipherKeyGenerator());
        }
    }


    public static class Mappings
        extends DigestAlgorithmProvider
    {
        private static final String PREFIX = GOST34311.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {           
            
            // ua
            provider.addAlgorithm("MessageDigest.GOST34311", PREFIX + "$Digest");
            provider.addAlgorithm("Alg.Alias.MessageDigest.GOST-34311", "GOST34311");
            provider.addAlgorithm("Alg.Alias.MessageDigest." + UAObjectIdentifiers.gost34311, "GOST34311");

            addHMACAlgorithm(provider, "GOST34311", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
            addHMACAlias(provider, "GOST34311", UAObjectIdentifiers.gost34311);
            //--

      
            //ua
            provider.addAlgorithm("Alg.Alias.SecretKeyFactory." + UAObjectIdentifiers.gost34311, "PBEWITHHMACGOST34311");
        }
    }
}
