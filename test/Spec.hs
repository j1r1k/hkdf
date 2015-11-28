import Data.Byteable (toBytes)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Data.Char (chr)
import Data.Maybe (fromMaybe)
import Crypto.Hash
import Crypto.HKDF
import Test.Hspec
import Text.Printf

hex :: BS.ByteString -> String
hex = concatMap (printf "%02x") . BS.unpack

convertOctets :: [Int] -> BS.ByteString
convertOctets = C8.pack . map chr

testCase :: (HashAlgorithm a) => a
         -> [Int] -- ^ ikm octets
         -> [Int] -- ^ salt octets
         -> [Int] -- ^ info octets
         -> Int   -- ^ L
         -> (BS.ByteString, BS.ByteString) -- ^ (PRK, OKM)
testCase alg ikm salt info l = (prk, okm)
  where prk  = toBytes $ hkdfExtract alg (convertOctets salt) (convertOctets ikm)
        okm  = fromMaybe BS.empty $ hkdfExpand alg prk (convertOctets info) l

testCase1 :: (BS.ByteString, BS.ByteString)
testCase1 = testCase SHA256
                     (replicate 22 0x0b) 
                     [0x00 .. 0x0c] 
                     [0xf0 .. 0xf9] 
                     42

testCase2 :: (BS.ByteString, BS.ByteString)
testCase2 = testCase SHA256
                     [0x00 .. 0x4f]
                     [0x60 .. 0xaf]
                     [0xb0 .. 0xff]
                     82

testCase3 :: (BS.ByteString, BS.ByteString)
testCase3 = testCase SHA256
                     (replicate 22 0x0b)
                     []
                     []
                     42

testCase4 :: (BS.ByteString, BS.ByteString)
testCase4 = testCase SHA1
                     (replicate 11 0x0b)
                     [0x00 .. 0x0c]
                     [0xf0 .. 0xf9]
                     42

testCase5 :: (BS.ByteString, BS.ByteString)
testCase5 = testCase SHA1
                     [0x00 .. 0x4f]
                     [0x60 .. 0xaf]
                     [0xb0 .. 0xff]
                     82

testCase6 :: (BS.ByteString, BS.ByteString)
testCase6 = testCase SHA1
                     (replicate 22 0x0b)
                     []
                     []
                     42

testCase7 :: (BS.ByteString, BS.ByteString)
testCase7 = testCase SHA1
                     (replicate 22 0x0c)
                     []
                     []
                     42

main :: IO ()
main = hspec $ do
  describe "hkdf-export" $ do
    it "should work for test case 1" $ hex (fst testCase1) `shouldBe` "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    it "should work for test case 2" $ hex (fst testCase2) `shouldBe` "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"
    it "should work for test case 3" $ hex (fst testCase3) `shouldBe` "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
    it "should work for test case 4" $ hex (fst testCase4) `shouldBe` "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243"
    it "should work for test case 5" $ hex (fst testCase5) `shouldBe` "8adae09a2a307059478d309b26c4115a224cfaf6"
    it "should work for test case 6" $ hex (fst testCase6) `shouldBe` "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01"
    it "should work for test case 7" $ hex (fst testCase7) `shouldBe` "2adccada18779e7c2077ad2eb19d3f3e731385dd"

  describe "hkdf-expand" $ do
    it "should work for test case 1" $ hex (snd testCase1) `shouldBe` "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    it "should work for test case 2" $ hex (snd testCase2) `shouldBe` "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
    it "should work for test case 3" $ hex (snd testCase3) `shouldBe` "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    it "should work for test case 4" $ hex (snd testCase4) `shouldBe` "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896"
    it "should work for test case 5" $ hex (snd testCase5) `shouldBe` "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4"
    it "should work for test case 6" $ hex (snd testCase6) `shouldBe` "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918"
    it "should work for test case 7" $ hex (snd testCase7) `shouldBe` "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48"
