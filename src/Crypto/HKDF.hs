-- |
-- Module: Crypto.HKDF
-- Maintainer: Jiri Marsicek <jiri.marsicek@gmail.com>
--
-- This module provides implementation of HKDF function defined in
-- RFC-5869 (<http://www.ietf.org/rfc/rfc5869.txt>),
-- It is using "HashAlgorithm" from "cryptohash" as underlying implementation
--
module Crypto.HKDF
    ( hkdfExtract
    , hkdfExpand
    , hkdf
    ) where

import Crypto.Hash (HashAlgorithm)
import Crypto.MAC (HMAC, hmacAlg)
import Data.Byteable (toBytes)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS (concat, empty, length, take)
import qualified Data.ByteString.Char8 as C8 (singleton)
import Data.Char (chr)

-- | Extract function. 
--
-- Synonym to 'hmacAlg'
hkdfExtract :: (HashAlgorithm a) => a -- ^ hash algorithm
            -> ByteString             -- ^ optional salt value (a non-secret random value)
            -> ByteString             -- ^ input keying material
            -> HMAC a                 -- ^ a pseudorandom key
hkdfExtract = hmacAlg

-- | Expand function.
--
-- "Nothing" is returned in case (length of output > 255 * hash length)
hkdfExpand :: (HashAlgorithm a) => a -- ^ hash algorithm
           -> ByteString             -- ^ pseudorandom key
           -> ByteString             -- ^ info
           -> Int                    -- ^ length of output keying material in octets
           -> Maybe ByteString       -- ^ output keying material
hkdfExpand alg prk info l
  | l <= 255 * chunkSize = Just $ BS.take l $ BS.concat $ take (l `div` chunkSize + 2) hkdfChunks
  | otherwise            = Nothing
  where hkdfChunks = map fst $ iterate (hkdfSingle alg prk info) (BS.empty, 1)
        chunkSize  = BS.length $ hkdfChunks !! 1

type HKDFIteration = (ByteString, Int)

hkdfSingle :: (HashAlgorithm a) => a -- ^ hash algorithm
           -> ByteString             -- ^ pseudorandom key
           -> ByteString             -- ^ info
           -> HKDFIteration          -- ^ output of previous iteration
           -> HKDFIteration          -- ^ output of current iteration
hkdfSingle alg prk info (prev, n) = (toBytes $ hmacAlg alg prk $ BS.concat [prev, info, C8.singleton $ chr n], n + 1)

-- | Function combining extract and expand functions.
hkdf :: (HashAlgorithm a) => a -- ^ hash algorithm
     -> ByteString             -- ^ optional salt value (a non-secret random value)
     -> ByteString             -- ^ input keying material
     -> ByteString             -- ^ info
     -> Int                    -- ^ length of output keying material in octets
     -> Maybe ByteString       -- ^ output keying material
hkdf alg salt ikm = hkdfExpand alg (toBytes $ hkdfExtract alg salt ikm)
