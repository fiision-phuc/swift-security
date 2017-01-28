//  Project name: FwiSecurity
//  File name   : FwiRSAPrivateKey.swift
//
//  Author      : Phuc, Tran Huu
//  Created date: 1/26/17
//  Version     : 1.00
//  --------------------------------------------------------------
//  Copyright © 2017 Fiision Studio. All rights reserved.
//  --------------------------------------------------------------

import Foundation
/// Optional
import FwiCore


public struct FwiRSAPrivateKey {

    // MARK: Class's constructors
    public init?(withIdentifier i: String? = String.randomIdentifier()) {
        guard let identifier = i, identifier.length() > 0 else {
            return nil
        }
        
        rsaKey = FwiRSAKey(withIdentifier: "\(identifier)|private")
        guard rsaKey.inKeystore else {
            return nil
        }
    }
    
    // MARK: Class's properties
    fileprivate var rsaKey: FwiRSAKey
    
    // MARK: Class's public methods
    /// Decrypt Data.
    ///
    /// - parameter data (required): data to be decrypted
    public func decrypt(data d: Data?) -> Data? {
        /* Condition validation */
        guard let data = d, rsaKey.inKeystore && data.count > 0 else {
            return nil
        }
        var (keyRef, blocksize) = rsaKey.keyRef
        
        /* Condition validation: Verify overhead raw data */
        guard let key = keyRef, data.count == blocksize else {
            return nil
        }
        
        // Encrypt data
        var buffer = [UInt8](repeating: 0, count: blocksize)
        defer { bzero(&buffer, buffer.count) }
        
        // Finalize result
        let status = SecKeyDecrypt(key, .PKCS1, data.bytes(), data.count, &buffer, &blocksize)
        if status == errSecSuccess {
            return Data(bytes: buffer, count: blocksize)
        }
        return nil
    }
    
    /// Generate signature for encrypted data.
    ///
    /// - parameter data (required): data to be encrypted
    /// - parameter digest (required): digest to create signature
    public func sign(encryptedData da: Data?, usingDigest di: FwiDigest = .sha1) -> Data? {
        return nil
        
//        /* Condition validation */
//        if (![self inKeystore]) return nil;
//        
//        /* Condition validation: verify signature length */
//        size_t blocksize = self.blocksize;
//        if (!data || data.length <= 0 || blocksize == 0) return nil;
//        
//        // Standardize signature
//        NSData *digestData = [[FwiDer sequence:
//            [FwiDer sequence:
//            [FwiDer objectIdentifierWithOIDString:FwiDigestOIDWithDigest(digest)],
//            [FwiDer null],
//            nil],
//            [FwiDer octetStringWithData:[data sha:digest]],
//            nil] encode];
//        
//        // Create digital signature
//        uint8_t *buffer = malloc(blocksize);
//        bzero(buffer, blocksize);
//        SecKeyRef key = self.key;
//        
//        FwiSecStatus status = SecKeyRawSign(key, kSecPaddingPKCS1, digestData.bytes, digestData.length, buffer, &blocksize);
//        FwiReleaseCF(key);
//        
//        __autoreleasing NSData *result = nil;
//        if (status == kSec_Success) result = [[NSData alloc] initWithBytes:buffer length:blocksize];
//        
//        free(buffer);
//        return FwiAutoRelease(result);
    }
    
    /// Remove current key from keystore.
    public func remove() {
        rsaKey.key.remove()
    }
    
    // MARK: Class's private methods
}
