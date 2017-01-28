//  Project name: FwiSecurity
//  File name   : FwiRSAPublicKey.swift
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


public struct FwiRSAPublicKey {

    // MARK: Class's constructors
    public init?(withIdentifier i: String? = String.randomIdentifier()) {
        guard let identifier = i, identifier.length() > 0 else {
            return nil
        }
        
        rsaKey = FwiRSAKey(withIdentifier: "\(identifier)|public")
        guard rsaKey.inKeystore else {
            return nil
        }
    }
    
    // MARK: Class's properties
    fileprivate var rsaKey: FwiRSAKey
    
    // MARK: Class's public methods
    /// Encrypt Data.
    ///
    /// - parameter data (required): data to be encrypted
    public func encrypt(data d: Data?) -> Data? {
        /* Condition validation */
        guard let data = d, rsaKey.inKeystore && data.count > 0 else {
            return nil
        }
        var (keyRef, blocksize) = rsaKey.keyRef
        
        /* Condition validation: Verify overhead raw data */
        guard let key = keyRef, data.count <= (blocksize - 12) else {
            return nil
        }
        
        // Encrypt data
        var buffer = [UInt8](repeating: 0, count: blocksize)
        let status = SecKeyEncrypt(key, .PKCS1, data.bytes(), data.count, &buffer, &blocksize)
        
        // Finalize result
        if status == errSecSuccess {
            return Data(bytes: buffer, count: blocksize)
        }
        return nil
    }
    
    /// Verify data against its signature.
    ///
    /// - parameter data (required): data to be encrypted
    /// - parameter digest (required): digest that had been used by private key to create signature
    /// - parameter signature (required): signature that had been created by private key
    public func verify(data da: Data?, usingDigest di: FwiDigest = .sha1, withSignature s: Data?) -> Bool {
        /* Condition validation */
        guard let data = da, let signature = s, rsaKey.inKeystore && data.count > 0 && signature.count > 0 else {
            return false
        }
        var (keyRef, blocksize) = rsaKey.keyRef
        
        /* Condition validation: Verify overhead raw data */
        guard let key = keyRef, data.count <= (blocksize - 12) && signature.count <= (blocksize - 12) else {
            return false
        }
        return false
        
//        // Standardize signature
//        NSData *digestData = [[FwiDer sequence:
//            [FwiDer sequence:
//            [FwiDer objectIdentifierWithOIDString:FwiDigestOIDWithDigest(digest)],
//            [FwiDer null],
//            nil],
//            [FwiDer octetStringWithData:[data sha:digest]],
//            nil] encode];
//        
//        // Verify signature
//        let status = SecKeyRawVerify(key, .PKCS1, digestData.bytes, digestData.length, signature.bytes(), blocksize)
//        return (status == errSecSuccess)
    }
    
    /// Remove current key from keystore.
    public func remove() {
        rsaKey.key.remove()
    }
    
    // MARK: Class's private methods
}
