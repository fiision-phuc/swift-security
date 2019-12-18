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
    public init?(withIdentifier i: String? = String.randomIdentifier) {
        guard let identifier = i, identifier.count > 0 else {
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
        var (keyRef, blocksize) = rsaKey.keyRef
        
        /* Condition validation */
        guard let key = keyRef, let data = d, data.count > 0 && data.count <= (blocksize - 12) else {
            return nil
        }
        
        // Encrypt data
        var buffer = [UInt8](repeating: 0, count: blocksize)
        defer { bzero(&buffer, buffer.count) }
        
        // Finalize result
        let status = SecKeyEncrypt(key, .PKCS1, data.bytes(), data.count, &buffer, &blocksize)
        if status != errSecSuccess {
            return nil
        }
        return Data(bytes: buffer, count: blocksize)
    }
    
    /// Verify data against its signature.
    ///
    /// - parameter data (required): data to be encrypted
    /// - parameter digest (required): digest that had been used by private key to create signature
    /// - parameter signature (required): signature that had been created by private key
    public func verify(data da: Data?, usingDigest di: FwiDigest = .sha1, withSignature s: Data?) -> Bool {
        let (keyRef, blocksize) = rsaKey.keyRef
        
        /* Condition validation */
        guard let key = keyRef, let data = da, let signature = s, data.count > 0 && signature.count == blocksize else {
            return false
        }
        
        // Verify signature
        let status = SecKeyRawVerify(key, di.padding, data.bytes(), data.count, signature.bytes(), signature.count)
        return (status == errSecSuccess)
    }
    
    /// Remove current key from keystore.
    public func remove() {
        rsaKey.key.remove()
    }
}

// MARK: Struct's forward properties
public extension FwiRSAPublicKey {
    
    var isInKeystore: Bool {
        return rsaKey.inKeystore
    }
}
